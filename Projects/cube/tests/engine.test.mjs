import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cleanLog, splitBlocks } from '../js/parsers/clean.js';
import { parseSipMessages } from '../js/parsers/ccsip.js';
import { parseCcapi, parseSyslogEvents } from '../js/parsers/ccapi.js';
import { parseConfig } from '../js/parsers/config.js';
import { matchPattern } from '../js/engine/pattern.js';
import { applyRuleSet, applyProfile } from '../js/engine/translation.js';
import { matchInbound, matchOutbound } from '../js/engine/matcher.js';
import { buildCalls } from '../js/engine/correlate.js';
import { analyzeCall } from '../js/engine/diagnose.js';
import { defaultProfile, classifyNumber, parseRanges, inRanges } from '../js/engine/itsp.js';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const cfg = parseConfig(read('../samples/running-config.txt'));

function run(file, itsp) {
  const blocks = splitBlocks(cleanLog(read(file)));
  const res = buildCalls(parseSipMessages(blocks), parseCcapi(blocks), parseSyslogEvents(blocks));
  return { ...res, analyses: res.calls.map((c) => analyzeCall(c, { cfg, itsp })) };
}

test('pattern semantics (Cisco wildcards)', () => {
  assert.ok(matchPattern('12..$', '1234').ok);
  assert.ok(!matchPattern('12..$', '12345').ok);
  assert.ok(matchPattern('12..', '12345').ok, 'no $ => prefix match');
  assert.ok(matchPattern('.T', '+966138105234').ok);
  assert.ok(matchPattern('.', '5551212').ok);
  assert.ok(!matchPattern('9661381052..', '+966138105234').ok, 'leading digit cannot match "+"');
  assert.ok(matchPattern('\\+9661381052..', '+966138105234').ok, 'escaped plus');
  assert.ok(matchPattern('+9661381052..', '+966138105234').ok, 'leading + is literal');
  assert.ok(matchPattern('9661381052..', '966138105234').ok);
  assert.ok(matchPattern('[2-5]...$', '3456').ok);
  assert.ok(matchPattern('9,,,,,55591[1-3,5-9]8675309', '95559128675309').ok);
});

test('translation rules from the real config', () => {
  // profile PSTN-IN: called -> rule 4, calling -> rule 5
  const c1 = applyProfile(cfg, 'PSTN-IN', 'called', '+966138105234');
  assert.equal(c1.out, '1234');
  assert.equal(c1.ruleSeq, 1);
  // no leading char before 966 => rule 4/1 requires ".+" so unchanged
  assert.equal(applyProfile(cfg, 'PSTN-IN', 'called', '966138105234').out, '966138105234');
  // PSTN-OUT calling -> rule 5: 1201 => +966138105201
  assert.equal(applyProfile(cfg, 'PSTN-OUT', 'calling', '1201').out, '+966138105201');
  assert.equal(applyProfile(cfg, 'PSTN-OUT', 'calling', '+966501234567').out, '50501234567');
  // sed semantics: only matched part replaced
  assert.equal(applyRuleSet(cfg, '1', '5200').out, '8105200');
});

test('inbound matching: "+" number does not match dp 300 (only matches dp 500 via calling-number destination-pattern)', () => {
  const plus = matchInbound(cfg, { called: '+966138105234', calling: '+966501234567', uris: {} });
  assert.equal(plus.winner.tag, 500);
  assert.match(plus.winner.step, /destination-pattern/);
  const plain = matchInbound(cfg, { called: '966138105234', calling: '966501234567', uris: {} });
  assert.equal(plain.winner.tag, 300);
  const cucm = matchInbound(cfg, { called: '0555123456', calling: '1201', uris: {} });
  assert.equal(cucm.winner.tag, 102, 'ANI vs destination-pattern, longest literal wins');
});

test('outbound matching: shutdown dp 100 excluded, 102 before 103 by preference', () => {
  const o = matchOutbound(cfg, { called: '0555123456', calling: '1201' });
  assert.equal(o.winner.tag, 500);
  const blocked100 = o.tiers.flatMap((t) => t.blockedMatches).find((c) => c.tag === 100);
  assert.match(blocked100.blocked, /shutdown/);
  const ext = matchOutbound(cfg, { called: '1234', calling: '1' });
  assert.deepEqual(ext.hunt.map((h) => h.tag), [102, 103, 500]);
});

test('ITSP helpers', () => {
  assert.equal(classifyNumber('+966138105234', '966'), 'e164plus');
  assert.equal(classifyNumber('966138105234', '966'), 'e164');
  assert.equal(classifyNumber('0138105234', '966'), 'national');
  assert.equal(classifyNumber('1234', '966'), 'short');
  const r = parseRanges('+966138105200-299\n+9661381060xx\n966138107000', '966');
  assert.equal(r.length, 3);
  assert.equal(inRanges('+966138105234', r, '966'), true);
  assert.equal(inRanges('0138105234', r, '966'), true);
  assert.equal(inRanges('0138105134', r, '966'), false);
  assert.equal(inRanges('0138106012', r, '966'), true);
  assert.equal(inRanges('1234', r, '966'), null);
});

test('sample 1: DID outside translation range -> inbound dp 500 by ANI -> hairpin -> 403', () => {
  const itsp = { ...defaultProfile(), ips: ['10.154.15.1'], didRanges: '+966138105200-299' };
  const { calls, analyses } = run('../samples/call-itsp-hairpin-fail.log', itsp);
  assert.equal(calls.length, 1);
  const c = calls[0];
  const a = analyses[0];
  assert.equal(c.result, 'failed');
  assert.equal(c.finalCode, 403);
  assert.equal(c.called, '+966138106234');
  assert.equal(c.outs.length, 1);
  assert.equal(a.inTag, 500);
  assert.equal(a.outTag, 500);
  const ids = a.findings.map((f) => f.id);
  assert.ok(ids.includes('inbound-by-ani'), ids.join());
  assert.ok(ids.includes('hairpin'));
  assert.ok(ids.includes('did-range-in'));
  assert.ok(ids.some((i) => i.startsWith('sip-out-leg-403')));
  assert.equal(a.root.id, 'hairpin');
});

test('sample 2: CUCM -> ITSP answered, called number not +E.164 flagged', () => {
  const itsp = { ...defaultProfile(), ips: ['10.154.15.1'], didRanges: '+966138105200-299' };
  const { calls, analyses } = run('../samples/call-cucm-to-itsp-ok.log', itsp);
  assert.equal(calls.length, 1);
  const c = calls[0];
  const a = analyses[0];
  assert.equal(c.result, 'answered');
  assert.equal(a.inTag, 102);
  assert.equal(a.outTag, 500);
  assert.equal(a.outbound.translation.predictedCalling, '+966138105201');
  const ids = a.findings.map((f) => f.id);
  assert.ok(ids.includes('itsp-format'));
  assert.ok(!ids.includes('did-range-out'), 'caller +966138105201 is inside the DID range');
  assert.ok(!ids.includes('predict-calling'));
});

test('without config/ccapi the tool asks for what is missing', () => {
  const blocks = splitBlocks(cleanLog(read('../samples/call-itsp-hairpin-fail.log')).filter((l) => !/CCAPI|^\s{3}/.test(l)));
  const { calls } = buildCalls(parseSipMessages(blocks), [], []);
  const a = analyzeCall(calls[0], { cfg: null, itsp: null });
  assert.ok(a.need.some((n) => n.what === 'running-config'));
  assert.ok(a.need.some((n) => /ccapi/.test(n.what)));
});


test('"+" called number with no catch-all dial-peer: dial-peer 0 and the fix is reported', () => {
  const cfg2 = parseConfig(`dial-peer voice 300 voip
 session protocol sipv2
 session target sip-server
 incoming called-number 9661381052..
 voice-class codec 1
!
dial-peer voice 102 voip
 destination-pattern 12..$
 session protocol sipv2
 session target ipv4:10.10.20.201
!`);
  const blocks = splitBlocks(cleanLog(read('../samples/call-itsp-hairpin-fail.log')).map((l) => l.replace('+966138106234', '+966138105234')).map((l) => l.replace('Incoming Dial-peer=500', 'Incoming Dial-peer=0')));
  const { calls } = buildCalls(parseSipMessages(blocks), parseCcapi(blocks), []);
  const a = analyzeCall(calls[0], { cfg: cfg2, itsp: null });
  assert.equal(a.inTag, 0);
  const f = a.findings.find((x) => x.id === 'inbound-plus');
  assert.equal(f.sev, 'error');
  assert.ok(f.fix.join('\n').includes('incoming called-number +9661381052..'));
  assert.ok(a.findings.some((x) => x.id === 'out-nomatch') === false, 'out-leg exists in the log, so no routing failure is reported');
});
