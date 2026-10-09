import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cleanLog, splitBlocks } from '../js/parsers/clean.js';
import { parseSipMessages, parseUri } from '../js/parsers/ccsip.js';
import { parseCcapi, parseSyslogEvents } from '../js/parsers/ccapi.js';
import { parseConfig } from '../js/parsers/config.js';
import { parseDialPeerSummary, parseDialplanNumber, parseVoipTrace } from '../js/parsers/summary.js';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');

test('clean: recorder prefix, BOM and injected whitespace-only lines', () => {
  const lines = cleanLog(read('./fixtures/options-only-recorder.log'));
  assert.ok(lines.length > 2500);
  assert.ok(!lines.some((l) => l.includes('§')));
  assert.ok(!lines.some((l) => l.length && !l.trim()));
});

test('recorder log: 156 SIP messages, all OPTIONS keepalives, zero INVITE', () => {
  const msgs = parseSipMessages(splitBlocks(cleanLog(read('./fixtures/options-only-recorder.log'))));
  assert.equal(msgs.length, 156);
  assert.ok(msgs.every((m) => m.cseq.method === 'OPTIONS'));
  assert.ok(!msgs.some((m) => m.method === 'INVITE'));
  const sent = msgs.find((m) => m.dir === 'sent');
  assert.equal(sent.code, 200);
  assert.ok(sent.ccId > 0);
});

test('uri parsing', () => {
  assert.deepEqual(
    (({ user, host, port }) => ({ user, host, port }))(parseUri('"Ext" <sip:+966138106234;phone-context=x@10.1.1.1:5060;user=phone>;tag=1')),
    { user: '+966138106234', host: '10.1.1.1', port: '5060' },
  );
  assert.equal(parseUri('tel:+9661').user, '+9661');
});

test('sample fail log: SIP + CCAPI parsing', () => {
  const blocks = splitBlocks(cleanLog(read('../samples/call-itsp-hairpin-fail.log')));
  const sip = parseSipMessages(blocks);
  assert.equal(sip.length, 7);
  const inv = sip[0];
  assert.equal(inv.method, 'INVITE');
  assert.equal(inv.reqUri.user, '+966138106234');
  assert.equal(inv.via.host, '10.154.15.1');
  assert.deepEqual(inv.sdp.codecs.map((c) => c.name), ['PCMA', 'PCMU', 'G729']);
  assert.equal(inv.sdp.dtmf, 'rtp-nte');
  const cc = parseCcapi(blocks);
  const setup = cc.find((e) => e.func === 'cc_api_call_setup_ind');
  assert.equal(setup.inDp, 500);
  assert.equal(setup.called, '+966138106234');
  assert.equal(setup.calling, '+966501234567');
  assert.equal(cc.find((e) => e.func === 'ccCallSetupRequest').outDp, 500);
  assert.equal(cc.find((e) => e.func === 'cc_api_call_disconnected').cause, 21);
});

test('config: dial-peers, rules, profiles, trusted list', () => {
  const cfg = parseConfig(read('../samples/running-config.txt'));
  assert.equal(cfg.hostname, 'DMM-CST-VG-R01');
  assert.deepEqual(cfg.dialPeers.map((d) => d.tag), [100, 102, 200, 300, 103, 500]);
  const d300 = cfg.dialPeers.find((d) => d.tag === 300);
  assert.deepEqual(d300.incomingCalled, ['9661381052..']);
  assert.equal(d300.transIn, 'PSTN-IN');
  assert.equal(cfg.dialPeers.find((d) => d.tag === 100).shutdown, true);
  assert.equal(cfg.dialPeers.find((d) => d.tag === 103).preference, 4);
  assert.equal(cfg.rules['5'].length, 8);
  assert.equal(cfg.rules['1'][0].match, '\\(^52..\\)');
  assert.equal(cfg.profiles['PSTN-IN'].called, '4');
  assert.deepEqual(cfg.voiceService.trustedIps, ['10.10.20.201', '10.10.20.202', '10.154.15.1', '10.10.20.209']);
  assert.ok(cfg.voiceService.allow.includes('sip to sip'));
  assert.deepEqual(cfg.codecClasses['1'], ['g711alaw', 'g711ulaw']);
  assert.deepEqual(cfg.sipUa.servers, ['ipv4:10.154.15.1']);
  assert.ok(!/\$9\$/.test(cfg.clean));
});

test('syslog: IEC and MAXCONNCAC', () => {
  const lines = cleanLog([
    '000984: *Mar  9 20:53:01.225: %VOICE_IEC-3-GW: SIP: Internal Error (DNS query fail): IEC=10.1.128.7.47.0 on callID 6 GUID=37B668DF044111E7A950D832C82B325C',
    '000310: Oct  5 19:01:02.604: %SIP-3-MAXCONNCAC: Call rejected due to CAC based on maximum number of connections on dial-peer 1, sent response 503',
  ].join('\n'));
  const ev = parseSyslogEvents(splitBlocks(lines));
  assert.equal(ev[0].type, 'iec');
  assert.equal(ev[0].callId, 6);
  assert.equal(ev[1].type, 'maxconn');
  assert.equal(ev[1].dp, 1);
});

test('show dial-peer voice summary', () => {
  const rows = parseDialPeerSummary(`TAG    TYPE  MIN  OPER PREFIX    DEST-PATTERN      FER THRU SESS-TARGET    STAT PORT    KEEPALIVE
1      voip  up   up                                0  syst
777    voip  up   up             9...               0  syst ipv4:10.50.244.2
555    voip  up   down           555                0  syst
123    voip  up   up             123                0  syst ipv4:10.10.10.10            busyout`);
  assert.equal(rows.length, 4);
  assert.equal(rows[1].destPattern, '9...');
  assert.equal(rows[1].target, 'ipv4:10.50.244.2');
  assert.equal(rows[2].oper, 'down');
  assert.equal(rows[3].busyout, true);
});

test('show dialplan number + voip trace cover buffers', () => {
  const dp = parseDialplanNumber(`Macro Exp.: 1234

VoiceOverIpPeer102
        peer type = voice, system default peer = FALSE, description = '',
        tag = 102, destination-pattern = '12..$',
        preference = 0,
        session target = ipv4:10.10.20.201,
        Matched: 1234   Digits: 4
        Target: ipv4:10.10.20.201`);
  assert.equal(dp.matches[0].tag, 102);
  assert.equal(dp.matches[0].pattern, '12..$');
  const vt = parseVoipTrace(`------------------ Cover Buffer ---------------
Search-key = 8845:3002:659
CallID = 659
Peer-CallID = 661
Called-Number = 3002
Calling-Number = 8845
SIP CallID = 20857880-1ec12085-13b930-411b300a@10.48.27.65
GUID = 208578800000
-----------------------------------------------`);
  assert.equal(vt[0].peerCallId, 661);
  assert.equal(vt[0].guid, '208578800000');
});


