import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runAnalysis } from '../js/pipeline.js';
import { defaultProfile } from '../js/engine/itsp.js';
import { renderLadder } from '../js/render/ladder.js';
import { renderBanner, renderNeed, renderTimeline, renderTranslation, renderInbound, renderOutbound, renderFindings, renderRaw } from '../js/render/detail.js';
import { maskString } from '../js/render/dom.js';
import { inspectDebug, inspectConfig } from '../js/ui/checklist.js';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const texts = {
  debug: read('../samples/call-itsp-hairpin-fail.log') + '\n' + read('../samples/call-cucm-to-itsp-ok.log'),
  config: read('../samples/running-config.txt'),
};
const itsp = { ...defaultProfile(), ips: ['10.154.15.1'], didRanges: '+966138105200-299' };

test('pipeline finds both sample calls and every renderer produces HTML', () => {
  const r = runAnalysis(texts, itsp);
  assert.equal(r.calls.length, 2);
  assert.deepEqual(r.calls.map((c) => c.result), ['failed', 'answered']);
  for (const c of r.calls) {
    const a = r.analyses.get(c.id);
    const svg = renderLadder(c, a, r.cfg, itsp);
    assert.match(svg, /^<svg/);
    assert.match(svg, /INVITE/);
    for (const html of [renderBanner(c, a), renderNeed(a), renderTimeline(a, itsp), renderTranslation(a), renderInbound(c, a), renderOutbound(c, a), renderFindings(a), renderRaw(c)]) {
      assert.equal(typeof html, 'string');
      assert.ok(!html.includes('undefined'), html.slice(0, 200));
      assert.ok(!html.includes('[object'), html.slice(0, 200));
    }
  }
});

test('masking', () => {
  assert.equal(maskString('call +966138105234 from 10.154.15.1'), 'call +966xxxxxxxxx from 10.154.x.x');
});

test('input inspection tells the user what is missing', () => {
  assert.equal(inspectDebug('').state, 'missing');
  const only = inspectDebug('*Mar 18 09:09:28.099: //-1/xxxxxxxxxxxx/SIP/Msg/ccsipDisplayMsg:\nReceived:\nOPTIONS sip:1.1.1.1 SIP/2.0');
  assert.equal(only.state, 'warn');
  assert.ok(only.notes.some((n) => /no INVITE/.test(n)));
  assert.ok(only.notes.some((n) => /CCAPI/.test(n)));
  assert.equal(inspectConfig('hostname x').state, 'warn');
  assert.equal(inspectDebug(texts.debug).state, 'ok');
});

test('real recorder log (OPTIONS only): analysis completes, 0 calls, keepalives bucketed, asks for a call capture', () => {
  const r = runAnalysis({ debug: read('./fixtures/options-only-recorder.log'), config: read('../samples/running-config.txt') }, defaultProfile());
  assert.equal(r.calls.length, 0);
  assert.equal(r.stats.sip, 156);
  const total = r.keepalives.reduce((s, k) => s + k.total, 0);
  assert.equal(total, 156 / 2);
  const roles = r.keepalives.map((k) => k.peer);
  assert.ok(roles.includes('10.154.15.1'));
});


