// UI wiring: inputs, checklist status, call list, call detail.
import { runAnalysis } from './pipeline.js';
import { esc, chip, maskDom } from './render/dom.js';
import { renderLadder } from './render/ladder.js';
import { renderBanner, renderNeed, renderTimeline, renderTranslation, renderInbound, renderOutbound, renderFindings, renderRaw, inDpSummary } from './render/detail.js';
import { PREP_COMMANDS, COLLECT_COMMANDS, CONFIG_COMMANDS, inspectDebug, inspectConfig, inspectOptional } from './ui/checklist.js';
import { defaultProfile, FORMATS } from './engine/itsp.js';
import { peerRole, sipCodeText } from './engine/diagnose.js';

const $ = (s, r = document) => r.querySelector(s);
const LS_KEY = 'cube-sip-troubleshooter.itsp.v1';
const state = { result: null, selected: null, showKeep: false, filter: '' };

// ------------------------------------------------------------------ static text
$('#cmd-prep').textContent = PREP_COMMANDS;
$('#cmd-collect').textContent = COLLECT_COMMANDS;
$('#cmd-config').textContent = CONFIG_COMMANDS;

// ------------------------------------------------------------------ ITSP profile form
const F = {
  name: $('#itsp-name'), ips: $('#itsp-ips'), cc: $('#itsp-cc'), ranges: $('#itsp-ranges'),
  inCalled: $('#itsp-in-called'), inCalling: $('#itsp-in-calling'), outCalled: $('#itsp-out-called'), outCalling: $('#itsp-out-calling'), callerRange: $('#itsp-callerrange'),
};
for (const sel of [F.inCalled, F.inCalling, F.outCalled, F.outCalling]) sel.innerHTML = Object.entries(FORMATS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('');

function readProfile() {
  return {
    name: F.name.value.trim() || 'ITSP',
    ips: F.ips.value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean),
    countryCode: F.cc.value.replace(/\D/g, ''),
    didRanges: F.ranges.value,
    inbound: { called: F.inCalled.value, calling: F.inCalling.value },
    outbound: { called: F.outCalled.value, calling: F.outCalling.value },
    callerInRange: F.callerRange.checked,
  };
}
function writeProfile(p) {
  const d = { ...defaultProfile(), ...p };
  F.name.value = d.name; F.ips.value = (d.ips || []).join(', '); F.cc.value = d.countryCode; F.ranges.value = d.didRanges;
  F.inCalled.value = d.inbound.called; F.inCalling.value = d.inbound.calling; F.outCalled.value = d.outbound.called; F.outCalling.value = d.outbound.calling;
  F.callerRange.checked = !!d.callerInRange;
  updateItspStatus();
}
function updateItspStatus() {
  const p = readProfile();
  const ok = p.didRanges.trim() && p.countryCode;
  $('#st-itsp').innerHTML = ok ? chip('ok', `${p.ips.length || 'no'} IPs, ranges set`) : chip('opt', 'optional: add DID ranges + country code');
}
try {
  writeProfile(JSON.parse(localStorage.getItem(LS_KEY) || 'null') || defaultProfile());
} catch { writeProfile(defaultProfile()); }
for (const el of Object.values(F)) el.addEventListener('input', () => { try { localStorage.setItem(LS_KEY, JSON.stringify(readProfile())); } catch {} updateItspStatus(); });
$('#itsp-export').addEventListener('click', () => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(readProfile(), null, 2)], { type: 'application/json' }));
  a.download = 'itsp-profile.json';
  a.click();
});
$('#itsp-import').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try { writeProfile(JSON.parse(await f.text())); localStorage.setItem(LS_KEY, JSON.stringify(readProfile())); } catch { alert('Not a valid profile JSON file'); }
  e.target.value = '';
});

// ------------------------------------------------------------------ input status chips
const T = { debug: $('#in-debug'), config: $('#in-config'), summary: $('#in-summary'), dialplan: $('#in-dialplan'), trace: $('#in-trace') };
const chipFor = (r) => chip(r.state === 'ok' ? 'ok' : r.state === 'warn' ? 'warn' : r.state === 'missing' ? 'missing' : 'opt', r.state === 'missing' ? 'missing: ' + r.msg : r.msg);
let timer;
function refreshStatus() {
  const d = inspectDebug(T.debug.value);
  $('#st-debug').innerHTML = chipFor(d);
  $('#hint-debug').innerHTML = d.notes.map(esc).join('<br>');
  const c = inspectConfig(T.config.value);
  $('#st-config').innerHTML = chipFor(c);
  $('#hint-config').innerHTML = c.notes.map(esc).join('<br>');
  $('#st-summary').innerHTML = chipFor(inspectOptional(T.summary.value, /^\s*\d+\s+(voip|pots)\s+(up|down)/im, 'summary'));
  $('#st-dialplan').innerHTML = chipFor(inspectOptional(T.dialplan.value, /Macro Exp|Peer\d+|No match/i, 'dialplan'));
  $('#st-trace').innerHTML = chipFor(inspectOptional(T.trace.value, /Cover Buffer/i, 'cover buffers'));
}
for (const el of Object.values(T)) el.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(refreshStatus, 400); });
refreshStatus();

// file loaders + copy buttons
document.addEventListener('change', async (e) => {
  const t = e.target;
  if (t.matches('input[type=file][data-target]')) {
    const f = t.files[0];
    if (!f) return;
    $(t.dataset.target).value = await f.text();
    refreshStatus();
    t.value = '';
  }
});
document.addEventListener('click', (e) => {
  const b = e.target.closest('button.copy');
  if (!b) return;
  const el = $(b.dataset.copy);
  navigator.clipboard.writeText(el.value ?? el.textContent).then(() => { const o = b.textContent; b.textContent = 'Copied'; setTimeout(() => (b.textContent = o), 1200); });
});

// ------------------------------------------------------------------ analyze
function show(view) {
  $('#sec-input').hidden = view !== 'input';
  $('#sec-results').hidden = view !== 'results';
  $('#sec-detail').hidden = view !== 'detail';
  window.scrollTo(0, 0);
}
const maskOn = () => $('#mask').checked;
function finish(el) { if (maskOn()) maskDom(el); }

function analyze() {
  const texts = Object.fromEntries(Object.entries(T).map(([k, el]) => [k, el.value]));
  if (!texts.debug.trim()) {
    $('#analyze-msg').textContent = 'Step 2 is required: paste the debug output first.';
    $('#step2').scrollIntoView({ behavior: 'smooth' });
    return;
  }
  $('#analyze-msg').textContent = 'Analyzing...';
  setTimeout(() => {
    try {
      state.result = runAnalysis(texts, readProfile());
    } catch (err) {
      console.error(err);
      $('#analyze-msg').textContent = 'Analysis failed: ' + err.message;
      return;
    }
    $('#analyze-msg').textContent = '';
    const focus = $('#in-focus').value.replace(/\D/g, '');
    state.filter = focus;
    const matches = focus ? state.result.calls.filter((c) => callDigits(c).includes(focus)) : [];
    if (matches.length === 1) openCall(matches[0].id);
    else renderResults();
  }, 20);
}
const callDigits = (c) => [c.called, c.calling, c.outCalled, c.outCalling].filter(Boolean).join(' ').replace(/[^\d ]/g, '');

// ------------------------------------------------------------------ results list
function renderResults() {
  const r = state.result;
  const el = $('#sec-results');
  const filt = state.filter;
  const calls = r.calls.filter((c) => !filt || callDigits(c).includes(filt));
  const globalNeed = [];
  if (!r.cfg) globalNeed.push(['running-config (step 3)', 'dial-peer matching and translation can only be simulated with it']);
  if (!r.stats.ccapi) globalNeed.push(['debug voip ccapi inout (step 2)', 'otherwise the incoming/outgoing dial-peer chosen by the router is unknown']);
  if (!r.itsp.didRanges.trim()) globalNeed.push(['ITSP profile with DID ranges (step 5)', 'to verify numbers are in your ranges and in +E.164']);
  if (!r.calls.length) globalNeed.unshift(['a capture that contains an INVITE (step 2)', r.stats.sip ? `found ${r.stats.sip} SIP messages but no call; reproduce the call while debugs are on` : 'no SIP debug lines were recognised']);

  let h = `<div class="bar"><h2>${r.calls.length} call${r.calls.length === 1 ? '' : 's'} found <span class="muted small">(${r.stats.sip} SIP messages, ${r.stats.ccapi} CCAPI events, ${r.stats.lines} log lines${r.cfg ? ', ' + r.cfg.dialPeers.length + ' dial-peers' : ''})</span></h2><div><button id="back-input">&larr; Edit inputs</button></div></div>`;
  if (globalNeed.length) h += `<div class="need"><h3>To improve the answer, please provide:</h3><ol>${globalNeed.map(([w, y]) => `<li><b>${esc(w)}</b> &mdash; ${esc(y)}</li>`).join('')}</ol></div>`;
  h += `<div class="bar"><label>Filter by number <input id="filter" type="text" value="${esc(filt)}" size="14"></label>${r.keepalives.length ? `<label class="switch"><input type="checkbox" id="showkeep" ${state.showKeep ? 'checked' : ''}> Show keepalives / non-call SIP (${r.keepalives.reduce((s, k) => s + k.total, 0)})</label>` : ''}</div>`;
  if (calls.length) {
    h += '<table class="t calls"><thead><tr><th>#</th><th>Time</th><th>Flow</th><th>Calling</th><th>Called (rx &rarr; tx)</th><th>Result</th><th>In dp</th><th>Out dp</th><th>Findings</th><th>Likely cause</th></tr></thead><tbody>';
    calls.forEach((c, i) => {
      const a = r.analyses.get(c.id);
      const errs = a.findings.filter((f) => f.sev === 'error').length;
      const warns = a.findings.filter((f) => f.sev === 'warn').length;
      const inRole = c.in ? peerRole(c.in.peerIp, r.cfg, r.itsp) : 'CUBE';
      const outRole = c.outs[0] ? peerRole(c.outs[0].peerIp, r.cfg, r.itsp) : c.in ? '(none)' : '?';
      h += `<tr data-call="${c.id}"><td>${i + 1}</td><td>${esc(c.startText.replace(/^\w+ +\d+ (\d{4} )?/, ''))}</td><td>${esc(inRole)} &rarr; CUBE &rarr; ${esc(outRole)}</td><td class="num">${esc(c.calling || '-')}</td><td class="num">${esc(c.called)}${c.outCalled && c.outCalled !== c.called ? ' &rarr; ' + esc(c.outCalled) : ''}</td>`
        + `<td>${chip(c.result, c.result + (c.finalCode && c.result !== 'answered' ? ' ' + c.finalCode : ''))}${c.finalCode >= 300 && sipCodeText(c.finalCode) ? `<div class="muted small">${esc(sipCodeText(c.finalCode))}</div>` : ''}</td>`
        + `<td>${esc(inDpSummary(a, r.cfg))}</td><td>${a.outTag ?? '-'}</td><td>${errs ? chip('err', errs + ' error' + (errs > 1 ? 's' : '')) : ''} ${warns ? chip('warn', warns + ' warn') : ''}${!errs && !warns ? chip('ok', 'ok') : ''}</td><td class="small">${a.root ? esc(a.root.title) : ''}</td></tr>`;
    });
    h += '</tbody></table><p class="muted small">Click a call to see the ladder diagram, dial-peer matching and findings for that call only.</p>';
  } else h += `<p class="muted">${filt ? 'No call matches this filter.' : 'No INVITE-based calls in this capture.'}</p>`;
  if (state.showKeep) {
    h += '<h3>Keepalives / non-call SIP (OPTIONS etc.)</h3><table class="t"><thead><tr><th>Method</th><th>Peer</th><th>Role</th><th>Seen</th><th>OK</th><th>Failed</th><th>First</th><th>Last</th></tr></thead><tbody>'
      + r.keepalives.map((k) => `<tr><td>${esc(k.method)} (${esc(k.direction)})</td><td class="num">${esc(k.peer)}</td><td>${esc(peerRole(k.peer, r.cfg, r.itsp))}</td><td>${k.total}</td><td class="ok">${k.ok}</td><td class="${k.failed.length ? 'bad' : ''}">${k.failed.length}${k.failed.length ? ' (' + esc(k.failed.slice(0, 3).map((f) => f.code).join(', ')) + ')' : ''}</td><td>${esc(k.firstTs)}</td><td>${esc(k.lastTs)}</td></tr>`).join('') + '</tbody></table>';
  }
  el.innerHTML = h;
  show('results');
  finish(el);
  $('#back-input', el).onclick = () => show('input');
  const f = $('#filter', el);
  f.onchange = () => { state.filter = f.value.replace(/\D/g, ''); renderResults(); };
  const k = $('#showkeep', el);
  if (k) k.onchange = () => { state.showKeep = k.checked; renderResults(); };
  el.querySelectorAll('tr[data-call]').forEach((tr) => (tr.onclick = () => openCall(tr.dataset.call)));
}

// ------------------------------------------------------------------ call detail
function openCall(id) {
  state.selected = id;
  const r = state.result;
  const call = r.calls.find((c) => c.id === id);
  const a = r.analyses.get(id);
  const el = $('#sec-detail');
  const inRole = call.in ? peerRole(call.in.peerIp, r.cfg, r.itsp) : '';
  const outRole = call.outs[0] ? peerRole(call.outs[0].peerIp, r.cfg, r.itsp) : '';
  let h = `<div class="bar"><h2>Call ${esc(call.startText)}: ${esc(call.calling || '?')} &rarr; ${esc(call.called)} ${chip(call.result, call.result + (call.finalCode && call.result !== 'answered' ? ' ' + call.finalCode + ' ' + (call.finalReason || '') : ''))}</h2><div><button id="back-list">&larr; All calls</button></div></div>`;
  h += `<div class="muted small">${call.in ? `in-leg: ${esc(inRole)} ${esc(call.in.peerIp)}` : ''}${call.outs.length ? ` &nbsp;|&nbsp; out-leg${call.outs.length > 1 ? 's' : ''}: ${call.outs.map((o) => esc(peerRole(o.peerIp, r.cfg, r.itsp) + ' ' + o.peerIp)).join(', ')}` : ''}${call.guid ? ` &nbsp;|&nbsp; GUID ${esc(call.guid)}` : ''}${call.inferred ? ' &nbsp;|&nbsp; <span class="bad">legs paired by timing (no GUID in log)</span>' : ''}${call.endedBy ? ` &nbsp;|&nbsp; ended by ${esc(call.endedBy)}` : ''}</div>`;
  h += renderBanner(call, a) + renderNeed(a);
  h += `<details class="panel" open><summary>Call flow (ladder)</summary><div class="ladder">${renderLadder(call, a, r.cfg, r.itsp)}</div></details>`;
  h += `<details class="panel" open><summary>Number timeline (what happens to the called / calling number)</summary>${renderTimeline(a, r.itsp)}${renderTranslation(a)}</details>`;
  h += `<details class="panel" open><summary>Inbound dial-peer matching</summary>${renderInbound(call, a)}</details>`;
  h += `<details class="panel" open><summary>Outbound dial-peer matching</summary>${renderOutbound(call, a)}</details>`;
  h += `<details class="panel" open><summary>All findings (${a.findings.length})</summary>${renderFindings(a)}</details>`;
  h += `<details class="panel"><summary>Raw messages</summary>${renderRaw(call)}</details>`;
  el.innerHTML = h;
  show('detail');
  finish(el);
  $('#back-list', el).onclick = () => { renderResults(); };
}

$('#mask').addEventListener('change', () => {
  if (!state.result) return;
  if (!$('#sec-detail').hidden && state.selected) openCall(state.selected);
  else if (!$('#sec-results').hidden) renderResults();
});

// ------------------------------------------------------------------ buttons
$('#btn-analyze').addEventListener('click', analyze);
$('#btn-clear').addEventListener('click', () => {
  Object.values(T).forEach((el) => (el.value = ''));
  $('#in-focus').value = '';
  state.result = null;
  refreshStatus();
  show('input');
});
$('#btn-sample').addEventListener('click', async () => {
  try {
    const get = async (p) => { const r = await fetch(p); if (!r.ok) throw new Error(p + ' ' + r.status); return r.text(); };
    const [a, b, cfg] = await Promise.all([get('samples/call-itsp-hairpin-fail.log'), get('samples/call-cucm-to-itsp-ok.log'), get('samples/running-config.txt')]);
    T.debug.value = a + '\n' + b;
    T.config.value = cfg;
    writeProfile({ ...defaultProfile(), name: 'Sample ITSP', ips: ['10.154.15.1'], countryCode: '966', didRanges: '+966138105200-299' });
    refreshStatus();
    $('#analyze-msg').textContent = 'Sample loaded (synthetic calls + your sanitized config). Press Analyze.';
  } catch (err) {
    $('#analyze-msg').textContent = 'Could not load sample (serve the folder over http, e.g. python -m http.server): ' + err.message;
  }
});

// #demo in the URL: load the sample and analyze immediately; #demo-call-N opens call N (demos / smoke tests)
const demo = /^#demo(?:-call-(\d+))?(-mask)?$/.exec(location.hash);
if (demo) {
  if (demo[2]) $('#mask').checked = true;
  $('#btn-sample').click();
  setTimeout(analyze, 600);
  if (demo[1]) setTimeout(() => state.result && openCall('call-' + demo[1]), 900);
}


