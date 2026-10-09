// HTML renderers for the single-call detail view.
import { esc, chip, pre } from './dom.js';
import { classifyNumber, FORMATS } from '../engine/itsp.js';
import { dialPeerByTag } from '../parsers/config.js';

const NOMASK = (s) => `<span class="nomask">${esc(s)}</span>`;
const mark = (ok) => (ok ? '<span class="ok">&#10003;</span>' : '<span class="bad">&#10007;</span>');

export function renderBanner(call, a) {
  const r = a.root;
  const cls = !r ? 'ok' : r.sev === 'error' ? 'err' : r.sev === 'warn' ? 'warn' : 'ok';
  let html = `<div class="banner ${cls}">`;
  if (r) {
    html += `<div class="banner-title">${esc(r.title)}</div><div>${esc(r.detail)}</div>`;
    if (r.fix && r.fix.length) html += `<div class="banner-fix"><b>Suggested fix</b>${pre(r.fix, 'nomask')}</div>`;
  } else {
    html += `<div class="banner-title">No problem detected</div><div>Result: ${esc(call.result)}. Provide more inputs (see below) for a deeper check.</div>`;
  }
  return html + '</div>';
}

export function renderNeed(a) {
  if (!a.need.length) return '';
  return `<div class="need"><h3>Could not fully determine &mdash; I need:</h3><ol>${a.need.map((n) => `<li><b>${esc(n.what)}</b> &mdash; ${esc(n.why)}</li>`).join('')}</ol></div>`;
}

export function renderTimeline(a, itsp) {
  if (!a.timeline.length) return '<p class="muted">No number information available.</p>';
  const cc = (itsp && itsp.countryCode) || '';
  let prev = null;
  const fmt = (n) => {
    const c = classifyNumber(n, cc);
    const good = c === 'e164plus';
    return `<span class="fmt ${good ? 'good' : 'plain'}" title="${esc(FORMATS[c] || c)}">${esc(c)}</span>`;
  };
  const rows = a.timeline
    .map((r) => {
      const cc1 = prev && prev.called !== r.called ? 'chg' : '';
      const cg1 = prev && prev.calling !== r.calling ? 'chg' : '';
      prev = r;
      return `<tr class="${r.kind}"><td>${esc(r.stage)}</td><td class="num ${cc1}">${esc(r.called ?? '-')} ${fmt(r.called)}</td><td class="num ${cg1}">${esc(r.calling || '-')} ${r.calling ? fmt(r.calling) : ''}</td><td>${esc(r.note || '')}</td></tr>`;
    })
    .join('');
  return `<table class="t"><thead><tr><th>Stage</th><th>Called number</th><th>Calling number</th><th>Note</th></tr></thead><tbody>${rows}</tbody></table>
  <p class="muted small">Rows tinted blue are read from the log; other rows are simulated from your config. Changed values are highlighted.</p>`;
}

function translationDetail(label, t) {
  if (!t) return '';
  const part = (k, x) => {
    if (!x) return '';
    if (x.missingProfile) return `<tr><td>${label} ${k}</td><td colspan="2" class="bad">profile ${esc(x.name)} not found in config</td></tr>`;
    if (!x.applied) return `<tr><td>${label} ${k}</td><td colspan="2" class="muted">profile ${esc(x.name)} has no ${k} rule</td></tr>`;
    return `<tr><td>${label} ${k}<br><span class="muted small">profile ${esc(x.name)} / rule-set ${esc(x.ruleId)}</span></td><td class="nomask">${x.steps.map((s) => `<div class="${s.matched ? 'ok' : 'muted'}">${s.matched ? '&#10003;' : '&#10007;'} ${esc(s.raw)}</div>`).join('') || '<span class="muted">no rules</span>'}</td><td>${x.matched ? `<b>${esc(x.out)}</b>${x.rejected ? ' <span class="bad">(REJECT)</span>' : ''}` : '<span class="muted">unchanged</span>'}</td></tr>`;
  };
  return part('called', t.called) + part('calling', t.calling);
}

export function renderTranslation(a) {
  const rows = translationDetail('incoming', a.inbound && a.inbound.translation) + translationDetail('outgoing', a.outbound && a.outbound.translation);
  if (!rows) return '<p class="muted">No translation profile is applied on this call (or no config pasted).</p>';
  return `<table class="t"><thead><tr><th>Translation</th><th>Rules tried (top-down, first match wins)</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>`;
}

export function renderInbound(call, a) {
  if (!a.inbound) return '<p class="muted">No inbound leg in this capture.</p>';
  const { sim, debugTag } = a.inbound;
  let html = `<p>Matching input &mdash; called: <b>${esc(call.called)}</b>, calling: <b>${esc(call.calling)}</b> <span class="muted small">(Request-URI / ${esc(call.callingSource)} user)</span></p>`;
  html += `<p>Router debug says: ${debugTag != null ? chip(debugTag === 0 ? 'warn' : 'ok', 'dial-peer ' + debugTag) : chip('muted', 'not in log (add debug voip ccapi inout)')} &nbsp; Config simulation: ${sim ? chip(sim.winner ? 'info' : 'warn', sim.winner ? 'dial-peer ' + sim.winner.tag : 'dial-peer 0 (no match)') : chip('muted', 'no config')}</p>`;
  if (!sim) return html + '<p class="muted">Paste <code>show running-config</code> to see why.</p>';
  html += '<p class="muted small">Cisco order for SIP: each step is evaluated fully; the first step with a match wins.</p><table class="t"><thead><tr><th>Step</th><th>Dial-peer</th><th>Criterion</th><th>Compared with</th><th></th><th>Why</th></tr></thead><tbody>';
  sim.steps.forEach((s, i) => {
    const won = sim.winner && sim.winner.step === s.name;
    if (!s.tried.length) {
      html += `<tr class="dim"><td>${i + 1}. ${esc(s.name)}</td><td colspan="5" class="muted">no dial-peer configured with this criterion</td></tr>`;
      return;
    }
    s.tried.forEach((t, j) => {
      const sel = s.winner && s.winner.tag === t.tag && s.winner.field === t.field && won;
      html += `<tr class="${sel ? 'sel' : ''}">${j === 0 ? `<td rowspan="${s.tried.length}">${i + 1}. ${esc(s.name)}${won ? '<br>' + chip('ok', 'MATCH') : ''}</td>` : ''}<td>${t.tag}</td><td>${NOMASK(t.field)}</td><td class="num">${esc(t.input)}</td><td>${mark(t.ok)}</td><td class="small">${esc(t.reason || (t.ok ? (sel ? 'selected' : 'also matches (lower priority within step)') : ''))}</td></tr>`;
    });
  });
  html += '</tbody></table>';
  html += sim.winner ? `<p class="result">&#8594; Simulated inbound dial-peer <b>${sim.winner.tag}</b> via <i>${esc(sim.winner.step)}</i></p>` : `<p class="result bad">&#8594; No dial-peer matched: default <b>dial-peer 0</b> is used (no dtmf-relay, all codecs, no translation profile).</p>`;
  return html;
}

export function renderOutbound(call, a) {
  if (!a.outbound) return '<p class="muted">No outbound simulation (needs <code>show running-config</code> and an INVITE).</p>';
  const { sim, debugTags, ctx } = a.outbound;
  let html = `<p>Matching input &mdash; called: <b>${esc(ctx.called)}</b> <span class="muted small">(after incoming translation)</span></p>`;
  html += `<p>Router debug says: ${debugTags.length ? debugTags.map((t) => chip('ok', 'dial-peer ' + t)).join(' ') : chip('muted', a.outInferred ? `not in log; inferred dial-peer ${a.outTag} from the INVITE target` : 'not in log')} &nbsp; Config simulation: ${chip(sim.winner ? 'info' : 'bad', sim.winner ? 'dial-peer ' + sim.winner.tag : 'no usable dial-peer')}</p>`;
  const scheme = sim.scheme ? ` (dial-peer hunt ${sim.scheme})` : ' (dial-peer hunt 0: longest match, then preference)';
  html += `<p class="muted small">Cisco order for SIP: destination dpg &gt; destination uri &gt; destination-pattern / e164-pattern-map. Within a tier: ${scheme}.</p>`;
  sim.tiers.forEach((t) => {
    if (!t.cands.length) return;
    html += `<h4>${esc(t.name)}${sim.usedTier === t.name ? ' ' + chip('ok', 'USED') : ''}</h4><table class="t"><thead><tr><th>Dial-peer</th><th>Criterion</th><th></th><th>Literal digits</th><th>Pref</th><th>State</th><th>Why</th></tr></thead><tbody>`;
    t.cands.forEach((c) => {
      const rank = sim.hunt.findIndex((x) => x.tag === c.tag && x.via === c.via);
      html += `<tr class="${rank === 0 ? 'sel' : ''}"><td>${c.tag}${c.dp && c.dp.description ? `<br><span class="muted small">${esc(c.dp.description)}</span>` : ''}</td><td>${NOMASK(c.via)}</td><td>${c.ok === false ? mark(false) : mark(true)}</td><td>${c.literal ?? ''}</td><td>${c.pref}</td><td>${c.blocked ? `<span class="bad">${esc(c.blocked)}</span>` : c.ok === false ? '<span class="muted">-</span>' : '<span class="ok">usable</span>'}</td><td class="small">${esc(c.reason || (rank >= 0 ? `hunt order #${rank + 1}` : ''))}</td></tr>`;
    });
    html += '</tbody></table>';
  });
  if (sim.hunt.length) html += `<p class="result">&#8594; Hunt order: ${sim.hunt.map((h) => `<b>dp ${h.tag}</b>`).join(' &rarr; ')}${sim.hunt.length > 1 ? ' <span class="muted small">(next one is tried only if the previous fails)</span>' : ''}</p>`;
  else html += '<p class="result bad">&#8594; No usable outbound dial-peer: the call fails (cause 1 / 3, SIP 404 or 503).</p>';
  if (sim.excluded.length) html += `<details><summary>${sim.excluded.length} dial-peers not considered</summary><ul class="small">${sim.excluded.map((e) => `<li>dial-peer ${e.tag}: ${esc(e.reason)}</li>`).join('')}</ul></details>`;
  return html;
}

export function renderFindings(a) {
  if (!a.findings.length) return '<p class="muted">No findings.</p>';
  return a.findings
    .map((f) => `<div class="finding ${f.sev}"><div class="f-title">${chip(f.sev, f.sev.toUpperCase())} ${esc(f.title)}</div><div>${esc(f.detail)}</div>${f.evidence.length ? `<details><summary>Evidence from log</summary>${pre(f.evidence)}</details>` : ''}${f.fix.length ? `<details open><summary>Suggested fix</summary>${pre(f.fix, 'nomask')}</details>` : ''}</div>`)
    .join('');
}

export function renderRaw(call) {
  const sip = call.msgs
    .map((m) => `<details><summary>${esc(m.tsText)} &nbsp; ${m.dir === 'recv' ? '&larr; Received' : '&rarr; Sent'} &nbsp; <b>${esc(m.startLine)}</b></summary>${pre(m.rawLines)}</details>`)
    .join('');
  const cc = call.ccapi.map((e) => `<details><summary>${esc(e.tsText)} &nbsp; <b>${esc(e.func)}</b>${e.inDp != null ? ` (in dp ${e.inDp})` : ''}${e.outDp != null ? ` (out dp ${e.outDp})` : ''}${e.cause != null ? ` (cause ${e.cause})` : ''}</summary>${pre(e.raw)}</details>`).join('');
  return `<h4>SIP messages (${call.msgs.length})</h4>${sip}<h4>CCAPI events (${call.ccapi.length})</h4>${cc || '<p class="muted">none attached to this call</p>'}`;
}

export function inDpSummary(a, cfg) {
  if (a.inTag == null) return '-';
  const dp = cfg ? dialPeerByTag(cfg, a.inTag) : null;
  return a.inTag === 0 ? '0 (default)' : String(a.inTag) + (dp && dp.shutdown ? ' (shut)' : '');
}

