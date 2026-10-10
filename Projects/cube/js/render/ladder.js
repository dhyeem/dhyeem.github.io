// SVG ladder (sequence) diagram of one call: peer A <-> CUBE <-> peer B, with dial-peer annotations.
import { esc } from './dom.js';
import { peerRole } from '../engine/diagnose.js';

const COLORS = { req: '#1565c0', prov: '#78909c', ok: '#2e7d32', fail: '#c62828' };

function colorKey(m) {
  if (m.kind === 'req') return 'req';
  if (m.code >= 300) return 'fail';
  if (m.code >= 200) return 'ok';
  return 'prov';
}

const label = (m) => (m.kind === 'req' ? m.method : `${m.code} ${m.reason}`.trim());

export function renderLadder(call, a, cfg, itsp) {
  const W = 940;
  const X = [150, 470, 790];
  const inSet = new Set(call.in ? call.in.msgs : []);
  const msgs = call.msgs.filter((m) => !(m.kind === 'req' && m.method === 'OPTIONS'));
  const leftIp = call.in ? call.in.peerIp : '';
  const rightIp = call.outs[0] ? call.outs[0].peerIp : '';
  const lane = (ip) => `${peerRole(ip, cfg, itsp)}${ip ? '\n' + ip : ''}`;
  const rows = [];
  let inInviteSeen = false;
  let outInviteSeen = false;
  for (const m of msgs) {
    const isIn = inSet.has(m);
    if (isIn && !inInviteSeen && m.kind === 'req' && m.method === 'INVITE') {
      inInviteSeen = true;
      rows.push({ type: 'msg', m, isIn });
      const tag = a.inTag;
      const t = a.inbound && a.inbound.translation;
      rows.push({ type: 'note', text: `in dial-peer ${tag === 0 ? '0 (default)' : tag ?? '?'}${a.inbound && a.inbound.debugTag == null && a.simInTag != null ? ' (simulated)' : ''}  |  called ${call.called} -> ${a.timeline.find((x) => /incoming translation/.test(x.stage))?.called ?? call.called}`, kind: tag === 0 ? 'warn' : 'info' });
      continue;
    }
    if (!isIn && !outInviteSeen && m.kind === 'req' && m.method === 'INVITE' && m.dir === 'sent') {
      outInviteSeen = true;
      rows.push({ type: 'note', text: `out dial-peer ${a.outTag ?? '?'}${a.outInferred ? ' (inferred from target)' : ''}  |  called ${call.outCalled}  calling ${call.outCalling || '-'}`, kind: 'info' });
    }
    rows.push({ type: 'msg', m, isIn });
  }
  if (call.in && !call.outs.length && call.result === 'failed') rows.push({ type: 'note', text: `No outbound leg was created${a.root ? ': ' + a.root.title : ''}`, kind: 'err' });

  const RH = 30;
  const top = 90;
  const H = top + rows.length * RH + 40;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="SIP ladder diagram" font-family="Segoe UI, Arial, sans-serif" font-size="12">`;
  s += `<defs>${Object.entries(COLORS).map(([k, c]) => `<marker id="ah-${k}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="${c}"/></marker>`).join('')}</defs>`;
  const heads = [lane(leftIp), 'CUBE\n' + (cfg && cfg.hostname ? cfg.hostname : ''), lane(rightIp)];
  heads.forEach((t, i) => {
    const fill = i === 1 ? '#e3f2fd' : '#f5f5f5';
    s += `<rect x="${X[i] - 90}" y="10" width="180" height="48" rx="6" fill="${fill}" stroke="#90a4ae"/>`;
    t.split('\n').forEach((ln, j) => (s += `<text x="${X[i]}" y="${30 + j * 16}" text-anchor="middle" font-weight="${j ? 400 : 700}">${esc(ln)}</text>`));
    s += `<line x1="${X[i]}" y1="58" x2="${X[i]}" y2="${H - 20}" stroke="#b0bec5" stroke-dasharray="4 4"/>`;
  });
  rows.forEach((r, i) => {
    const y = top + i * RH;
    if (r.type === 'note') {
      const c = { info: ['#fffde7', '#f9a825'], warn: ['#fff3e0', '#ef6c00'], err: ['#ffebee', '#c62828'] }[r.kind];
      s += `<rect x="${X[1] - 190}" y="${y - 12}" width="380" height="22" rx="4" fill="${c[0]}" stroke="${c[1]}"/>`;
      s += `<text x="${X[1]}" y="${y + 3}" text-anchor="middle" font-size="11">${esc(r.text.length > 70 ? r.text.slice(0, 69) + '…' : r.text)}</text>`;
      return;
    }
    const { m, isIn } = r;
    const a1 = isIn ? X[0] : X[1];
    const a2 = isIn ? X[1] : X[2];
    // in-leg: recv = peer->CUBE (left to right); sent = CUBE->peer (right to left)
    // out-leg: sent = CUBE->peer (left to right); recv = peer->CUBE (right to left)
    const ltr = isIn ? m.dir === 'recv' : m.dir === 'sent';
    const x1 = ltr ? a1 : a2;
    const x2 = ltr ? a2 : a1;
    const ck = colorKey(m);
    const col = COLORS[ck];
    s += `<line x1="${x1}" y1="${y}" x2="${x2 + (ltr ? -3 : 3)}" y2="${y}" stroke="${col}" stroke-width="1.6" marker-end="url(#ah-${ck})"/>`;
    s += `<text x="${(a1 + a2) / 2}" y="${y - 4}" text-anchor="middle" fill="${col}" font-weight="${m.kind === 'resp' && m.code >= 300 ? 700 : 400}">${esc(label(m))}</text>`;
    s += `<text x="6" y="${y + 4}" font-size="10" fill="#78909c">${esc(m.tsText.replace(/^\w+ +\d+ (\d{4} )?/, '').replace(/ [A-Za-z]{2,5}$/, ''))}</text>`;
  });
  s += '</svg>';
  return s;
}

