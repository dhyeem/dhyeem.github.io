// Parsers for optional show outputs:
//  - show dial-peer voice summary
//  - show dialplan number <digits>
//  - show voip trace cover-buffers  (+ any "dial peer" lines)

/** `show dial-peer voice summary` -> [{tag,type,admin,oper,prefix,destPattern,pref,target,busyout}] */
export function parseDialPeerSummary(text) {
  const rows = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\s*(\d+)\s+(voip|pots|mmoip|vofr|voatm)\s+(up|down)\s+(up|down)\s*(.*)$/i.exec(line);
    if (!m) continue;
    const rest = m[5].trim();
    const toks = rest ? rest.split(/\s+/) : [];
    let prefix = '';
    let dest = '';
    let pref = null;
    let target = '';
    const sIdx = toks.findIndex((t) => /^(syst|sys|h323|sip|ras|\w*pass)/i.test(t) && toks.indexOf(t) > 0 && /^\d+$/.test(toks[toks.indexOf(t) - 1]));
    if (sIdx > 0) {
      pref = +toks[sIdx - 1];
      const before = toks.slice(0, sIdx - 1);
      if (before.length >= 2) [prefix, dest] = before;
      else if (before.length === 1) dest = before[0];
      target = toks.slice(sIdx + 1).filter((t) => t !== 'busyout').join(' ');
    } else {
      dest = toks[0] || '';
    }
    rows.push({
      tag: +m[1],
      type: m[2].toLowerCase(),
      admin: m[3].toLowerCase(),
      oper: m[4].toLowerCase(),
      prefix,
      destPattern: dest,
      pref,
      target,
      busyout: /busyout/.test(line),
      raw: line.trim(),
    });
  }
  return rows;
}

/** `show dialplan number X` -> {number, matches:[{tag,pattern,pref,matched,digits,target,type}], noMatch} */
export function parseDialplanNumber(text) {
  const t = String(text || '');
  if (!/Macro Exp|Peer|No match/i.test(t)) return null;
  const res = { number: '', macro: '', matches: [], noMatch: /No match|no dial-?peer/i.test(t) };
  const nm = /show dialplan number (\S+)/i.exec(t);
  if (nm) res.number = nm[1];
  const mm = /Macro Exp\.?:\s*(\S+)/i.exec(t);
  if (mm) res.macro = mm[1];
  const parts = t.split(/^(?=\w*Peer\d+\s*$)/m);
  for (const p of parts) {
    const h = /^(\w*Peer)(\d+)/.exec(p);
    if (!h) continue;
    const g = (re) => (re.exec(p) || [])[1] || '';
    res.matches.push({
      type: h[1],
      tag: +g(/tag = (\d+)/) || +h[2],
      pattern: g(/destination-pattern = '([^']*)'/),
      pref: +(g(/preference = (\d+)/) || 0),
      matched: g(/Matched:\s*(\S+)/),
      digits: +(g(/Digits:\s*(\d+)/) || 0),
      target: g(/Target:\s*(\S+)/) || g(/session target = ([^,\s]+)/),
    });
  }
  return res;
}

/** `show voip trace cover-buffers` -> [{key,callId,peerCallId,called,calling,sipCallId,guid}] */
export function parseVoipTrace(text) {
  const out = [];
  const blocks = String(text || '').split(/-{5,}\s*Cover Buffer\s*-{5,}/i).slice(1);
  for (const b of blocks) {
    const g = (re) => (re.exec(b) || [])[1] || '';
    out.push({
      key: g(/Search-key\s*=\s*(\S+)/),
      callId: +g(/\bCallID\s*=\s*(\d+)/) || null,
      peerCallId: +g(/Peer-CallID\s*=\s*(\d+)/) || null,
      called: g(/Called-Number\s*=\s*(\S*)/),
      calling: g(/Calling-Number\s*=\s*(\S*)/),
      sipCallId: g(/SIP CallID\s*=\s*(\S+)/),
      guid: g(/GUID\s*=\s*([0-9A-Fa-f]+)/).toUpperCase(),
    });
  }
  return out;
}
