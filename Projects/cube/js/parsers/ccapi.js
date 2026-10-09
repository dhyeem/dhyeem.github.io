// Tolerant parser for `debug voip ccapi inout` (and optional `debug voip dialpeer` DPM lines).
//
// Documented by Cisco: each line starts with `//<CallID>/<GUID>/CCAPI/<function>:` and the
// details follow as indented `Key=Value` text. Field names below follow what IOS/IOS-XE
// prints (Calling Number=, Called Number=, Incoming Dial-peer=, Cause Value=, Call Id=...).
// NOTE: not yet verified against a real capture from the user's CUBE; every regex is
// intentionally loose and every field is optional.

const grab = (re, s) => {
  const m = re.exec(s);
  return m ? m[1] : null;
};

export function parseCcapiBlock(block) {
  const fm = /^(CCAPI|DPM)\/([A-Za-z_0-9]+):?\s*(.*)$/.exec(block.body);
  if (!fm) return null;
  const mod = fm[1];
  const func = fm[2];
  const text = [fm[3], ...block.lines].join(' ').replace(/\s+/g, ' ').trim();
  const ev = {
    ts: block.ts,
    tsText: block.tsText,
    lineNo: block.lineNo,
    module: mod,
    func,
    callId: block.callId,
    guid: block.guid,
    text,
    raw: [block.tsText + ' //' + block.callId + '/' + (block.guid || 'xxxxxxxxxxxx') + '/' + block.body, ...block.lines].join('\n'),
  };
  const bodyCallId = grab(/\bCall Id=(-?\d+)/i, text);
  ev.bodyCallId = bodyCallId != null ? +bodyCallId : null;
  ev.calling = grab(/Calling Number=([^,()\s]*)/i, text);
  ev.called = grab(/Called Number=([^,()\s]*)/i, text);
  const inDp = grab(/Incoming Dial-?peer(?: Tag)?\s*[=:]\s*(\d+)/i, text);
  if (inDp != null) ev.inDp = +inDp;
  const outDp =
    grab(/(?:Outgoing|Outbound) Dial-?peer(?: Tag)?\s*[=:]\s*(\d+)/i, text) ??
    grab(/Voice Peer Tag\s*=\s*(\d+)/i, text) ??
    (inDp == null ? grab(/\bDial-?peer(?: Tag)?\s*[=:]\s*(\d+)/i, text) : null);
  if (outDp != null) ev.outDp = +outDp;
  if (mod === 'DPM') {
    const pt = grab(/(?:peer[_ ]tag|Peer Tag)\s*[=:]\s*(\d+)/i, text);
    if (pt != null && /Incoming/i.test(func)) ev.inDp = +pt === 2147483647 ? 0 : +pt;
    else if (pt != null && /Match/i.test(func)) ev.outDp = +pt;
  }
  const cause = grab(/Cause Value=(\d+)/i, text);
  if (cause != null) ev.cause = +cause;
  ev.calledTranslated = grab(/Called Translated=(\w+)/i, text);
  ev.callingTranslated = grab(/Calling Translated=(\w+)/i, text);
  return ev;
}
export function parseCcapi(blocks) {
  const events = [];
  for (const b of blocks) {
    if (!/^(CCAPI|DPM)\//.test(b.body)) continue;
    const e = parseCcapiBlock(b);
    if (e) events.push(e);
  }
  return events;
}

/** VOICE_IEC and SIP/CCAPI syslog lines (voice iec syslog). */
export function parseSyslogEvents(blocks) {
  const out = [];
  for (const b of blocks) {
    const r = b.rest;
    let m;
    if ((m = /^%VOICE_IEC-\d-GW:\s*(.*?):\s*Internal Error \((.*?)\):\s*IEC=([\d.]+)(?: on callID (\d+))?(?: GUID=([0-9A-Fa-f]+))?/.exec(r))) {
      out.push({ type: 'iec', ts: b.ts, tsText: b.tsText, layer: m[1], text: m[2], iec: m[3], callId: m[4] ? +m[4] : null, guid: m[5] ? m[5].toUpperCase() : null, raw: r, lineNo: b.lineNo });
    } else if ((m = /^%SIP-3-MAXCONNCAC:.*dial-peer (\d+).*response (\d+)/.exec(r))) {
      out.push({ type: 'maxconn', ts: b.ts, tsText: b.tsText, dp: +m[1], code: +m[2], raw: r, lineNo: b.lineNo });
    } else if ((m = /^%CALL_CONTROL-6-MAX_CONNECTIONS:.*dial-peer (\d+)/.exec(r))) {
      out.push({ type: 'maxconn', ts: b.ts, tsText: b.tsText, dp: +m[1], raw: r, lineNo: b.lineNo });
    } else if (/^%(SIP|VOICE_IEC|CCH323|DIALPEER_DB|CALL_CONTROL)-/.test(r)) {
      out.push({ type: 'syslog', ts: b.ts, tsText: b.tsText, raw: r, lineNo: b.lineNo });
    }
  }
  return out;
}
