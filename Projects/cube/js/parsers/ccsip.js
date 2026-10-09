// Parser for `debug ccsip messages` (ccsipDisplayMsg blocks).

const COMPACT = { v: 'via', f: 'from', t: 'to', i: 'call-id', m: 'contact', c: 'content-type', l: 'content-length' };

/** Parse a SIP/TEL URI out of a header value or request-URI. */
export function parseUri(value) {
  if (!value) return null;
  let v = String(value).trim();
  let display = '';
  const ang = /^(.*?)<([^>]*)>/.exec(v);
  if (ang) {
    display = ang[1].trim().replace(/^"|"$/g, '');
    v = ang[2];
  }
  const m = /^(sips?|tel):(.*)$/i.exec(v.trim());
  if (!m) return { scheme: '', user: '', host: v, port: '', params: '', display, raw: value };
  const scheme = m[1].toLowerCase();
  let rest = m[2];
  let params = '';
  if (scheme === 'tel') {
    const [num, ...p] = rest.split(';');
    return { scheme, user: num, host: '', port: '', params: p.join(';'), display, raw: value };
  }
  let user = '';
  const at = rest.lastIndexOf('@');
  if (at >= 0) {
    user = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }
  const sc = rest.indexOf(';');
  if (sc >= 0) {
    params = rest.slice(sc + 1);
    rest = rest.slice(0, sc);
  }
  let host = rest;
  let port = '';
  const pm = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(rest);
  if (pm) {
    host = pm[1];
    port = pm[2] || '';
  }
  // user parameters (";phone-context=...") are not part of the number
  const userNum = user.split(';')[0];
  return { scheme, user: userNum, userRaw: user, host, port, params, display, raw: value };
}

const STATIC_PT = { 0: 'PCMU', 3: 'GSM', 4: 'G723', 8: 'PCMA', 9: 'G722', 15: 'G728', 18: 'G729', 2: 'G726-32' };

/** Map an SDP codec name to the Cisco IOS codec keywords that represent it. */
export function ciscoCodecsFor(name) {
  const n = String(name || '').toUpperCase();
  const map = {
    PCMU: ['g711ulaw'],
    PCMA: ['g711alaw'],
    G729: ['g729r8', 'g729br8', 'g729abr8', 'g729ar8'],
    G722: ['g722-64', 'g722-56', 'g722-48'],
    G723: ['g723r63', 'g723r53', 'g723ar63', 'g723ar53'],
    'G726-32': ['g726r32'],
    G728: ['g728'],
    ILBC: ['ilbc'],
    OPUS: ['opus'],
    GSM: ['gsmfr'],
  };
  return map[n] || [];
}

export function parseSdp(lines) {
  const sdp = { connection: '', media: [], codecs: [], dtmf: null, dtmfPt: null, direction: '', raw: lines.join('\n') };
  const rtpmap = {};
  let curM = null;
  for (const l of lines) {
    let m;
    if ((m = /^c=IN IP[46] (\S+)/.exec(l))) {
      if (curM) curM.connection = m[1];
      else sdp.connection = m[1];
    } else if ((m = /^m=(\w+) (\d+) (\S+)\s*(.*)$/.exec(l))) {
      curM = { type: m[1], port: +m[2], proto: m[3], pts: m[4].split(/\s+/).filter(Boolean), connection: '' };
      sdp.media.push(curM);
    } else if ((m = /^a=rtpmap:(\d+) ([^/\s]+)\/?(\d+)?/.exec(l))) {
      rtpmap[m[1]] = m[2];
    } else if ((m = /^a=(sendrecv|sendonly|recvonly|inactive)/.exec(l))) {
      sdp.direction = m[1];
    }
  }
  const audio = sdp.media.find((x) => x.type === 'audio');
  if (audio) {
    for (const pt of audio.pts) {
      const name = rtpmap[pt] || STATIC_PT[pt] || 'PT' + pt;
      if (/telephone-event/i.test(name)) {
        sdp.dtmf = 'rtp-nte';
        sdp.dtmfPt = pt;
      } else if (!/^(CN|PT)/i.test(name) || /^PT/.test(name)) {
        sdp.codecs.push({ pt, name });
      }
    }
  }
  sdp.audioPort = audio ? audio.port : null;
  return sdp;
}

/** Parse one ccsipDisplayMsg block into a message object. */
export function parseSipBlock(block) {
  const lines = block.lines.slice();
  let first = lines.findIndex((l) => l.trim() !== '');
  if (first < 0) return null;
  let dirLine = lines[first].trim();
  const dm = /^(Received|Sent):\s*(.*)$/.exec(dirLine);
  if (!dm) return null;
  const dir = dm[1] === 'Received' ? 'recv' : 'sent';
  let body = lines.slice(first + 1);
  if (dm[2]) body.unshift(dm[2]);
  while (body.length && body[0].trim() === '') body.shift();
  if (!body.length) return null;
  const startLine = body[0].trim();
  const msg = {
    dir,
    ts: block.ts,
    tsText: block.tsText,
    lineNo: block.lineNo,
    ccId: block.callId,
    guid: block.guid,
    startLine,
    headers: {},
    rawLines: body,
  };
  let m;
  if ((m = /^SIP\/2\.0 (\d{3})\s*(.*)$/.exec(startLine))) {
    msg.kind = 'resp';
    msg.code = +m[1];
    msg.reason = m[2];
  } else if ((m = /^([A-Z]+) (\S+) SIP\/2\.0$/.exec(startLine))) {
    msg.kind = 'req';
    msg.method = m[1];
    msg.uri = m[2];
  } else {
    return null;
  }
  let i = 1;
  let lastKey = null;
  for (; i < body.length; i++) {
    const l = body[i];
    if (l === '') break;
    if (/^\s/.test(l) && lastKey) {
      const arr = msg.headers[lastKey];
      arr[arr.length - 1] += ' ' + l.trim();
      continue;
    }
    const hm = /^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/.exec(l);
    if (!hm) continue;
    let key = hm[1].toLowerCase();
    key = COMPACT[key] || key;
    (msg.headers[key] ||= []).push(hm[2].trim());
    lastKey = key;
  }
  const sdpLines = body.slice(i + 1).filter((l) => l !== '');
  if (sdpLines.some((l) => /^v=0/.test(l))) msg.sdp = parseSdp(sdpLines);
  const h = (k) => (msg.headers[k] ? msg.headers[k][0] : '');
  msg.h = h;
  msg.callId = h('call-id');
  const cs = /^(\d+)\s+(\S+)/.exec(h('cseq'));
  msg.cseq = cs ? { num: +cs[1], method: cs[2] } : { num: 0, method: msg.method || '' };
  msg.method = msg.method || msg.cseq.method;
  msg.from = parseUri(h('from'));
  msg.to = parseUri(h('to'));
  msg.reqUri = msg.kind === 'req' ? parseUri(msg.uri) : null;
  msg.pai = parseUri(h('p-asserted-identity'));
  msg.rpid = parseUri(h('remote-party-id'));
  msg.ppi = parseUri(h('p-preferred-identity'));
  msg.diversion = parseUri(h('diversion'));
  msg.contact = parseUri(h('contact'));
  const via = h('via');
  const vm = /SIP\/2\.0\/(\w+)\s+([^;\s,]+)/i.exec(via);
  msg.via = vm ? { transport: vm[1].toUpperCase(), sentBy: vm[2], host: vm[2].replace(/:\d+$/, '') } : null;
  msg.reasonHdr = h('reason');
  msg.warning = h('warning');
  msg.userAgent = h('user-agent') || h('server');
  return msg;
}

export function parseSipMessages(blocks) {
  const msgs = [];
  for (const b of blocks) {
    if (!/\bSIP\/Msg\/ccsipDisplayMsg:/.test(b.rest)) continue;
    const m = parseSipBlock(b);
    if (m) msgs.push(m);
  }
  return msgs;
}
