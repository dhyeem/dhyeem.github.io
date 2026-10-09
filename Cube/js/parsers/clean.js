// Log cleaning and block splitting for Cisco IOS-XE debug output.

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** Timestamp -> comparable epoch ms (year defaults to 2000 when the log has none). */
export function parseTs(text) {
  const m = /([A-Z][a-z]{2}) +(\d+)(?: (\d{4}))? (\d\d):(\d\d):(\d\d)(?:\.(\d+))?/.exec(text || '');
  if (!m) return 0;
  const ms = m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0;
  return Date.UTC(m[3] ? +m[3] : 2000, MONTHS[m[1]] ?? 0, +m[2], +m[4], +m[5], +m[6], ms);
}

/**
 * Remove terminal-recorder prefixes ("HH:MM:SS.mmm §"), BOM, --More-- and the
 * whitespace-only lines a recorder injects at buffer boundaries. Real blank
 * lines (empty) are preserved because they separate SIP headers from the body.
 */
export function cleanLog(text) {
  const out = [];
  const src = String(text || '').replace(/^\uFEFF/, '').split(/\r?\n/);
  for (const raw of src) {
    let l = raw.replace(/^\d{1,2}:\d\d:\d\d(?:\.\d+)?\s*[§\uFFFD\u00A7]/, '');
    l = l.replace(/\s*--More--\s*/g, '').replace(/\u0008+\s*/g, '');
    if (l.length && !l.trim()) continue;
    out.push(l.replace(/\s+$/, ''));
  }
  return out;
}

const TS_RE = String.raw`[*.]?[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d+)?(?: [A-Za-z]{2,5})?`;
const HEAD = new RegExp(`^(?:(\\d+): )?(${TS_RE}):(?: (.*))?$`);
const DBG = /^\/\/(-?\d+)\/([0-9A-Fa-fx]+)\/(.*)$/;

/**
 * Split cleaned lines into debug "blocks": a timestamped line plus the
 * un-timestamped continuation lines that follow it.
 */
export function splitBlocks(lines) {
  const blocks = [];
  let cur = null;
  lines.forEach((line, i) => {
    const m = HEAD.exec(line);
    if (m) {
      cur = {
        seq: m[1] ? +m[1] : null,
        tsText: m[2].replace(/^[*.]/, ''),
        ts: parseTs(m[2]),
        rest: m[3] || '',
        lines: [],
        lineNo: i + 1,
        callId: null,
        guid: null,
        body: '',
      };
      const d = DBG.exec(cur.rest);
      if (d) {
        cur.callId = +d[1];
        cur.guid = /^x+$/i.test(d[2]) ? null : d[2].toUpperCase();
        cur.body = d[3];
      }
      blocks.push(cur);
    } else if (cur) {
      cur.lines.push(line);
    }
  });
  for (const b of blocks) {
    while (b.lines.length && b.lines[b.lines.length - 1] === '') b.lines.pop();
  }
  return blocks;
}
