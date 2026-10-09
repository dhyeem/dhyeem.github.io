// ITSP profile helpers: number classification (E.164 etc.) and DID range checks.

export const FORMATS = {
  e164plus: '+E.164 (e.g. +966138105234)',
  e164: 'E.164 without + (e.g. 966138105234)',
  national: 'National with leading 0 (e.g. 0138105234)',
  any: 'Any (do not check)',
};

export function defaultProfile() {
  return {
    name: 'My ITSP',
    ips: [],
    countryCode: '966',
    didRanges: '',
    inbound: { called: 'e164plus', calling: 'e164plus' },
    outbound: { called: 'e164plus', calling: 'e164plus' },
    callerInRange: true,
  };
}

const digitsOf = (s) => String(s || '').replace(/[^0-9]/g, '');

/** @returns 'e164plus' | 'e164' | 'national' | 'intl00' | 'short' | 'other' | 'empty' */
export function classifyNumber(n, cc = '') {
  const s = String(n || '').trim();
  if (!s) return 'empty';
  if (/^\+\d{7,15}$/.test(s)) return 'e164plus';
  if (/^\+/.test(s)) return 'other';
  if (!/^\d+$/.test(s)) return 'other';
  if (/^00\d{7,}$/.test(s)) return 'intl00';
  if (cc && s.startsWith(cc) && s.length >= cc.length + 6 && s.length <= 15) return 'e164';
  if (/^0\d{6,}$/.test(s)) return 'national';
  if (s.length <= 6) return 'short';
  return 'other';
}

export function formatMatches(actual, required, cc) {
  const cls = classifyNumber(actual, cc);
  if (required === 'any' || !required) return { ok: true, cls };
  return { ok: cls === required, cls };
}

/** Normalize to E.164 digits (no +) when possible; null if it looks like a local/short number. */
export function toE164Digits(n, cc) {
  const s = String(n || '').trim();
  let d = digitsOf(s);
  if (!d) return null;
  if (s.startsWith('+')) return d;
  if (d.startsWith('00')) return d.slice(2);
  if (cc && d.startsWith(cc) && d.length >= cc.length + 6) return d;
  if (d.startsWith('0') && cc && d.length >= 7) return cc + d.slice(1);
  return null;
}

/** Parse DID ranges text. Accepts "from-to", "+9661381052xx", "9661381052..", single numbers. */
export function parseRanges(text, cc) {
  const out = [];
  for (const rawTok of String(text || '').split(/[\n;,]+/)) {
    const tok = rawTok.trim();
    if (!tok) continue;
    const rm = /^(\+?[\dxX.#]+)\s*(?:-|to)\s*(\+?[\dxX.#]+)$/i.exec(tok);
    let from;
    let to;
    if (rm) {
      from = rm[1];
      to = rm[2];
      const a = toE164Digits(from.replace(/[xX.#]/g, '0'), cc) || digitsOf(from);
      let b = toE164Digits(to.replace(/[xX.#]/g, '9'), cc) || digitsOf(to);
      if (b.length < a.length) b = a.slice(0, a.length - b.length) + b;
      out.push({ from: a, to: b, label: tok });
    } else {
      const a = toE164Digits(tok.replace(/[xX.#]/g, '0'), cc) || digitsOf(tok.replace(/[xX.#]/g, '0'));
      const b = toE164Digits(tok.replace(/[xX.#]/g, '9'), cc) || digitsOf(tok.replace(/[xX.#]/g, '9'));
      out.push({ from: a, to: b, label: tok });
    }
  }
  return out.filter((r) => r.from && r.to);
}

/** @returns true | false | null (cannot tell: short/local number or no ranges) */
export function inRanges(n, ranges, cc) {
  if (!ranges.length) return null;
  const d = toE164Digits(n, cc);
  if (!d) return null;
  return ranges.some((r) => d.length === r.from.length && d >= r.from && d <= r.to);
}
