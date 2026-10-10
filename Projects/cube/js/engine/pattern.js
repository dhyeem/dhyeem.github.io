// Cisco dial-peer pattern semantics (destination-pattern, incoming called-number, answer-address, e164-pattern-map).
//
// Per Cisco "Understand IOS and IOS XE Call Routing" (Dial-Peer Wildcards):
//   .  any one of 0-9 A-F * # +        T  variable length (0-32 chars)
//   %  previous char 0 or more         +  literal at the start of a string, else previous char 1 or more
//   ?  previous char 0 or 1            [ ] range (commas separate ranges)     ( ) group
//   ^  start (implicit)  $  end        \  escape     ,  pause (ignored)       * # literal keys
//
// ASSUMPTION: a pattern without "$" matches a prefix of the digit string (that is why
// "incoming called-number ." matches everything). Marked as a simulation in the UI.

const ANY = '[0-9A-Fa-f*#+]';

export function compilePattern(pattern) {
  let re = '';
  let literal = 0;
  const p = String(pattern || '');
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '+' && i === 0) {
      re += '\\+';
      literal++;
    } else if (c === '+') re += '+';
    else if (c === '.') re += ANY;
    else if (c === 'T' || c === 't') re += ANY + '*';
    else if (c === '%') re += '*';
    else if (c === '?') re += '?';
    else if (c === '^' && i === 0) re += '^';
    else if (c === '$') re += '$';
    else if (c === ',') continue;
    else if (c === '[') {
      const j = p.indexOf(']', i);
      if (j < 0) {
        re += '\\[';
        continue;
      }
      re += '[' + p.slice(i + 1, j).replace(/,/g, '') + ']';
      literal++;
      i = j;
    } else if (c === '(' || c === ')') re += c;
    else if (c === '\\' && i + 1 < p.length) {
      re += '\\' + p[++i];
      literal++;
    } else if (/[0-9A-Fa-f]/.test(c)) {
      re += c;
      literal++;
    } else {
      re += '\\' + c;
      literal++;
    }
  }
  if (!re.startsWith('^')) re = '^' + re;
  let rx;
  try {
    rx = new RegExp(re, 'i');
  } catch {
    rx = null;
  }
  return { rx, literal, source: pattern };
}

/** @returns {{ok:boolean, len:number, literal:number}} */
export function matchPattern(pattern, number) {
  if (!pattern || number == null) return { ok: false, len: 0, literal: 0 };
  const c = compilePattern(pattern);
  if (!c.rx) return { ok: false, len: 0, literal: 0, invalid: true };
  const m = c.rx.exec(String(number));
  if (!m) return { ok: false, len: 0, literal: c.literal };
  return { ok: true, len: m[0].length, literal: c.literal };
}

/** Explain in plain English why a pattern did not match a number (first divergence). */
export function explainMismatch(pattern, number) {
  const num = String(number || '');
  if (!pattern) return 'no pattern configured';
  if (num.startsWith('+') && !/^\+|\\\+/.test(pattern) && matchPattern(pattern, num.slice(1)).ok) {
    return `the number starts with "+" but the pattern has no leading "+"; it would match without the plus (${num.slice(1)})`;
  }
  const p = String(pattern);
  const c = compilePattern(p);
  if (!c.rx) return 'invalid pattern';
  // find longest prefix of the number that still matches a prefix of the pattern
  for (let k = num.length; k >= 0; k--) {
    const probe = compilePattern(p.replace(/\$$/, ''));
    if (probe.rx && probe.rx.test(num.slice(0, k)) && k < num.length && /\$$/.test(p)) {
      return `pattern is anchored with $ and expects the number to end earlier (number has ${num.length} chars)`;
    }
    break;
  }
  const fixedLen = p.replace(/\$$/, '').replace(/\[[^\]]*\]/g, 'x').replace(/[T%?]/gi, '').length;
  if (!/[T%+]/i.test(p.slice(1)) && num.length < fixedLen) return `number is too short (${num.length} chars, pattern needs ${fixedLen})`;
  return `"${num}" does not fit pattern "${pattern}"`;
}
