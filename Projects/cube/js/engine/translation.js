// Voice translation-rule / profile simulation (sed-style /match/ /replace/).
// Cisco semantics: rules are searched top-down, first match wins, match is NOT anchored
// unless it uses ^, and only the matched part is replaced (rest of the number is kept).
// In the running-config, groups are written \( \) ; \0 or & = whole match ; \1..\9 = groups.

/** Convert a Cisco (BRE-like) rule match string to a JS RegExp. */
export function ruleToRegExp(match) {
  let out = '';
  for (let i = 0; i < match.length; i++) {
    const c = match[i];
    if (c === '\\' && i + 1 < match.length) {
      const n = match[++i];
      if (n === '(') out += '(';
      else if (n === ')') out += ')';
      else if (n === '|') out += '|';
      else if (/\d/.test(n)) out += '\\' + n;
      else out += '\\' + n;
    } else if (c === '(' || c === ')' || c === '|' || c === '{' || c === '}') out += '\\' + c;
    else out += c;
  }
  try {
    return new RegExp(out);
  } catch {
    return null;
  }
}

export function applyRule(rule, number) {
  const rx = ruleToRegExp(rule.match);
  if (!rx) return { matched: false, invalid: true };
  const m = rx.exec(number);
  if (!m) return { matched: false };
  if (rule.reject) return { matched: true, rejected: true, out: number };
  const rep = (rule.replace ?? '').replace(/\\(\d)|&/g, (all, d) => (all === '&' ? m[0] : (m[+d] ?? '')));
  return { matched: true, out: number.slice(0, m.index) + rep + number.slice(m.index + m[0].length) };
}

/** Apply a numbered rule-set. Returns {out, ruleSeq, matched, rejected, steps}. */
export function applyRuleSet(cfg, ruleId, number) {
  const rules = cfg.rules[ruleId];
  if (!rules) return { out: number, matched: false, missing: true, ruleId, steps: [] };
  const steps = [];
  for (const r of rules) {
    const res = applyRule(r, number);
    steps.push({ seq: r.seq, raw: r.raw, matched: res.matched });
    if (res.matched) {
      return { out: res.out, matched: true, rejected: !!res.rejected, ruleSeq: r.seq, ruleRaw: r.raw, ruleId, steps };
    }
  }
  return { out: number, matched: false, ruleId, steps };
}

/** Apply a translation profile for `kind` ('called' | 'calling'). */
export function applyProfile(cfg, profileName, kind, number) {
  if (!profileName) return { out: number, applied: false, name: null };
  const prof = cfg.profiles[profileName];
  if (!prof) return { out: number, applied: false, name: profileName, missingProfile: true };
  const ruleId = prof[kind];
  if (!ruleId) return { out: number, applied: false, name: profileName, noRule: true };
  const r = applyRuleSet(cfg, ruleId, number);
  return { ...r, applied: true, name: profileName, kind };
}

/** Test helper equivalent to `test voice translation-rule <id> <number>` */
export const testRule = (cfg, id, number) => applyRuleSet(cfg, id, number);
