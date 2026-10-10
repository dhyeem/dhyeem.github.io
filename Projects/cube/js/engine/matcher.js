// Dial-peer matching simulation following Cisco's documented preference order.
//   Inbound (SIP)  : incoming uri via > request > to > from > incoming called-number / called e164-pattern-map
//                    > answer-address / calling e164-pattern-map > destination-pattern (vs calling) > dial-peer 0
//   Outbound (SIP) : destination dpg > (provision-policy uri) > route-string > destination uri
//                    > destination-pattern / e164-pattern-map  ; none => call fails
import { matchPattern, explainMismatch } from './pattern.js';

const isSipCapable = (dp) => dp.type === 'voip' && !/^(h323|cisco)$/i.test(dp.sessionProtocol || '');

function uriClassMatch(cfg, name, uri) {
  const cls = cfg.uriClasses[name];
  if (!cls) return { ok: false, reason: `voice class uri ${name} is not configured` };
  if (!uri) return { ok: false, reason: 'header not present in message' };
  const checks = [];
  if (cls.hosts.length) {
    const host = uri.host || '';
    const ok = cls.hosts.some((h) => {
      const v = h.replace(/^(ipv4|ipv6|dns):/, '');
      if (/^ipv4:/.test(h)) return v === host;
      try {
        return new RegExp('^(?:' + v + ')$', 'i').test(host);
      } catch {
        return false;
      }
    });
    checks.push({ what: 'host', ok, want: cls.hosts.join(', '), got: host });
  }
  if (cls.user) {
    let ok = false;
    try {
      ok = new RegExp('^(?:' + cls.user + ')$', 'i').test(uri.user || '');
    } catch {}
    checks.push({ what: 'user-id', ok, want: cls.user, got: uri.user || '' });
  }
  if (cls.pattern) {
    let ok = false;
    try {
      ok = new RegExp(cls.pattern, 'i').test(`${uri.user || ''}@${uri.host || ''}`);
    } catch {}
    checks.push({ what: 'pattern', ok, want: cls.pattern, got: `${uri.user || ''}@${uri.host || ''}` });
  }
  if (!checks.length) return { ok: false, reason: 'voice class uri has no host/user-id/pattern' };
  const bad = checks.find((c) => !c.ok);
  return bad ? { ok: false, reason: `${bad.what} "${bad.got}" does not match "${bad.want}"` } : { ok: true, len: 1, literal: 1 };
}

const mapPatterns = (cfg, id) => cfg.patternMaps[id] || [];

/**
 * @param ctx {called, calling, uris:{via,request,to,from}}
 */
export function matchInbound(cfg, ctx) {
  const steps = [];
  const dps = cfg.dialPeers;
  let winner = null;
  const order = (a, b) => b.literal - a.literal || a.idx - b.idx;

  const uriSteps = ['via', 'request', 'to', 'from'];
  uriSteps.forEach((k) => {
    const step = { name: `incoming uri ${k}`, tried: [], winner: null };
    dps.forEach((dp, idx) => {
      if (!dp.incomingUri[k]) return;
      const eligible = isSipCapable(dp) && !dp.shutdown;
      const r = eligible ? uriClassMatch(cfg, dp.incomingUri[k], ctx.uris?.[k]) : { ok: false, reason: dp.shutdown ? 'dial-peer is shutdown' : 'not a SIP voip dial-peer' };
      step.tried.push({ tag: dp.tag, field: `incoming uri ${k} ${dp.incomingUri[k]}`, input: ctx.uris?.[k] ? `${ctx.uris[k].user || ''}@${ctx.uris[k].host || ''}` : '(none)', ok: r.ok, reason: r.reason, literal: r.literal || 0, idx });
    });
    step.winner = step.tried.filter((t) => t.ok).sort(order)[0] || null;
    steps.push(step);
  });

  const calledStep = { name: 'incoming called-number', tried: [], winner: null };
  dps.forEach((dp, idx) => {
    const eligible = isSipCapable(dp) && !dp.shutdown;
    const pats = [...dp.incomingCalled.map((p) => ({ p, f: `incoming called-number ${p}` }))];
    if (dp.incomingCalledMap) mapPatterns(cfg, dp.incomingCalledMap).forEach((p) => pats.push({ p, f: `incoming called e164-pattern-map ${dp.incomingCalledMap} (${p})` }));
    pats.forEach(({ p, f }) => {
      if (!eligible) {
        calledStep.tried.push({ tag: dp.tag, field: f, pattern: p, input: ctx.called, ok: false, reason: dp.shutdown ? 'dial-peer is shutdown' : 'not a SIP voip dial-peer', literal: 0, idx });
        return;
      }
      const r = matchPattern(p, ctx.called);
      calledStep.tried.push({ tag: dp.tag, field: f, pattern: p, input: ctx.called, ok: r.ok, reason: r.ok ? '' : explainMismatch(p, ctx.called), literal: r.literal, len: r.len, idx });
    });
  });
  calledStep.winner = calledStep.tried.filter((t) => t.ok).sort(order)[0] || null;
  steps.push(calledStep);

  const callingStep = { name: 'answer-address / incoming calling', tried: [], winner: null };
  dps.forEach((dp, idx) => {
    const eligible = isSipCapable(dp) && !dp.shutdown;
    const pats = [];
    if (dp.answerAddress) pats.push({ p: dp.answerAddress, f: `answer-address ${dp.answerAddress}` });
    if (dp.incomingCallingMap) mapPatterns(cfg, dp.incomingCallingMap).forEach((p) => pats.push({ p, f: `incoming calling e164-pattern-map ${dp.incomingCallingMap} (${p})` }));
    pats.forEach(({ p, f }) => {
      if (!eligible) {
        callingStep.tried.push({ tag: dp.tag, field: f, pattern: p, input: ctx.calling, ok: false, reason: dp.shutdown ? 'dial-peer is shutdown' : 'not a SIP voip dial-peer', literal: 0, idx });
        return;
      }
      const r = matchPattern(p, ctx.calling);
      callingStep.tried.push({ tag: dp.tag, field: f, pattern: p, input: ctx.calling, ok: r.ok, reason: r.ok ? '' : explainMismatch(p, ctx.calling), literal: r.literal, len: r.len, idx });
    });
  });
  callingStep.winner = callingStep.tried.filter((t) => t.ok).sort(order)[0] || null;
  steps.push(callingStep);

  const destStep = { name: 'destination-pattern (vs calling number)', tried: [], winner: null };
  dps.forEach((dp, idx) => {
    if (!dp.destPattern) return;
    const eligible = isSipCapable(dp) && !dp.shutdown;
    if (!eligible) {
      destStep.tried.push({ tag: dp.tag, field: `destination-pattern ${dp.destPattern}`, pattern: dp.destPattern, input: ctx.calling, ok: false, reason: dp.shutdown ? 'dial-peer is shutdown' : 'not a SIP voip dial-peer', literal: 0, idx });
      return;
    }
    const r = matchPattern(dp.destPattern, ctx.calling);
    destStep.tried.push({ tag: dp.tag, field: `destination-pattern ${dp.destPattern}`, pattern: dp.destPattern, input: ctx.calling, ok: r.ok, reason: r.ok ? '' : explainMismatch(dp.destPattern, ctx.calling), literal: r.literal, len: r.len, idx });
  });
  destStep.winner = destStep.tried.filter((t) => t.ok).sort(order)[0] || null;
  steps.push(destStep);

  const hit = steps.find((s) => s.winner);
  if (hit) winner = { tag: hit.winner.tag, step: hit.name, via: hit.winner.field };
  return { steps, winner, dp0: !winner };
}

/**
 * @param ctx {called, calling, inDp (dial-peer object|null), uris}
 */
export function matchOutbound(cfg, ctx) {
  const excluded = [];
  const tiers = [];
  const dps = cfg.dialPeers;
  const scheme = cfg.huntScheme || 0;
  const eligibleFor = (dp) => {
    if (dp.shutdown) return 'dial-peer is shutdown (administratively down)';
    if (dp.oper === 'down') return 'dial-peer operational state is down (see dial-peer summary)';
    if (dp.type !== 'voip') return `${dp.type} dial-peer (not used for SIP out-leg)`;
    if (/^(h323|cisco)$/i.test(dp.sessionProtocol || '')) return 'session protocol is not SIP';
    if (!dp.sessionTarget && !dp.destDpg) return 'no session target configured (dial-peer cannot go up)';
    return null;
  };

  const sorter = (a, b) =>
    scheme === 2 || scheme === 3 ? a.pref - b.pref || b.literal - a.literal || a.idx - b.idx : b.literal - a.literal || a.pref - b.pref || a.idx - b.idx;

  // Tier 1: dial-peer group from inbound dial-peer
  if (ctx.inDp && ctx.inDp.destDpg) {
    const grp = cfg.dpgs[ctx.inDp.destDpg] || [];
    const cands = grp
      .map((g, i) => ({ dp: dps.find((d) => d.tag === g.tag), pref: g.pref, idx: i }))
      .filter((c) => c.dp)
      .map((c) => ({ tag: c.dp.tag, dp: c.dp, via: `destination dpg ${ctx.inDp.destDpg}`, pattern: '(dial-peer group)', pref: c.pref, literal: 0, len: 0, idx: c.idx, blocked: eligibleFor(c.dp) }));
    tiers.push({ name: `destination dpg ${ctx.inDp.destDpg} (set on inbound dial-peer ${ctx.inDp.tag})`, cands });
  }

  const tUri = { name: 'destination uri', cands: [] };
  const tNum = { name: 'destination-pattern / destination e164-pattern-map', cands: [] };
  dps.forEach((dp, idx) => {
    const block = eligibleFor(dp);
    const hasAny = dp.destPattern || dp.destMap || dp.destUri;
    if (!hasAny) {
      if (dp.incomingCalled.length || dp.answerAddress || Object.keys(dp.incomingUri).length || dp.incomingCalledMap)
        excluded.push({ tag: dp.tag, reason: 'inbound-only dial-peer (no destination-pattern)', pattern: '' });
      return;
    }
    if (dp.destUri) {
      const r = uriClassMatch(cfg, dp.destUri, ctx.uris?.request);
      tUri.cands.push({ tag: dp.tag, dp, via: `destination uri ${dp.destUri}`, pattern: dp.destUri, ok: r.ok, reason: r.reason, pref: dp.preference, literal: r.literal || 0, len: r.len || 0, idx, blocked: block });
    }
    const pats = [];
    if (dp.destPattern) pats.push({ p: dp.destPattern, f: `destination-pattern ${dp.destPattern}` });
    if (dp.destMap) (cfg.patternMaps[dp.destMap] || []).forEach((p) => pats.push({ p, f: `destination e164-pattern-map ${dp.destMap} (${p})` }));
    pats.forEach(({ p, f }) => {
      const r = matchPattern(p, ctx.called);
      tNum.cands.push({ tag: dp.tag, dp, via: f, pattern: p, ok: r.ok, reason: r.ok ? '' : explainMismatch(p, ctx.called), pref: dp.preference, literal: r.literal, len: r.len, idx, blocked: block });
    });
  });
  tiers.push(tUri, tNum);

  let hunt = [];
  let usedTier = null;
  for (const t of tiers) {
    const matched = t.cands.filter((c) => c.ok !== false);
    const live = matched.filter((c) => !c.blocked);
    t.matched = matched;
    t.blockedMatches = matched.filter((c) => c.blocked);
    if (live.length && !usedTier) {
      usedTier = t.name;
      // one entry per dial-peer (best matching pattern)
      const byTag = new Map();
      live.sort(sorter).forEach((c) => !byTag.has(c.tag) && byTag.set(c.tag, c));
      hunt = [...byTag.values()].sort(sorter);
    }
  }
  const allTried = tiers.flatMap((t) => t.cands);
  return { tiers, tried: allTried, excluded, hunt, winner: hunt[0] || null, usedTier, scheme };
}
