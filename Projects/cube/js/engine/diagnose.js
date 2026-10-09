// Per-call analysis: dial-peer simulation, translation timeline, ITSP/E.164 checks, findings.
import { matchInbound, matchOutbound } from './matcher.js';
import { applyProfile } from './translation.js';
import { classifyNumber, formatMatches, parseRanges, inRanges, FORMATS } from './itsp.js';
import { ciscoCodecsFor } from '../parsers/ccsip.js';
import { dialPeerByTag } from '../parsers/config.js';
import { matchPattern } from './pattern.js';

export const Q850 = {
  1: 'Unallocated (unassigned) number', 2: 'No route to specified transit network', 3: 'No route to destination',
  16: 'Normal call clearing', 17: 'User busy', 18: 'No user responding', 19: 'No answer from user (alerting)',
  20: 'Subscriber absent', 21: 'Call rejected', 22: 'Number changed', 27: 'Destination out of order',
  28: 'Invalid number format (address incomplete)', 29: 'Facility rejected', 31: 'Normal, unspecified',
  34: 'No circuit/channel available', 38: 'Network out of order', 41: 'Temporary failure', 42: 'Switching equipment congestion',
  44: 'Requested circuit/channel not available', 47: 'Resource unavailable, unspecified', 50: 'Requested facility not subscribed',
  57: 'Bearer capability not authorized', 58: 'Bearer capability not presently available', 63: 'Service or option not available',
  65: 'Bearer capability not implemented', 79: 'Service or option not implemented', 88: 'Incompatible destination',
  95: 'Invalid message, unspecified', 102: 'Recovery on timer expiry', 111: 'Protocol error, unspecified', 127: 'Interworking, unspecified',
  188: 'Dial-peer busyout (keepalive failed)',
};

const SIP_HELP = {
  400: ['Bad Request', 'The far end could not parse the request. Usually malformed headers, a bad number format or SIP profile / header-passing output.'],
  401: ['Unauthorized', 'The far end wants digest authentication. Check `authentication` / `credentials` in sip-ua (or tenant) and the ITSP username/password.'],
  407: ['Proxy Authentication Required', 'The far end wants digest authentication. Check `authentication` / `credentials` in sip-ua (or tenant) and the ITSP username/password.'],
  403: ['Forbidden', 'The far end understood the call but refused it. Typical ITSP causes: CUBE source IP not whitelisted, calling number (From/PAI) not one of your DIDs or not in the required format (+E.164), or call type/destination not allowed on the trunk.'],
  404: ['Not Found', 'The far end has no route for the called number. If CUBE sent it: no matching dial-peer. If the peer sent it: the number format is not what it expects (for example missing +E.164) or the DID/route is not provisioned.'],
  408: ['Request Timeout', 'No answer within the timer. Check reachability, firewall/ACL, and the far end load.'],
  480: ['Temporarily Unavailable', 'The destination is registered/known but not available (endpoint offline, DND, no registered device).'],
  481: ['Call/Transaction Does Not Exist', 'A mid-dialog request did not match a dialog. Check for stale sessions, session-timer/refresh problems or asymmetric routing.'],
  482: ['Loop Detected', 'The call looped. Often a catch-all dial-peer (for example `.T`) sends the call back to where it came from.'],
  484: ['Address Incomplete', 'Number too short or missing a prefix (country/area code). Check translation rules and the number format.'],
  486: ['Busy Here', 'Called party is busy.'],
  487: ['Request Terminated', 'Call was cancelled before answer (caller hung up or a hunt timer expired).'],
  488: ['Not Acceptable Here', 'Media negotiation failed: no common codec, SRTP/RTP mismatch, ptime or DTMF payload problem. Compare the SDP offer with `voice-class codec` on the dial-peers.'],
  491: ['Request Pending', 'Glare on re-INVITE/UPDATE.'],
  500: ['Server Internal Error', 'The far end hit an internal error. Check the Warning/Reason headers and the far-end logs.'],
  502: ['Bad Gateway', 'A proxy on the path could not reach the next hop.'],
  503: ['Service Unavailable', 'The far end is overloaded, the trunk is down/busy or CAC (max-conn) rejected the call. If CUBE sent it check `%SIP-3-MAXCONNCAC`, `max-conn`, `call threshold` and trusted-list rejections.'],
  504: ['Server Time-out', 'A proxy did not get a timely answer from the next hop.'],
  600: ['Busy Everywhere', 'All destinations are busy.'],
  603: ['Decline', 'Far end explicitly declined the call.'],
  604: ['Does Not Exist Anywhere', 'Number does not exist anywhere. Check the number format and the DID provisioning.'],
};

export const sipCodeText = (c) => (SIP_HELP[c] ? SIP_HELP[c][0] : '');

const hostOfTarget = (t) => {
  const m = /^(?:ipv4|ipv6):\[?([0-9a-fA-F.:]+?)\]?(?::\d+)?$/.exec(t || '') || /^dns:([^:\s]+)/.exec(t || '');
  return m ? m[1] : null;
};

export function emptyConfig() {
  return { dialPeers: [], rules: {}, profiles: {}, codecClasses: {}, uriClasses: {}, patternMaps: {}, dpgs: {}, trunkGroups: {}, sipUa: { servers: [] }, voiceService: { trustedIps: [], allow: [], sipLines: [] }, interfaces: [], huntScheme: 0, numExp: [], globalIncomingProfile: null, hostname: '', empty: true };
}

/** Merge `show dial-peer voice summary` rows into a config (or build stubs when there is no config). */
export function mergeSummary(cfg, rows) {
  if (!rows || !rows.length) return cfg;
  const out = cfg || emptyConfig();
  for (const r of rows) {
    let dp = out.dialPeers.find((d) => d.tag === r.tag);
    if (!dp) {
      dp = { tag: r.tag, type: r.type, shutdown: r.admin === 'down', destPattern: r.destPattern || null, incomingCalled: [], incomingUri: {}, translateOutgoing: {}, sessionTarget: r.target || null, preference: r.pref || 0, lines: [], fromSummaryOnly: true, description: '' };
      out.dialPeers.push(dp);
    }
    dp.oper = r.oper;
    dp.busyout = r.busyout;
    if (r.admin === 'down') dp.shutdown = true;
  }
  return out;
}

export function itspIps(cfg, itsp) {
  const set = new Set((itsp && itsp.ips) || []);
  const assumed = !set.size;
  if (assumed && cfg) {
    (cfg.sipUa.servers || []).forEach((s) => {
      const h = hostOfTarget(s);
      if (h) set.add(h);
    });
    cfg.dialPeers.filter((d) => d.destPattern && /^\.?T$|^\.T$|^\+?\.?T$/.test(d.destPattern)).forEach((d) => {
      const h = hostOfTarget(d.sessionTarget);
      if (h) set.add(h);
    });
  }
  return { ips: set, assumed };
}

export function peerRole(ip, cfg, itsp) {
  if (!ip) return 'Peer';
  const { ips } = itspIps(cfg, itsp);
  if (ips.has(ip)) return 'ITSP';
  if (cfg) {
    if (cfg.voiceService.trustedIps.includes(ip)) return 'CUCM/PBX';
    if (cfg.dialPeers.some((d) => hostOfTarget(d.sessionTarget) === ip)) return 'CUCM/PBX';
  }
  return 'Peer';
}

const ev = (m) => `${m.tsText}  ${m.dir === 'recv' ? 'Received' : 'Sent'}  ${m.startLine}`;

function dpCodecs(cfg, dp) {
  if (!dp) return null; // dial-peer 0 => all codecs
  if (dp.codecClass && cfg.codecClasses[dp.codecClass]) return cfg.codecClasses[dp.codecClass];
  if (dp.codec) return [dp.codec];
  return null; // default: all codecs (voice class not set)
}

export function analyzeCall(call, env) {
  const cfg = env.cfg || null;
  const itsp = env.itsp || null;
  const cc = (itsp && itsp.countryCode) || '';
  const ranges = itsp ? parseRanges(itsp.didRanges, cc) : [];
  const findings = [];
  const need = [];
  const add = (sev, id, title, detail, extra = {}) => findings.push({ sev, id, title, detail, evidence: extra.evidence || [], fix: extra.fix || [], pri: extra.pri ?? 50 });

  const res = {
    inbound: null,
    outbound: null,
    timeline: [],
    findings,
    need,
    inTag: null,
    outTag: null,
    simInTag: null,
    simOutTag: null,
  };

  const inD = call.in;
  const inInv = inD && inD.invite;
  const outD = call.outs[0] || null;
  const outInv = outD && outD.invite;

  if (!cfg) need.push({ what: 'running-config', why: 'to simulate dial-peer matching and translation rules and explain why a dial-peer was or was not selected' });
  if (!call.ccapi.length) need.push({ what: 'debug voip ccapi inout', why: 'to read the incoming/outgoing dial-peer the router actually selected (the tool otherwise only simulates it from the config)' });
  if (!itsp || !itsp.didRanges) need.push({ what: 'ITSP profile (DID ranges)', why: 'to check that numbers are inside your ranges and in the format your ITSP expects (+E.164)' });

  // ------------------------------------------------------------ inbound leg
  let inDp = null;
  let calledAfterIn = call.called;
  let callingAfterIn = call.calling;
  if (inInv) {
    const ctx = { called: call.called, calling: call.calling, uris: { via: inInv.via ? { user: '', host: inInv.via.host } : null, request: inInv.reqUri, to: inInv.to, from: inInv.from } };
    const sim = cfg && cfg.dialPeers.length ? matchInbound(cfg, ctx) : null;
    res.simInTag = sim ? (sim.winner ? sim.winner.tag : 0) : null;
    res.inTag = call.inDpDebug != null ? call.inDpDebug : res.simInTag;
    res.inbound = { ctx, sim, debugTag: call.inDpDebug, tag: res.inTag };
    inDp = res.inTag ? dialPeerByTag(cfg || emptyConfig(), res.inTag) : null;

    const evd = [ev(inInv)];
    const plusHit = cfg && /^\+/.test(call.called) && cfg.dialPeers.filter((d) => !d.shutdown && d.incomingCalled.length && !d.incomingCalled.some((p) => matchPattern(p, call.called).ok) && d.incomingCalled.some((p) => matchPattern(p, call.called.slice(1)).ok));
    const calledStepWon = sim && sim.winner && /^incoming (called|uri)/.test(sim.winner.step);
    if (plusHit && plusHit.length) {
      const dp = plusHit[0];
      const pat = dp.incomingCalled.find((p) => matchPattern(p, call.called.slice(1)).ok);
      const dp0 = res.inTag === 0;
      add(dp0 ? 'error' : 'warn', 'inbound-plus', dp0 ? `Inbound call fell to dial-peer 0 because of the "+" in the called number` : `"+E.164" called number cannot match dial-peer ${dp.tag} incoming called-number ${pat}`, `The INVITE Request-URI user is "${call.called}". Dial-peer ${dp.tag} (incoming called-number ${pat}) would match "${call.called.slice(1)}" but not "${call.called}": in a dial-peer pattern "+" is only a literal at the very start of the pattern, so ${pat} can never match a number that starts with "+".` + (dp0 ? ' The call used default dial-peer 0 (no dtmf-relay, all codecs, no translation profile).' : ` The call was instead matched by dial-peer ${res.inTag}${sim && sim.winner && !calledStepWon ? ' through ' + sim.winner.step : ''}, so dial-peer ${dp.tag} settings (translation-profile, codec, dtmf) are NOT applied to ITSP calls.`), {
        evidence: evd,
        pri: dp0 ? 15 : 36,
        fix: [`dial-peer voice ${dp.tag} voip`, ` incoming called-number +${pat}`, `! Cisco: a leading "+" in a pattern is a literal plus. Keep both forms if the ITSP can send either:`, `voice class e164-pattern-map 1`, ` e164 +${pat}`, ` e164 ${pat}`, `dial-peer voice ${dp.tag} voip`, ` incoming called e164-pattern-map 1`],
      });
    } else if (res.inTag === 0) {
      add('warn', 'inbound-dp0', 'No inbound dial-peer matched: default dial-peer 0 was used', `None of the dial-peers matched the incoming call (called "${call.called}", calling "${call.calling}"). Dial-peer 0 has no dtmf-relay, advertises all codecs and applies no translation profile, so behaviour is unpredictable. Cisco recommends an explicit inbound dial-peer per trunk (for example \`incoming uri via\` for the ITSP IP).`, {
        evidence: evd,
        pri: 35,
        fix: [`voice class uri ITSP sip`, ` host ipv4:${call.in.peerIp || '<ITSP-IP>'}`, `dial-peer voice <tag> voip`, ` incoming uri via ITSP`, ` session protocol sipv2`, ` voice-class codec <n>`, ` dtmf-relay rtp-nte`],
      });
    }
    if (sim && sim.winner && /^destination-pattern/.test(sim.winner.step) && res.inTag === sim.winner.tag) {
      add('warn', 'inbound-by-ani', `Inbound dial-peer ${res.inTag} was selected only because its destination-pattern matched the CALLING number`, `Nothing matched by incoming uri or incoming called-number, so CUBE fell back to Cisco's step 7: destination-pattern compared against the calling number (${sim.winner.via}, calling "${call.calling}"). This works by accident and will break when the calling number changes; add an explicit \`incoming uri via\` or \`incoming called-number\` dial-peer for this trunk.`, { evidence: evd, pri: 37 });
    }
    if (res.inTag != null && call.inDpDebug != null && res.simInTag != null && res.simInTag !== call.inDpDebug) {
      add('info', 'sim-mismatch-in', `Debug says inbound dial-peer ${call.inDpDebug}, config simulation says ${res.simInTag}`, `The router log is authoritative. The difference usually means the config pasted is not the config that was active at the time of the call, or a feature not simulated here (VRF/tenant filtering, voice class tenant) is in use.`, { pri: 60 });
    }

    // incoming translation (dial-peer profile, global profile)
    if (cfg) {
      const profName = (inDp && inDp.transIn) || cfg.globalIncomingProfile;
      let called = call.called;
      let calling = call.calling;
      const trC = profName ? applyProfile(cfg, profName, 'called', called) : null;
      const trG = profName ? applyProfile(cfg, profName, 'calling', calling) : null;
      if (trC && trC.missingProfile) add('error', 'profile-missing', `Translation profile "${profName}" is referenced but not defined`, `Dial-peer ${res.inTag} uses translation-profile incoming ${profName} but there is no \`voice translation-profile ${profName}\` in the pasted config.`, { pri: 20 });
      for (const [kind, t] of [['called', trC], ['calling', trG]]) {
        if (t && t.rejected) add('error', 'rule-reject', `Call blocked by translation rule (${kind})`, `Profile ${profName}, rule-set ${t.ruleId}, ${t.ruleRaw} rejected the ${kind} number.`, { pri: 12 });
        if (t && t.missing) add('error', 'ruleset-missing', `Translation rule ${t.ruleId} is missing`, `Profile ${profName} refers to voice translation-rule ${t.ruleId}, which is not in the config.`, { pri: 20 });
      }
      if (trC && trC.applied && !trC.rejected) called = trC.out;
      if (trG && trG.applied && !trG.rejected) calling = trG.out;
      calledAfterIn = called;
      callingAfterIn = calling;
      res.inbound.translation = { profile: profName || null, called: trC, calling: trG };
    }
  }

  // ------------------------------------------------------------ outbound leg
  if (cfg && cfg.dialPeers.length && (inInv || outInv)) {
    const ctx = { called: calledAfterIn, calling: callingAfterIn, inDp, uris: inInv ? { via: null, request: inInv.reqUri, to: inInv.to, from: inInv.from } : null };
    const sim = matchOutbound(cfg, ctx);
    res.simOutTag = sim.winner ? sim.winner.tag : null;
    let actual = call.outDpsDebug.length ? call.outDpsDebug[call.outDpsDebug.length - 1] : null;
    if (actual == null && outInv && outInv.reqUri) {
      const hostIp = outInv.reqUri.host;
      const byTarget = cfg.dialPeers.filter((d) => hostOfTarget(d.sessionTarget) === hostIp && sim.hunt.some((h) => h.tag === d.tag));
      actual = byTarget.length ? byTarget[0].tag : null;
      if (actual != null) res.outInferred = true;
    }
    res.outTag = actual != null ? actual : res.simOutTag;
    res.outbound = { ctx, sim, debugTags: call.outDpsDebug, tag: res.outTag };

    if (inInv && !outD && call.result === 'failed') {
      // CUBE never created an out-leg: failure is in routing
      if (!sim.winner) {
        const blocked = sim.tiers.flatMap((t) => t.blockedMatches || []);
        if (blocked.length) {
          add('error', 'out-blocked', 'The only matching outbound dial-peer(s) cannot be used', `Called number "${calledAfterIn}" matches ${blocked.map((b) => `dial-peer ${b.tag} (${b.via})`).join(', ')}, but ${blocked.map((b) => `dial-peer ${b.tag}: ${b.blocked}`).join('; ')}. No other dial-peer matches, so CUBE rejected the call.`, { pri: 25, evidence: call.in.final ? [ev(call.in.final)] : [], fix: ['Re-enable the dial-peer (`no shutdown`) or fix its session target / keepalive state, or add another matching dial-peer.'] });
        } else {
          add('error', 'out-nomatch', 'No outbound dial-peer matches the called number', `After incoming translation the called number is "${calledAfterIn}" (received "${call.called}"). No outbound dial-peer has a destination-pattern, destination e164-pattern-map or destination uri that matches it, so CUBE had nowhere to route the call and rejected it (${call.finalCode} ${call.finalReason}; typically Q.850 cause 1/3).`, { pri: 25, evidence: call.in.final ? [ev(call.in.final)] : [] });
        }
      }
    }
    if (sim.winner && sim.hunt.length > 1 && outD) {
      const wTag = sim.winner.tag;
      if (actual != null && actual !== wTag && call.outDpsDebug.length === 1) add('info', 'sim-mismatch-out', `Debug says outbound dial-peer ${actual}, simulation chose ${wTag}`, 'Config used for the simulation may differ from the config active at call time.', { pri: 60 });
    }
    if (call.outDpsDebug.length > 1) add('info', 'hunting', `Dial-peer hunting: ${call.outDpsDebug.length} outbound dial-peers were tried (${call.outDpsDebug.join(' > ')})`, 'The first dial-peer failed and CUBE hunted to the next one. A delay before ringback is expected. Use `huntstop` to disable this.', { pri: 70 });
    else if (call.outs.length > 1) add('info', 'hunting', `Dial-peer hunting: ${call.outs.length} outbound legs were created`, 'The first dial-peer failed and CUBE hunted to the next one.', { pri: 70 });

    // dp0-without-plus hairpin warning: .T catch-all sends back to the ITSP
    const outDp = res.outTag != null ? dialPeerByTag(cfg, res.outTag) : null;
    if (outDp && inInv && call.in && peerRole(call.in.peerIp, cfg, itsp) === 'ITSP' && peerRole(outInv ? outInv.reqUri.host : '', cfg, itsp) === 'ITSP') {
      add('error', 'hairpin', 'Call from the ITSP is being routed back to the ITSP (hairpin)', `Inbound leg arrived from ${call.in.peerIp} and the outbound dial-peer ${outDp.tag} (${outDp.destPattern}) sends it to ${hostOfTarget(outDp.sessionTarget)}, the same ITSP. The called number "${calledAfterIn}" was probably not translated to the internal extension, so only the catch-all matched.`, { pri: 18, fix: ['Fix the inbound match / incoming translation so the DID becomes the internal extension (see the number timeline).'] });
    }

    // outgoing translation + prediction
    if (outDp) {
      const profName = outDp.transOut;
      let c = calledAfterIn;
      let g = callingAfterIn;
      let trC = null;
      let trG = null;
      if (profName) {
        trC = applyProfile(cfg, profName, 'called', c);
        trG = applyProfile(cfg, profName, 'calling', g);
        if (trC.missingProfile) add('error', 'profile-missing', `Translation profile "${profName}" is referenced but not defined`, `Dial-peer ${outDp.tag} uses translation-profile outgoing ${profName}.`, { pri: 20 });
        if (trC.rejected || trG.rejected) add('error', 'rule-reject', 'Call blocked by outgoing translation rule', `Profile ${profName} rejected the number.`, { pri: 12 });
        if (trC.applied && !trC.rejected) c = trC.out;
        if (trG.applied && !trG.rejected) g = trG.out;
      }
      if (outDp.translateOutgoing && outDp.translateOutgoing.called) {
        const t = applyProfile({ ...cfg, profiles: { _t: { called: outDp.translateOutgoing.called } } }, '_t', 'called', c);
        if (t.applied) c = t.out;
      }
      if (outDp.translateOutgoing && outDp.translateOutgoing.calling) {
        const t = applyProfile({ ...cfg, profiles: { _t: { calling: outDp.translateOutgoing.calling } } }, '_t', 'calling', g);
        if (t.applied) g = t.out;
      }
      res.outbound.translation = { profile: profName || null, called: trC, calling: trG, predictedCalled: c, predictedCalling: g };
      if (outInv) {
        const ac = call.outCalled;
        const ag = call.outCalling;
        if (ac != null && c !== ac) add('info', 'predict-called', 'Called number on the out-leg differs from what the config predicts', `Config predicts "${c}" but INVITE was sent with "${ac}". The active configuration (or a SIP profile / num-exp) may differ from the pasted one.`, { pri: 65 });
        if (ag != null && ag !== '' && g !== ag) add('info', 'predict-calling', 'Calling number on the out-leg differs from what the config predicts', `Config predicts "${g}" but the INVITE carries "${ag}" (From/PAI).`, { pri: 65 });
      }
    }
    if (cfg.numExp && cfg.numExp.length) add('info', 'numexp', 'num-exp is configured', 'Number expansion is applied after outbound dial-peer matching and is not simulated by this tool.', { pri: 90 });
  }

  // ------------------------------------------------------------ timeline
  const tl = res.timeline;
  if (inInv) {
    tl.push({ stage: `Received on in-leg (${call.in.peerIp || '?'})`, called: call.called, calling: call.calling, note: `calling taken from ${call.callingSource}`, kind: 'actual' });
    if (res.inbound && res.inbound.translation && res.inbound.translation.profile) {
      const t = res.inbound.translation;
      tl.push({ stage: `After incoming translation (profile ${t.profile}, dp ${res.inTag})`, called: calledAfterIn, calling: callingAfterIn, note: [t.called && t.called.matched ? `called: rule-set ${t.called.ruleId} rule ${t.called.ruleSeq}` : 'called: no rule matched', t.calling && t.calling.matched ? `calling: rule-set ${t.calling.ruleId} rule ${t.calling.ruleSeq}` : 'calling: no rule matched'].join('; '), kind: 'sim' });
    }
  }
  if (res.outbound && res.outbound.translation) {
    const t = res.outbound.translation;
    if (t.profile || res.outbound.translation.predictedCalled !== calledAfterIn)
      tl.push({ stage: `After outgoing translation (dp ${res.outTag}${t.profile ? ', profile ' + t.profile : ''})`, called: t.predictedCalled, calling: t.predictedCalling, note: t.profile ? [t.called && t.called.matched ? `called: rule ${t.called.ruleId}/${t.called.ruleSeq}` : 'called: no rule matched', t.calling && t.calling.matched ? `calling: rule ${t.calling.ruleId}/${t.calling.ruleSeq}` : 'calling: no rule matched'].join('; ') : '', kind: 'sim' });
  }
  if (outInv) tl.push({ stage: `Sent on out-leg (${call.outs[0].peerIp || '?'})`, called: call.outCalled, calling: call.outCalling, note: 'from the INVITE actually sent', kind: 'actual' });

  // ------------------------------------------------------------ ITSP / E.164 checks
  const itspSide = (d) => d && peerRole(d.peerIp, cfg, itsp) === 'ITSP';
  const { assumed } = itspIps(cfg, itsp);
  const fmtCheck = (label, actual, req, msgm, pri, side) => {
    if (!req || req === 'any') return;
    const r = formatMatches(actual, req, cc);
    if (!r.ok && r.cls !== 'empty')
      add('error', 'itsp-format', `${label}: "${actual}" is not ${FORMATS[req].split(' (')[0]}`, `The ${label.toLowerCase()} is "${actual}" (${r.cls}). Your ITSP profile requires ${FORMATS[req]}${assumed ? ' (ITSP side inferred from sip-ua / `.T` dial-peer; set the ITSP IPs in the profile to be sure)' : ''}.`, { evidence: msgm ? [ev(msgm)] : [], pri, fix: formatFix(side, actual, r.cls, req, cc, cfg, res) });
  };
  if (itsp) {
    if (itspSide(inD)) {
      fmtCheck('Inbound called number (Request-URI)', call.called, itsp.inbound.called, inInv, 40, 'in');
      fmtCheck('Inbound calling number', call.calling, itsp.inbound.calling, inInv, 41, 'in');
      const r = inRanges(call.called, ranges, cc);
      if (r === false) add('error', 'did-range-in', `Inbound called number ${call.called} is outside your DID ranges`, `The ITSP delivered ${call.called}, which is not in the ranges you entered. Either the profile ranges are incomplete or the ITSP is routing wrong numbers to you.`, { evidence: [ev(inInv)], pri: 42 });
    }
    if (outD && itspSide(outD)) {
      fmtCheck('Outbound called number (Request-URI)', call.outCalled, itsp.outbound.called, outInv, 40, 'out');
      fmtCheck('Outbound calling number (From/PAI)', call.outCalling, itsp.outbound.calling, outInv, 41, 'out');
      if (itsp.callerInRange && call.outCalling) {
        const r = inRanges(call.outCalling, ranges, cc);
        if (r === false) add('error', 'did-range-out', `Outbound caller ID ${call.outCalling} is not one of your DIDs`, `ITSPs usually reject (403/404/603) or overwrite a caller ID that is not inside the range they gave you. "${call.outCalling}" is outside the ranges in your ITSP profile.`, { evidence: [ev(outInv)], pri: 43, fix: ['Translate the calling number to a DID in your range (outgoing translation-profile on the ITSP dial-peer).'] });
      }
    }
    if (!itspSide(inD) && !itspSide(outD) && (inD || outD)) need.push({ what: 'ITSP IP addresses in the profile', why: 'could not tell which leg faces the ITSP, so the +E.164 / range checks were skipped for this call' });
  }

  // ------------------------------------------------------------ SIP outcome
  const outcome = (d, label) => {
    if (!d || !d.final || d.final.code < 300) return;
    const f = d.final;
    const [name, helpText] = SIP_HELP[f.code] || [f.reason, ''];
    const role = peerRole(d.peerIp, cfg, itsp);
    const sentByCube = f.dir === 'sent';
    const reason = f.reasonHdr ? ` Reason: ${f.reasonHdr}.` : '';
    const q = /cause=(\d+)/.exec(f.reasonHdr || '');
    const qTxt = q && Q850[+q[1]] ? ` (Q.850 ${q[1]}: ${Q850[+q[1]]})` : '';
    const warn = f.warning ? ` Warning: ${f.warning}.` : '';
    const who = sentByCube ? `CUBE itself sent ${f.code} ${f.reason} to the ${label} (${role} ${d.peerIp})` : `The ${role} ${d.peerIp} rejected the ${label} with ${f.code} ${f.reason}`;
    const loc = sentByCube && label === 'in-leg' && !call.outs.length ? ' No out-leg was created, so the failure is in CUBE routing/config, not in the next hop.' : sentByCube && call.outs.length ? ' CUBE relayed the failure from the out-leg.' : '';
    add(f.code === 487 ? 'info' : 'error', `sip-${label}-${f.code}`, `${who}`, `${name}: ${helpText}${reason}${qTxt}${warn}${loc}`, { evidence: [ev(f)], pri: 30 });
    if (f.code === 488) codecCheck(d);
    if (f.code === 503 && call.syslog.some((s) => s.type === 'maxconn')) add('error', 'maxconn', 'Rejected by CUBE CAC (max-conn)', call.syslog.find((s) => s.type === 'maxconn').raw, { pri: 28, fix: ['Raise `max-conn` on the dial-peer or investigate stuck calls (`show call active voice brief`).'] });
  };
  outcome(inD, 'in-leg');
  call.outs.forEach((o, i) => outcome(o, call.outs.length > 1 ? `out-leg ${i + 1}` : 'out-leg'));

  // retransmissions / no response
  call.outs.forEach((o) => {
    const respCount = o.msgs.filter((m) => m.kind === 'resp').length;
    if (o.inviteTransmissions.length > 1 && !respCount)
      add('error', 'no-response', `No response from ${o.peerIp} to ${o.inviteTransmissions.length} INVITE transmissions`, 'CUBE retransmitted the INVITE and nothing came back. Check IP reachability/routing, ACL/firewall (UDP/TCP 5060), the dial-peer session target, `sip-ua retry invite` / timers and that the far end is alive (OPTIONS keepalive).', { evidence: o.inviteTransmissions.map(ev), pri: 29 });
  });
  if (inD && inD.inviteTransmissions.length > 1 && !inD.msgs.some((m) => m.dir === 'sent' && m.kind === 'resp'))
    add('error', 'cube-silent', `CUBE did not answer ${inD.inviteTransmissions.length} INVITE retransmissions from ${inD.peerIp}`, 'CUBE received the INVITE repeatedly but never sent a response. Typical causes: source not in the trusted list (toll-fraud protection drops it), no `allow-connections sip to sip`, SIP binding/ACL, or the SIP process busy.', { evidence: inD.inviteTransmissions.map(ev), pri: 11 });
  if (call.result === 'no-final' && inD && !inD.msgs.some((m) => m.dir === 'sent' && m.kind === 'resp') && inD.inviteTransmissions.length === 1)
    add('warn', 'cube-silent', 'CUBE received the INVITE but sent no response', 'No 100 Trying / final response from CUBE in the capture. Check trusted list, allow-connections and `show ip access-lists` / ZBFW on the interface.', { evidence: [ev(inInv)], pri: 12 });

  // trusted list / allow-connections
  if (cfg && !cfg.empty && inD) {
    const trusted = cfg.voiceService.trustedIps || [];
    const ip = inD.peerIp;
    const implicit = cfg.dialPeers.some((d) => hostOfTarget(d.sessionTarget) === ip);
    if (trusted.length && ip && !trusted.includes(ip) && !implicit) {
      const rejected = call.result === 'failed' || call.result === 'no-final';
      add(rejected ? 'error' : 'warn', 'untrusted', `Source ${ip} is not in the voice service trusted list`, `\`ip address trusted list\` is configured and ${ip} is neither in it nor the session target of any dial-peer. IOS-XE toll-fraud protection rejects or silently drops SIP calls from untrusted sources (see %VOICE_IEC "Toll fraud call rejected").`, { evidence: [ev(inInv)], pri: 10, fix: ['voice service voip', ` ip address trusted list`, `  ipv4 ${ip}`] });
    }
    const allow = cfg.voiceService.allow || [];
    if (cfg.voiceService.lines && cfg.voiceService.lines.length && !allow.some((a) => a === 'sip to sip') && call.outs.length + (inD ? 1 : 0) > 1)
      add('error', 'no-allow-sip', '`allow-connections sip to sip` is missing', 'CUBE cannot interconnect two SIP legs without it.', { pri: 9, fix: ['voice service voip', ' allow-connections sip to sip'] });
  }

  // syslog IEC
  call.syslog.filter((s) => s.type === 'iec').forEach((s) => add(/reject|fail|deny|block/i.test(s.text) ? 'error' : 'warn', 'iec', `IEC ${s.iec}: ${s.text}`, `${s.layer} internal error code from \`voice iec syslog\`: ${s.raw}`, { pri: 22 }));

  // CCAPI cause
  if (call.causeDebug != null && call.result !== 'answered') {
    const t = Q850[call.causeDebug];
    if (call.causeDebug === 188) add('error', 'busyout', 'Dial-peer is in busyout (cause 188)', 'A dial-peer selected for the call is in busyout state because its keepalive (OPTIONS) failed.', { pri: 24, fix: ['Check `show dial-peer voice summary` KEEPALIVE column and the far end OPTIONS responses.'] });
    else if (call.causeDebug !== 16 && call.causeDebug !== 31) add('info', 'cause', `CCAPI disconnect cause ${call.causeDebug}${t ? ': ' + t : ''}`, 'Reported by cc_api_call_disconnected.', { pri: 55 });
  }

  // ------------------------------------------------------------ media: codec / dtmf
  function codecCheck(d) {
    if (!d || !d.offer || !cfg) return;
    const tag = d.dir === 'in' ? res.inTag : res.outTag;
    const dp = tag ? dialPeerByTag(cfg, tag) : null;
    const allowed = dpCodecs(cfg, dp);
    if (!allowed) return;
    const offered = d.offer.codecs.map((c) => c.name);
    const ok = offered.some((n) => ciscoCodecsFor(n).some((k) => allowed.some((a) => a.startsWith(k.slice(0, 4)) && (a === k || k.startsWith(a) || a.startsWith(k)))));
    if (!ok) add('error', 'codec', `No common codec on ${d.dir === 'in' ? 'in-leg' : 'out-leg'} (dial-peer ${tag})`, `SDP offers ${offered.join(', ') || 'none'} but dial-peer ${tag} allows only ${allowed.join(', ')}. This produces 488 Not Acceptable Here.`, { evidence: [ev(d.invite)], pri: 33, fix: [`voice class codec <n>`, ` codec preference 1 <one of: ${offered.map((n) => ciscoCodecsFor(n)[0]).filter(Boolean).join(', ')}>`, `! or enable transcoding / use \`codec transparent\``] });
  }
  if (inD && inD.final && inD.final.code === 488) codecCheck(inD);
  if (inD && inD.offer && cfg) {
    const dp = res.inTag ? dialPeerByTag(cfg, res.inTag) : null;
    if (dp && dp.dtmf && /rtp-nte/.test(dp.dtmf) && !inD.offer.dtmf) add('warn', 'dtmf', 'Caller did not offer RFC2833 telephone-event but the dial-peer expects rtp-nte', `Dial-peer ${dp.tag} has dtmf-relay ${dp.dtmf} and the SDP offer has no telephone-event. DTMF may need in-band or SIP-INFO/KPML. Check the far end config.`, { evidence: [ev(inInv)], pri: 60 });
    if (dp && dp.nte && inD.offer.dtmfPt && String(dp.nte) !== String(inD.offer.dtmfPt))
      add('info', 'dtmf-pt', `telephone-event payload type differs (offer ${inD.offer.dtmfPt}, dial-peer rtp payload-type nte ${dp.nte})`, 'CUBE normally interworks this, but check `asymmetric payload dtmf` if DTMF fails.', { pri: 80 });
  }

  // show dialplan cross-check
  if (env.dialplan && env.dialplan.matches && env.dialplan.matches.length && res.outbound) {
    const dpl = env.dialplan.matches[0].tag;
    if (env.dialplan.number && (env.dialplan.number === calledAfterIn || env.dialplan.number === call.called) && res.simOutTag != null && dpl !== res.simOutTag)
      add('info', 'dialplan-diff', `show dialplan number ${env.dialplan.number} chose dial-peer ${dpl}; simulation chose ${res.simOutTag}`, 'Trust the router. Pattern edge cases (T, %, ranges) may differ from the simulation.', { pri: 60 });
  }

  // cause summary for unfinished
  if (call.result === 'answered' && !findings.some((f) => f.sev === 'error')) add('ok', 'answered', 'Call was answered and no configuration problem was detected', 'Check the number timeline to confirm the numbers were normalised as intended.', { pri: 99 });
  if (call.result === 'cancelled' && !findings.length) add('info', 'cancelled', 'Call was cancelled before it was answered', 'The caller hung up (CANCEL / 487). Not a configuration failure by itself.', { pri: 80 });

  findings.sort((a, b) => ({ error: 0, warn: 1, info: 2, ok: 3 }[a.sev] - { error: 0, warn: 1, info: 2, ok: 3 }[b.sev] || a.pri - b.pri));
  res.root = findings.find((f) => f.sev === 'error') || findings.find((f) => f.sev === 'warn') || null;
  return res;
}

function formatFix(side, actual, cls, req, cc, cfg, res) {
  const dpTag = side === 'out' ? res.outTag : res.inTag;
  const kind = side === 'out' ? 'translation-profile outgoing' : 'translation-profile incoming';
  const lines = [];
  if (req === 'e164plus') {
    if (cls === 'national') lines.push(`voice translation-rule <n>`, ` rule 1 /^0\\(.*\\)/ /+${cc || '<cc>'}\\1/`);
    else if (cls === 'e164') lines.push(`voice translation-rule <n>`, ` rule 1 /^\\(${cc || '<cc>'}.*\\)/ /+\\1/`);
    else if (cls === 'intl00') lines.push(`voice translation-rule <n>`, ` rule 1 /^00\\(.*\\)/ /+\\1/`);
    else if (cls === 'short') lines.push(`voice translation-rule <n>`, ` rule 1 /^\\(....\\)$/ /+${cc || '<cc>'}<area+DID prefix>\\1/   ! map extension to the full DID`);
    else lines.push(`voice translation-rule <n>`, ` rule 1 /^\\(.*\\)/ /+\\1/   ! adjust to your numbering`);
  } else if (req === 'e164') lines.push(`voice translation-rule <n>`, ` rule 1 /^+\\(.*\\)/ /\\1/`);
  else if (req === 'national') lines.push(`voice translation-rule <n>`, ` rule 1 /^+${cc || '<cc>'}\\(.*\\)/ /0\\1/`);
  if (lines.length && dpTag != null) lines.push(`voice translation-profile <PROFILE>`, ` translate called <n>   ! use "calling" for the From/PAI number`, `dial-peer voice ${dpTag} voip`, ` ${kind} <PROFILE>`);
  return lines;
}

