// Correlation: SIP dialogs -> CUBE calls (in-leg + out-leg(s)), attach CCAPI / IEC events.

const num = (u) => (u ? u.user || '' : '');

function buildDialog(callId, msgs) {
  const sorted = msgs.slice().sort((a, b) => a.ts - b.ts || a.lineNo - b.lineNo);
  const inv = sorted.find((m) => m.kind === 'req' && m.method === 'INVITE');
  const sentIds = sorted.filter((m) => m.ccId != null && m.ccId >= 0);
  const withGuid = sorted.find((m) => m.guid);
  return {
    callId,
    msgs: sorted,
    invite: inv || null,
    dir: inv ? (inv.dir === 'recv' ? 'in' : 'out') : 'unknown',
    ccId: sentIds.length ? sentIds[0].ccId : null,
    guid: withGuid ? withGuid.guid : null,
    start: sorted[0].ts,
  };
}

function finalInviteResponse(d) {
  // responses to INVITE (final >=200), ignoring those for other methods
  const finals = d.msgs.filter((m) => m.kind === 'resp' && m.cseq.method === 'INVITE' && m.code >= 200);
  return finals.length ? finals[finals.length - 1] : null;
}

function summarizeDialog(d) {
  const resps = d.msgs.filter((m) => m.kind === 'resp' && m.cseq.method === 'INVITE');
  d.final = finalInviteResponse(d);
  d.provisional = resps.filter((m) => m.code < 200);
  d.answered = resps.some((m) => m.code >= 200 && m.code < 300);
  d.has180 = resps.some((m) => m.code === 180 || m.code === 183);
  d.cancel = d.msgs.find((m) => m.kind === 'req' && m.method === 'CANCEL') || null;
  d.bye = d.msgs.find((m) => m.kind === 'req' && m.method === 'BYE') || null;
  d.inviteTransmissions = d.msgs.filter((m) => m.kind === 'req' && m.method === 'INVITE' && m.cseq.num === (d.invite ? d.invite.cseq.num : 0));
  d.peerIp = d.invite
    ? d.dir === 'in'
      ? (d.invite.via && d.invite.via.host) || (d.invite.contact && d.invite.contact.host) || ''
      : (d.invite.reqUri && d.invite.reqUri.host) || ''
    : '';
  d.offer = d.invite && d.invite.sdp ? d.invite.sdp : null;
  return d;
}

export function buildCalls(sipMsgs, ccapiEvents = [], syslogEvents = [], voipTrace = []) {
  const byCallId = new Map();
  const keep = new Map();
  for (const m of sipMsgs) {
    if (!m.callId) continue;
    (byCallId.get(m.callId) || byCallId.set(m.callId, []).get(m.callId)).push(m);
  }
  const dialogs = [];
  for (const [cid, msgs] of byCallId) {
    const isInvite = msgs.some((m) => (m.kind === 'req' && m.method === 'INVITE') || (m.kind === 'resp' && m.cseq.method === 'INVITE'));
    if (isInvite) dialogs.push(summarizeDialog(buildDialog(cid, msgs)));
    else {
      const first = msgs.find((m) => m.kind === 'req');
      const method = first ? first.method : msgs[0].cseq.method;
      const peer = first ? (first.dir === 'recv' ? (first.via && first.via.host) || '' : (first.reqUri && first.reqUri.host) || '') : '';
      const key = `${method}|${peer}`;
      const k = keep.get(key) || { method, peer, total: 0, ok: 0, failed: [], firstTs: msgs[0].tsText, lastTs: msgs[msgs.length - 1].tsText, direction: first ? (first.dir === 'recv' ? 'received' : 'sent') : '?' };
      k.total++;
      const resp = msgs.find((m) => m.kind === 'resp' && m.code >= 200);
      if (resp && resp.code < 300) k.ok++;
      else k.failed.push({ ts: msgs[0].tsText, code: resp ? resp.code : 'no response', reason: resp ? resp.reason : '' });
      k.lastTs = msgs[msgs.length - 1].tsText;
      keep.set(key, k);
    }
  }
  dialogs.sort((a, b) => a.start - b.start);

  // ---- group dialogs into calls ----
  const groups = [];
  const byGuid = new Map();
  const leftoverOut = [];
  for (const d of dialogs) {
    if (d.guid && byGuid.has(d.guid)) {
      byGuid.get(d.guid).dialogs.push(d);
      continue;
    }
    if (d.guid) {
      const g = { dialogs: [d], guid: d.guid };
      byGuid.set(d.guid, g);
      groups.push(g);
    } else if (d.dir === 'out') leftoverOut.push(d);
    else groups.push({ dialogs: [d], guid: null });
  }
  // voip trace peer mapping
  const traceByCid = new Map(voipTrace.map((t) => [t.sipCallId, t]));
  for (const d of leftoverOut) {
    const t = traceByCid.get(d.callId);
    let g = t && t.guid ? byGuid.get(t.guid) : null;
    if (!g) {
      g = groups
        .filter((x) => x.dialogs[0].dir === 'in' && x.dialogs[0].start <= d.start && d.start - x.dialogs[0].start < 15000)
        .filter((x) => d.ccId == null || x.dialogs[0].ccId == null || (d.ccId > x.dialogs[0].ccId && d.ccId - x.dialogs[0].ccId <= 6))
        .sort((a, b) => b.dialogs[0].start - a.dialogs[0].start)[0];
      if (g) g.inferred = true;
    }
    if (g) g.dialogs.push(d);
    else groups.push({ dialogs: [d], guid: null });
  }

  const calls = groups.map((g, i) => {
    const ds = g.dialogs.slice().sort((a, b) => a.start - b.start);
    const inD = ds.find((d) => d.dir === 'in') || null;
    const outs = ds.filter((d) => d.dir === 'out');
    const inv = (inD && inD.invite) || (outs[0] && outs[0].invite);
    const outInv = outs[0] && outs[0].invite;
    const call = {
      id: 'call-' + (i + 1),
      guid: g.guid,
      inferred: !!g.inferred,
      in: inD,
      outs,
      start: ds[0].start,
      startText: ds[0].msgs[0].tsText,
      ccapi: [],
      syslog: [],
      msgs: ds.flatMap((d) => d.msgs).sort((a, b) => a.ts - b.ts || a.lineNo - b.lineNo),
    };
    call.called = inv ? num(inv.reqUri) || num(inv.to) : '';
    call.calling = inv ? num(inv.pai) || num(inv.rpid) || num(inv.from) : '';
    call.callingSource = inv ? (num(inv.pai) ? 'P-Asserted-Identity' : num(inv.rpid) ? 'Remote-Party-ID' : 'From') : '';
    call.outCalled = outInv ? num(outInv.reqUri) || num(outInv.to) : null;
    call.outCalling = outInv ? num(outInv.pai) || num(outInv.rpid) || num(outInv.from) : null;
    call.direction = inD ? 'in' : 'out';
    return call;
  });

  // ---- result classification ----
  for (const c of calls) {
    const lead = c.in || c.outs[0];
    const answered = c.in ? c.in.answered : c.outs.some((o) => o.answered);
    const inFinal = c.in && c.in.final;
    const outFinals = c.outs.map((o) => o.final).filter(Boolean);
    const lastOut = outFinals[outFinals.length - 1];
    c.finalCode = answered ? 200 : (inFinal || lastOut || {}).code || null;
    c.finalReason = answered ? 'OK' : (inFinal || lastOut || {}).reason || '';
    const canceled = c.msgs.some((m) => m.kind === 'req' && m.method === 'CANCEL') || c.finalCode === 487;
    c.result = answered ? 'answered' : canceled ? 'cancelled' : c.finalCode ? 'failed' : lead && lead.has180 ? 'ringing' : 'no-final';
    if (answered) {
      const bye = c.msgs.find((m) => m.kind === 'req' && m.method === 'BYE');
      c.endedBy = bye ? (bye.dir === 'recv' ? (c.in && c.in.msgs.includes(bye) ? 'caller (in-leg)' : 'called party (out-leg)') : (c.in && c.in.msgs.includes(bye) ? 'CUBE (towards in-leg)' : 'CUBE (towards out-leg)')) : '';
    }
  }

  // ---- attach CCAPI events ----
  const findByCcId = (id) => (id == null || id < 0 ? null : calls.find((c) => [c.in, ...c.outs].some((d) => d && d.ccId === id)));
  const findByGuid = (guid) => (guid ? calls.find((c) => c.guid === guid) : null);
  const winOf = (ev) =>
    calls
      .filter((c) => c.in && ev.ts >= c.in.start - 1500 && ev.ts <= c.in.start + 4000)
      .sort((a, b) => Math.abs(ev.ts - a.in.start) - Math.abs(ev.ts - b.in.start))[0] ||
    calls
      .filter((c) => ev.ts >= c.start - 1500 && ev.ts <= c.start + 4000)
      .sort((a, b) => Math.abs(ev.ts - a.start) - Math.abs(ev.ts - b.start))[0];
  const orphanCcapi = [];
  for (const ev of ccapiEvents) {
    const c = findByGuid(ev.guid) || findByCcId(ev.callId > 0 ? ev.callId : ev.bodyCallId) || winOf(ev);
    if (c) c.ccapi.push(ev);
    else orphanCcapi.push(ev);
  }
  for (const ev of syslogEvents) {
    const c = (ev.guid && findByGuid(ev.guid)) || findByCcId(ev.callId) || winOf(ev);
    if (c) c.syslog.push(ev);
  }
  for (const c of calls) {
    c.ccapi.sort((a, b) => a.ts - b.ts || a.lineNo - b.lineNo);
    const withIn = c.ccapi.find((e) => e.inDp != null);
    c.inDpDebug = withIn ? withIn.inDp : null;
    const outs = [];
    for (const e of c.ccapi) if (e.outDp != null && !outs.includes(e.outDp)) outs.push(e.outDp);
    c.outDpsDebug = outs;
    const cause = c.ccapi.filter((e) => e.cause != null);
    c.causeDebug = cause.length ? cause[cause.length - 1].cause : null;
    const s = c.ccapi.find((e) => e.called != null && /setup/i.test(e.func));
    c.ccapiCalled = s ? s.called : null;
    c.ccapiCalling = s ? s.calling : null;
  }
  return { calls, keepalives: [...keep.values()], dialogs, orphanCcapi };
}
