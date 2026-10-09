// Parser for `show running-config` (voice-relevant sections) + secret stripping.

/** Remove credentials / certificates from pasted config text. */
export function stripSecrets(text) {
  const out = [];
  let inCert = false;
  for (const line of String(text || '').replace(/^\uFEFF/, '').split(/\r?\n/)) {
    if (/^crypto pki certificate chain/.test(line)) {
      inCert = true;
      out.push(line + ' <removed>');
      continue;
    }
    if (inCert) {
      if (/^\S/.test(line) && !/^\s/.test(line)) inCert = false;
      else continue;
    }
    out.push(
      line
        .replace(/((?:enable )?secret (?:\d )?)\S+/i, '$1<removed>')
        .replace(/(password (?:\d )?)\S+/i, '$1<removed>')
        .replace(/(key(?:-string)? (?:\d )?)\S{8,}/i, '$1<removed>')
        .replace(/(community )\S+/i, '$1<removed>'),
    );
  }
  return out.join('\n');
}

/** Split config into top-level stanzas {head, lines[]} (indented lines belong to the preceding head). */
export function splitStanzas(text) {
  const stanzas = [];
  let cur = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, '');
    if (!line.trim() || /^\s*!/.test(line)) {
      if (!/^\s/.test(line)) cur = null;
      continue;
    }
    if (/^\s/.test(line)) {
      if (cur) cur.lines.push(line.trim());
    } else {
      cur = { head: line.trim(), lines: [] };
      stanzas.push(cur);
    }
  }
  return stanzas;
}

const first = (lines, re) => {
  for (const l of lines) {
    const m = re.exec(l);
    if (m) return m;
  }
  return null;
};

function parseDialPeer(st) {
  const hm = /^dial-peer voice (\d+) (\w+)/.exec(st.head);
  const L = st.lines;
  const dp = {
    tag: +hm[1],
    type: hm[2],
    shutdown: L.includes('shutdown'),
    description: (first(L, /^description (.*)$/) || [])[1] || '',
    destPattern: (first(L, /^destination-pattern (\S+)/) || [])[1] || null,
    incomingCalled: [],
    answerAddress: (first(L, /^answer-address (\S+)/) || [])[1] || null,
    incomingUri: {},
    incomingCalledMap: (first(L, /^incoming called e164-pattern-map (\d+)/) || [])[1] || null,
    incomingCallingMap: (first(L, /^incoming calling e164-pattern-map (\d+)/) || [])[1] || null,
    destUri: (first(L, /^destination uri (\S+)/) || [])[1] || null,
    destMap: (first(L, /^destination e164-pattern-map (\d+)/) || [])[1] || null,
    destDpg: (first(L, /^destination dpg (\d+)/) || [])[1] || null,
    preference: +((first(L, /^preference (\d+)/) || [])[1] || 0),
    huntstop: L.includes('huntstop'),
    sessionTarget: (first(L, /^session target (.*)$/) || [])[1] || null,
    sessionProtocol: (first(L, /^session protocol (\S+)/) || [])[1] || null,
    transIn: (first(L, /^translation-profile incoming (\S+)/) || [])[1] || null,
    transOut: (first(L, /^translation-profile outgoing (\S+)/) || [])[1] || null,
    translateOutgoing: {},
    codecClass: (first(L, /^voice-class codec (\d+)/) || [])[1] || null,
    codec: (first(L, /^codec (\S+)/) || [])[1] || null,
    dtmf: (first(L, /^dtmf-relay (.*)$/) || [])[1] || null,
    nte: (first(L, /^rtp payload-type nte (\d+)/) || [])[1] || null,
    earlyOffer: /voice-class sip early-offer forced/.test(L.join('\n')),
    numberingType: (first(L, /^numbering-type (\S+)/) || [])[1] || null,
    maxConn: (first(L, /^max-conn (\d+)/) || [])[1] || null,
    tenant: (first(L, /^voice-class sip tenant (\d+)/) || [])[1] || null,
    directInwardDial: !L.includes('no direct-inward-dial'),
    lines: L,
  };
  for (const l of L) {
    let m;
    if ((m = /^incoming called-number (\S+)/.exec(l))) dp.incomingCalled.push(m[1]);
    if ((m = /^incoming uri (via|request|to|from) (\S+)/.exec(l))) dp.incomingUri[m[1]] = m[2];
    if ((m = /^translate-outgoing (called|calling) (\d+)/.exec(l))) dp.translateOutgoing[m[1]] = m[2];
  }
  return dp;
}

function parseRuleLine(l) {
  const m = /^rule (\d+)\s+(reject\s+)?(.*)$/.exec(l);
  if (!m) return null;
  const rest = m[3];
  const d = rest[0];
  if (!d) return null;
  const esc = d.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const pm = new RegExp(`^${esc}((?:(?!${esc}).)*)${esc}(?:\\s*${esc}((?:(?!${esc}).)*)${esc})?`).exec(rest);
  if (!pm) return null;
  return { seq: +m[1], reject: !!m[2], match: pm[1], replace: pm[2] ?? null, raw: l };
}

export function parseConfig(text) {
  const clean = stripSecrets(text);
  const stanzas = splitStanzas(clean);
  const cfg = {
    hostname: '',
    version: '',
    dialPeers: [],
    rules: {},
    profiles: {},
    codecClasses: {},
    uriClasses: {},
    patternMaps: {},
    dpgs: {},
    trunkGroups: {},
    sipUa: { servers: [], lines: [] },
    voiceService: { trustedIps: [], allow: [], sipLines: [], trustedAuthenticate: false, lines: [] },
    interfaces: [],
    huntScheme: 0,
    numExp: [],
    globalIncomingProfile: null,
    tenants: {},
    clean,
  };
  for (const st of stanzas) {
    let m;
    if ((m = /^hostname (\S+)/.exec(st.head))) cfg.hostname = m[1];
    else if ((m = /^version (\S+)/.exec(st.head))) cfg.version = m[1];
    else if (/^dial-peer voice \d+ \w+/.test(st.head)) cfg.dialPeers.push(parseDialPeer(st));
    else if ((m = /^dial-peer hunt (\d)/.exec(st.head))) cfg.huntScheme = +m[1];
    else if ((m = /^voice translation-rule (\d+)/.exec(st.head))) {
      cfg.rules[m[1]] = st.lines.map(parseRuleLine).filter(Boolean).sort((a, b) => a.seq - b.seq);
    } else if ((m = /^voice translation-profile (\S+)/.exec(st.head))) {
      const p = { name: m[1], called: null, calling: null, redirectCalled: null, redirectTarget: null, callBlock: null };
      for (const l of st.lines) {
        let t;
        if ((t = /^translate (called|calling|redirect-called|redirect-target) (\d+)/.exec(l))) {
          const key = t[1].replace(/-(\w)/g, (_, c) => c.toUpperCase());
          p[key] = t[2];
        }
      }
      cfg.profiles[m[1]] = p;
    } else if ((m = /^voice class codec (\d+)/.exec(st.head))) {
      cfg.codecClasses[m[1]] = st.lines
        .map((l) => /^codec preference (\d+) (\S+)/.exec(l))
        .filter(Boolean)
        .sort((a, b) => +a[1] - +b[1])
        .map((x) => x[2]);
    } else if ((m = /^voice class uri (\S+) (\w+)/.exec(st.head))) {
      const u = { name: m[1], type: m[2], hosts: [], user: null, pattern: null };
      for (const l of st.lines) {
        let t;
        if ((t = /^host (\S+)/.exec(l))) u.hosts.push(t[1]);
        else if ((t = /^user-id (\S+)/.exec(l))) u.user = t[1];
        else if ((t = /^pattern (\S+)/.exec(l))) u.pattern = t[1];
      }
      cfg.uriClasses[m[1]] = u;
    } else if ((m = /^voice class e164-pattern-map (\d+)/.exec(st.head))) {
      cfg.patternMaps[m[1]] = st.lines.map((l) => /^e164 (\S+)/.exec(l)).filter(Boolean).map((x) => x[1]);
    } else if ((m = /^voice class dpg (\d+)/.exec(st.head))) {
      cfg.dpgs[m[1]] = st.lines.map((l) => /^dial-peer (\d+)(?: preference (\d+))?/.exec(l)).filter(Boolean).map((x) => ({ tag: +x[1], pref: +(x[2] || 0) }));
    } else if ((m = /^trunk group (\S+)/.exec(st.head))) {
      cfg.trunkGroups[m[1]] = {
        transIn: (first(st.lines, /^translation-profile incoming (\S+)/) || [])[1] || null,
        transOut: (first(st.lines, /^translation-profile outgoing (\S+)/) || [])[1] || null,
      };
    } else if (/^sip-ua/.test(st.head)) {
      cfg.sipUa.lines = st.lines;
      for (const l of st.lines) {
        const t = /^sip-server (\S+)/.exec(l);
        if (t) cfg.sipUa.servers.push(t[1]);
      }
    } else if (/^voice service voip/.test(st.head)) {
      cfg.voiceService.lines = st.lines;
      let inTrusted = false;
      let inSip = false;
      for (const l of st.lines) {
        let t;
        if (/^ip address trusted list/.test(l)) inTrusted = true;
        else if ((t = /^ipv4 (\S+)/.exec(l)) && inTrusted) cfg.voiceService.trustedIps.push(t[1]);
        else if ((t = /^allow-connections (\S+) to (\S+)/.exec(l))) cfg.voiceService.allow.push(`${t[1]} to ${t[2]}`);
        else if (/^no ip address trusted authenticate/.test(l)) cfg.voiceService.trustedAuthenticate = false;
        else if (/^sip$/.test(l)) {
          inSip = true;
          inTrusted = false;
        } else if (inSip) cfg.voiceService.sipLines.push(l);
        else if (!/^ipv4/.test(l)) inTrusted = false;
      }
    } else if ((m = /^voice class tenant (\d+)/.exec(st.head))) {
      cfg.tenants[m[1]] = st.lines;
    } else if ((m = /^interface (\S+)/.exec(st.head))) {
      cfg.interfaces.push({
        name: m[1],
        ip: (first(st.lines, /^ip address (\S+) (\S+)/) || [])[1] || null,
        description: (first(st.lines, /^description (.*)$/) || [])[1] || '',
        shutdown: st.lines.includes('shutdown'),
      });
    } else if ((m = /^num-exp (\S+) (\S+)/.exec(st.head))) {
      cfg.numExp.push({ pattern: m[1], expansion: m[2] });
    } else if ((m = /^voice translation-profile (\S+)/.exec(st.head))) {
      /* handled above */
    } else if ((m = /^voip-incoming translation-profile (\S+)/.exec(st.head))) {
      cfg.globalIncomingProfile = m[1];
    }
  }
  return cfg;
}

export const dialPeerByTag = (cfg, tag) => cfg.dialPeers.find((d) => d.tag === +tag);
