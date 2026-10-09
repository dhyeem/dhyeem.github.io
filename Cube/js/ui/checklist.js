// "What I need from you" checklist: instructions, copy-paste commands and live input validation.

export const PREP_COMMANDS = `configure terminal
 service timestamps debug datetime msec localtime show-timezone year
 service timestamps log datetime msec localtime show-timezone year
 service sequence-numbers
 logging buffered 10000000
 no logging console
 no logging monitor
 logging queue-limit 10000
 logging rate-limit 10000
 voice iec syslog
end
debug ccsip messages
debug ccsip error
debug voip ccapi inout
clear logging`;

export const COLLECT_COMMANDS = `! make ONE failing test call now, then:
undebug all
terminal length 0
show logging
! (optional, on a busy router) show log | redirect flash:calldebug.txt`;

export const CONFIG_COMMANDS = `terminal length 0
show running-config
! optional but useful:
show dial-peer voice summary
show dialplan number <called-number-as-CUBE-sees-it>
show voip trace cover-buffers`;

/** Cheap, regex-only inspection of the pasted debug text (runs on every input). */
export function inspectDebug(text) {
  const t = text || '';
  if (!t.trim()) return { state: 'missing', msg: 'Nothing pasted yet.', notes: [] };
  const count = (re) => (t.match(re) || []).length;
  const sipMsgs = count(/ccsipDisplayMsg:/g);
  const invites = count(/^(?:.*§)?\s*INVITE sip:/gm);
  const ccapi = count(/\/CCAPI\/|\/DPM\//g);
  const ms = /\d\d:\d\d:\d\d\.\d{3}/.test(t);
  const seq = /^\s*\d{4,}: /m.test(t);
  const notes = [];
  let state = 'ok';
  if (!sipMsgs) {
    state = 'warn';
    notes.push('No SIP messages found: enable `debug ccsip messages` and paste the output of `show logging`.');
  } else if (!invites) {
    state = 'warn';
    notes.push(`Found ${sipMsgs} SIP messages but no INVITE (only keepalives/OPTIONS?). Reproduce the call while the debugs are on, then capture again.`);
  }
  if (!ccapi) {
    state = state === 'ok' ? 'warn' : state;
    notes.push('No CCAPI lines: enable `debug voip ccapi inout` so the router tells us the incoming/outgoing dial-peer it actually used. (Analysis still runs, but dial-peers are only simulated.)');
  }
  if (!ms) notes.push('Timestamps have no milliseconds: add `service timestamps debug datetime msec`.');
  if (!seq) notes.push('No sequence numbers (optional): `service sequence-numbers` helps spot dropped log lines.');
  const msg = `${sipMsgs} SIP messages, ${invites} INVITE, ${ccapi} CCAPI lines`;
  return { state, msg, notes, stats: { sipMsgs, invites, ccapi } };
}

export function inspectConfig(text) {
  const t = text || '';
  if (!t.trim()) return { state: 'missing', msg: 'Nothing pasted yet.', notes: [] };
  const dps = (t.match(/^dial-peer voice \d+/gm) || []).length;
  const notes = [];
  let state = 'ok';
  if (!dps) {
    state = 'warn';
    notes.push('No `dial-peer voice` found: paste the whole `show running-config` (or at least dial-peers, voice translation-rule/profile, voice class, sip-ua, voice service voip).');
  }
  if (!/^voice translation-(rule|profile)/m.test(t)) notes.push('No translation rules/profiles in this config (fine if you do not use them).');
  if (/secret|password|crypto pki certificate/i.test(t)) notes.push('Credentials/certificates detected: they are removed locally before parsing and are never uploaded.');
  return { state, msg: `${dps} dial-peers`, notes };
}

export function inspectOptional(text, re, label) {
  if (!text || !text.trim()) return { state: 'opt', msg: 'optional', notes: [] };
  return re.test(text) ? { state: 'ok', msg: `${label} recognised`, notes: [] } : { state: 'warn', msg: `${label} not recognised`, notes: [] };
}
