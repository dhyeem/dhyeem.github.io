// Generates synthetic sample captures in the real IOS-XE format (debug ccsip messages + debug voip ccapi inout).
// The CCAPI lines are modelled on Cisco's documented prefix; field names are unverified against a real capture.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'samples');
mkdirSync(out, { recursive: true });

const CUBE_ITSP = '10.170.34.114';
const CUBE_PBX = '10.203.5.250';
const ITSP = '10.154.15.1';
const PBX = '10.10.20.201';

const sdp = (ip, pts, extra = []) => [
  'v=0', `o=CiscoSystemsSIP-GW-UserAgent 1234 5678 IN IP4 ${ip}`, 's=SIP Call', `c=IN IP4 ${ip}`, 't=0 0',
  `m=audio 16384 RTP/AVP ${pts.join(' ')}`, `c=IN IP4 ${ip}`,
  ...pts.map((p) => ({ 0: 'a=rtpmap:0 PCMU/8000', 8: 'a=rtpmap:8 PCMA/8000', 18: 'a=rtpmap:18 G729/8000', 101: 'a=rtpmap:101 telephone-event/8000' }[p])).filter(Boolean),
  ...(pts.includes(101) ? ['a=fmtp:101 0-16'] : []), ...extra,
];

class Log {
  constructor(start) { this.t = start; this.lines = []; this.seq = 1000; }
  tick(ms = 8) { this.t += ms; const d = new Date(this.t); const p = (n, l = 2) => String(n).padStart(l, '0'); return `${String(this.seq++).padStart(6, '0')}: *Mar 18 ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}: `; }
  msg(ccid, guid, dir, startLine, headers, body = [], ms = 8) {
    this.lines.push(`${this.tick(ms)}//${ccid}/${guid}/SIP/Msg/ccsipDisplayMsg:`, `${dir}: `, startLine, ...headers, `Content-Length: ${body.join('\r\n').length}`, '', ...body, '');
  }
  cc(ccid, guid, fn, text, ms = 3) { this.lines.push(`${this.tick(ms)}//${ccid}/${guid}/CCAPI/${fn}:`, ...text.map((x) => '   ' + x)); }
  syslog(text, ms = 3) { this.lines.push(`${this.tick(ms)}${text}`); }
  toString() { return this.lines.join('\n') + '\n'; }
}

// ---------------------------------------------------------------- sample 1: ITSP -> CUBE, DID outside translation range, inbound dp 500 by ANI, hairpin back to ITSP, 403
{
  const L = new Log(Date.UTC(2024, 2, 18, 9, 30, 0));
  const G = 'AABBCCDD0001';
  const inCall = 'a1b2c3d4-0001@10.154.15.1';
  const outCall = 'e5f6a7b8-0002@10.170.34.114';
  const calling = '+966501234567';
  const called = '+966138106234';
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', `INVITE sip:${called}@${CUBE_ITSP}:5060 SIP/2.0`, [
    `Via: SIP/2.0/UDP ${ITSP}:5060;branch=z9hG4bKitsp0001`, `From: <sip:${calling}@${ITSP}>;tag=itsp-tag-1`, `To: <sip:${called}@${CUBE_ITSP}>`, `Call-ID: ${inCall}`, 'CSeq: 1 INVITE',
    `Contact: <sip:${calling}@${ITSP}:5060>`, 'Max-Forwards: 69', 'Allow: INVITE, ACK, CANCEL, BYE, OPTIONS', 'Content-Type: application/sdp',
  ], sdp(ITSP, [8, 0, 18, 101]));
  L.cc(-1, 'xxxxxxxxxxxx', 'cc_api_call_setup_ind', [`Interface=0x7F1C2C3D4E00, Call Info(`, `Calling Number=${calling},(Calling Name=)(TON=Unknown, NPI=Unknown, Screening=Not Screened, Presentation=Allowed),`, `Called Number=${called}(TON=Unknown, NPI=Unknown),`, `Calling Translated=FALSE, Subscriber Type Str=RegularLine, FinalDestinationFlag=TRUE,`, `Incoming Dial-peer=500, Progress Indication=NULL(0), Calling IE Present=TRUE,`, `Source Trkgrp Route Label=, Target Trkgrp Route Label=, CLID Transparent=FALSE), Call Id=-1`]);
  L.msg(2001, G, 'Sent', 'SIP/2.0 100 Trying', [`Via: SIP/2.0/UDP ${ITSP}:5060;branch=z9hG4bKitsp0001`, `From: <sip:${calling}@${ITSP}>;tag=itsp-tag-1`, `To: <sip:${called}@${CUBE_ITSP}>`, `Call-ID: ${inCall}`, 'CSeq: 1 INVITE', 'Allow-Events: telephone-event', 'Server: Cisco-SIPGateway/IOS-17.6.1a'], [], 4);
  L.cc(2001, G, 'ccCallSetupRequest', [`Calling Number=${calling}, Called Number=${called}, Calling Translated=FALSE, Called Translated=FALSE,`, `Outgoing Dial-peer=500, Call Id=2002`]);
  L.msg(2002, G, 'Sent', `INVITE sip:${called}@${ITSP}:5060 SIP/2.0`, [
    `Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0002`, `From: <sip:50501234567@${CUBE_ITSP}>;tag=cube-tag-2`, `To: <sip:${called}@${ITSP}>`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE',
    `Contact: <sip:50501234567@${CUBE_ITSP}:5060>`, 'Max-Forwards: 68', 'Allow: INVITE, OPTIONS, BYE, CANCEL, ACK, PRACK, UPDATE, REFER', 'Content-Type: application/sdp',
  ], sdp(CUBE_ITSP, [8, 0, 101]), 6);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', 'SIP/2.0 403 Forbidden', [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0002`, `From: <sip:50501234567@${CUBE_ITSP}>;tag=cube-tag-2`, `To: <sip:${called}@${ITSP}>;tag=itsp-to-2`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE', 'Reason: Q.850;cause=21;text="Calling party not allowed"'], [], 40);
  L.msg(2002, G, 'Sent', `ACK sip:${called}@${ITSP}:5060 SIP/2.0`, [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0002`, `From: <sip:50501234567@${CUBE_ITSP}>;tag=cube-tag-2`, `To: <sip:${called}@${ITSP}>;tag=itsp-to-2`, `Call-ID: ${outCall}`, 'CSeq: 101 ACK'], [], 2);
  L.cc(2001, G, 'cc_api_call_disconnected', ['Cause Value=21, Interface=0x7F1C2C3D4E00, Call Id=2001']);
  L.msg(2001, G, 'Sent', 'SIP/2.0 403 Forbidden', [`Via: SIP/2.0/UDP ${ITSP}:5060;branch=z9hG4bKitsp0001`, `From: <sip:${calling}@${ITSP}>;tag=itsp-tag-1`, `To: <sip:${called}@${CUBE_ITSP}>;tag=cube-in-tag-1`, `Call-ID: ${inCall}`, 'CSeq: 1 INVITE', 'Reason: Q.850;cause=21', 'Server: Cisco-SIPGateway/IOS-17.6.1a'], [], 3);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', `ACK sip:${called}@${CUBE_ITSP}:5060 SIP/2.0`, [`Via: SIP/2.0/UDP ${ITSP}:5060;branch=z9hG4bKitsp0001`, `From: <sip:${calling}@${ITSP}>;tag=itsp-tag-1`, `To: <sip:${called}@${CUBE_ITSP}>;tag=cube-in-tag-1`, `Call-ID: ${inCall}`, 'CSeq: 1 ACK'], [], 30);
  writeFileSync(join(out, 'call-itsp-hairpin-fail.log'), L.toString());
}

// ---------------------------------------------------------------- sample 2: CUCM -> CUBE -> ITSP answered, called number sent as national (not +E.164)
{
  const L = new Log(Date.UTC(2024, 2, 18, 9, 41, 0));
  const G = 'AABBCCDD0002';
  const inCall = '11112222-3333@10.10.20.201';
  const outCall = '44445555-6666@10.170.34.114';
  const calling = '1201';
  const called = '0555123456';
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', `INVITE sip:${called}@${CUBE_PBX}:5060 SIP/2.0`, [
    `Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0001`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>`, `Call-ID: ${inCall}`, 'CSeq: 101 INVITE',
    `Contact: <sip:${calling}@${PBX}:5060>`, 'Max-Forwards: 69', 'Allow: INVITE, OPTIONS, INFO, BYE, CANCEL, ACK, PRACK, UPDATE, REFER', 'Content-Type: application/sdp',
  ], sdp(PBX, [0, 8, 101]));
  L.cc(-1, 'xxxxxxxxxxxx', 'cc_api_call_setup_ind', [`Interface=0x7F1C2C3D4F00, Call Info(`, `Calling Number=${calling},(Calling Name=Ext 1201)(TON=Unknown, NPI=Unknown, Screening=Not Screened, Presentation=Allowed),`, `Called Number=${called}(TON=Unknown, NPI=Unknown),`, `Calling Translated=FALSE, Subscriber Type Str=RegularLine, FinalDestinationFlag=TRUE,`, `Incoming Dial-peer=102, Progress Indication=NULL(0), Calling IE Present=TRUE), Call Id=-1`]);
  L.msg(3001, G, 'Sent', 'SIP/2.0 100 Trying', [`Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0001`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>`, `Call-ID: ${inCall}`, 'CSeq: 101 INVITE', 'Server: Cisco-SIPGateway/IOS-17.6.1a'], [], 4);
  L.cc(3001, G, 'ccCallSetupRequest', [`Calling Number=+966138105201, Called Number=${called}, Calling Translated=TRUE, Called Translated=FALSE,`, `Outgoing Dial-peer=500, Call Id=3002`]);
  L.msg(3002, G, 'Sent', `INVITE sip:${called}@${ITSP}:5060 SIP/2.0`, [
    `Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0003`, `From: <sip:+966138105201@${CUBE_ITSP}>;tag=cube-tag-3`, `To: <sip:${called}@${ITSP}>`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE',
    `Contact: <sip:+966138105201@${CUBE_ITSP}:5060>`, 'Max-Forwards: 68', 'Content-Type: application/sdp',
  ], sdp(CUBE_ITSP, [8, 0, 101]), 6);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', 'SIP/2.0 100 Trying', [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0003`, `From: <sip:+966138105201@${CUBE_ITSP}>;tag=cube-tag-3`, `To: <sip:${called}@${ITSP}>`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE'], [], 20);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', 'SIP/2.0 180 Ringing', [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0003`, `From: <sip:+966138105201@${CUBE_ITSP}>;tag=cube-tag-3`, `To: <sip:${called}@${ITSP}>;tag=itsp-to-3`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE'], [], 400);
  L.msg(3001, G, 'Sent', 'SIP/2.0 180 Ringing', [`Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0001`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>;tag=cube-in-tag-3`, `Call-ID: ${inCall}`, 'CSeq: 101 INVITE'], [], 3);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', 'SIP/2.0 200 OK', [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0003`, `From: <sip:+966138105201@${CUBE_ITSP}>;tag=cube-tag-3`, `To: <sip:${called}@${ITSP}>;tag=itsp-to-3`, `Call-ID: ${outCall}`, 'CSeq: 101 INVITE', `Contact: <sip:${called}@${ITSP}:5060>`, 'Content-Type: application/sdp'], sdp(ITSP, [8, 101]), 3000);
  L.cc(3001, G, 'cc_api_call_connected', ['Call Id=3001']);
  L.msg(3001, G, 'Sent', 'SIP/2.0 200 OK', [`Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0001`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>;tag=cube-in-tag-3`, `Call-ID: ${inCall}`, 'CSeq: 101 INVITE', `Contact: <sip:${called}@${CUBE_PBX}:5060>`, 'Content-Type: application/sdp'], sdp(CUBE_PBX, [8, 101]), 3);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', `ACK sip:${called}@${CUBE_PBX}:5060 SIP/2.0`, [`Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0002`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>;tag=cube-in-tag-3`, `Call-ID: ${inCall}`, 'CSeq: 101 ACK'], [], 20);
  L.msg(3002, G, 'Sent', `ACK sip:${called}@${ITSP}:5060 SIP/2.0`, [`Via: SIP/2.0/UDP ${CUBE_ITSP}:5060;branch=z9hG4bKcube0004`, `From: <sip:+966138105201@${CUBE_ITSP}>;tag=cube-tag-3`, `To: <sip:${called}@${ITSP}>;tag=itsp-to-3`, `Call-ID: ${outCall}`, 'CSeq: 101 ACK'], [], 3);
  L.msg(-1, 'xxxxxxxxxxxx', 'Received', `BYE sip:${called}@${CUBE_PBX}:5060 SIP/2.0`, [`Via: SIP/2.0/UDP ${PBX}:5060;branch=z9hG4bKcucm0003`, `From: "Ext 1201" <sip:${calling}@${PBX}>;tag=cucm-tag-1`, `To: <sip:${called}@${CUBE_PBX}>;tag=cube-in-tag-3`, `Call-ID: ${inCall}`, 'CSeq: 102 BYE'], [], 25000);
  L.cc(3001, G, 'cc_api_call_disconnected', ['Cause Value=16, Interface=0x7F1C2C3D4F00, Call Id=3001']);
  writeFileSync(join(out, 'call-cucm-to-itsp-ok.log'), L.toString());
}
console.log('samples written to', out);


