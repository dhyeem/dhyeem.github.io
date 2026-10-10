// Generates a terminal-recorder style capture that contains only OPTIONS keepalives (no INVITE),
// with the artefacts real recorders add: UTF-8 BOM, "HH:MM:SS.mmm §" prefix on each line, whitespace-only
// lines injected mid-message, a truncated first message and a stray syslog line. All data is dummy.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'tests', 'fixtures');
mkdirSync(out, { recursive: true });

const CUBE = '172.16.5.250';
const CUBE_ITSP = '192.0.2.2';
const peers = [
  { ip: '172.16.10.11', ua: 'Cisco-CUCM12.5', to: CUBE },
  { ip: '172.16.10.12', ua: 'Cisco-CUCM12.5', to: CUBE },
  { ip: '198.51.100.10', ua: '', to: CUBE_ITSP },
];
const lines = [];
let ms = Date.UTC(2024, 0, 1, 10, 0, 0);
const stamp = () => {
  ms += 2;
  const d = new Date(ms);
  const p = (n, l = 2) => String(n).padStart(l, '0');
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)} \u00a7`;
};
const push = (l) => lines.push(`${stamp()}${l}`);
const SDP = (ip) => ['v=0', `o=CiscoSystemsSIP-GW-UserAgent 1111 2222 IN IP4 ${ip}`, 's=SIP Call', `c=IN IP4 ${ip}`, 't=0 0', 'm=audio 0 RTP/AVP 18 0 8 9 4 2 15 3', `c=IN IP4 ${ip}`];

push('Start recording CUBE-LAB-01 (172.16.5.250) \u2013 10:00:00');
push('CUBE-LAB-01#show logging');
// truncated first message (starts mid-header)
push('Content-Type: application/sdp');
push('Content-Length: 169');
push('');
SDP(CUBE).forEach((l) => push(l));
push('');
for (let i = 0; i < 78; i++) {
  const peer = peers[i % peers.length];
  const callId = `${(0x9eaac280 + i).toString(16)}-1f01030b-c50699-ca140a0a@${peer.ip}`;
  const branch = `z9hG4bK${(0xcb65455693 + i * 977).toString(16)}`;
  const tag = 1000000 + i * 37;
  const t = (s) => `*Jan  1 10:${String(Math.floor(i / 6)).padStart(2, '0')}:${String((i % 6) * 10).padStart(2, '0')}.${String(100 + i).padStart(3, '0')}: ${s}`;
  push(t('//-1/xxxxxxxxxxxx/SIP/Msg/ccsipDisplayMsg:'));
  push('Received: ');
  push(`OPTIONS sip:${peer.to}:5060 SIP/2.0`);
  push(`Via: SIP/2.0/UDP ${peer.ip}:5060;branch=${branch}`);
  push(`From: <sip:${peer.ip}>;tag=${tag}`);
  push(`To: <sip:${peer.to}>`);
  push(`Call-ID: ${callId}`);
  if (peer.ua) push(`User-Agent: ${peer.ua}`);
  if (i % 7 === 3) push('          '); // injected whitespace-only line
  push('CSeq: 101 OPTIONS');
  push(`Contact: <sip:${peer.ip}:5060>`);
  push('Max-Forwards: 70');
  push('Content-Length: 0');
  push('');
  push('');
  push(t(`//${348442 + i}/${(0x0EB62EF39478 + i * 4097).toString(16).toUpperCase().padStart(12, '0')}/SIP/Msg/ccsipDisplayMsg:`));
  push('Sent: ');
  push('SIP/2.0 200 OK');
  push(`Via: SIP/2.0/UDP ${peer.ip}:5060;branch=${branch}`);
  push(`From: <sip:${peer.ip}>;tag=${tag}`);
  push(`To: <sip:${peer.to}>;tag=F7A7C3C-${i.toString(16)}`);
  push(`Call-ID: ${callId}`);
  push('Server: Cisco-SIPGateway/IOS-17.9.1a');
  if (i % 11 === 5) push('          ');
  push('CSeq: 101 OPTIONS');
  push('Allow: INVITE, OPTIONS, BYE, CANCEL, ACK, PRACK, UPDATE, REFER, SUBSCRIBE, NOTIFY, INFO, REGISTER');
  push('Content-Type: application/sdp');
  push('Content-Length: 169');
  push('');
  SDP(peer.to).forEach((l) => push(l));
  push('');
}
push('*Jan  1 11:00:03: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 172.16.5.10] [localport: 22]');
push('Stop recording CUBE-LAB-01 (172.16.5.250) - 10:05:00');
writeFileSync(join(out, 'options-only-recorder.log'), '\uFEFF' + lines.join('\r\n') + '\r\n');
console.log('fixture written,', lines.length, 'lines');
