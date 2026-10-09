# CUBE SIP Troubleshooter

Static web app (plain JavaScript, no build step) that explains **why a call through a Cisco CUBE failed**.
You paste the router output, it parses it **in your browser** (nothing is uploaded) and shows, per call:

- a SIP **ladder diagram** (ITSP / CUCM  <->  CUBE  <->  peer) with the dial-peers in use
- the **inbound and outbound dial-peer matching**, step by step in Cisco's documented order, with the reason every dial-peer did or did not match
- the **number timeline**: received -> after incoming translation -> after outgoing translation -> what was actually sent, with the translation rules that fired
- **+E.164 / DID-range checks** against your ITSP profile (what the ITSP sends you, what it expects from you)
- **findings** with evidence from the log and a suggested config fix
- a "**I still need ...**" list for anything it could not determine

## Use it

1. Open the page and follow the numbered steps (it tells you exactly what to collect):
   1. paste the prep commands on the CUBE (timestamps with ms, big buffer, `debug ccsip messages`, `debug voip ccapi inout`)
   2. make one failing call, run `undebug all`, `show logging`, paste the output
   3. paste `show running-config`
   4. optional: `show dial-peer voice summary`, `show dialplan number <n>`, `show voip trace cover-buffers`
   5. fill in the ITSP profile (IPs, country code, DID ranges, required number formats) - saved in your browser, exportable as JSON
   6. optional: the number you dialled, to jump straight to that call
2. **Analyze** -> list of calls -> click one for the detail view.
3. **Mask numbers & IPs** hides digits/IPs on screen before you screenshot or share.
4. **Load sample data** shows two synthetic calls analysed against a sanitized copy of a real config.

## Run locally

ES modules do not load from `file://`; serve the folder:

```
python -m http.server 8080      # then open http://localhost:8080
npm test                        # node --test, no dependencies (Node 18+)
```

`#demo` / `#demo-call-1` / `#demo-call-1-mask` on the URL load the sample and open the result directly.

## Publish on GitHub Pages

Upload the folder to a repo (manually or with git) -> **Settings -> Pages -> Deploy from a branch -> `main` / `(root)`**.
The `.nojekyll` file is already included. There is no server component.

**Before uploading, review the content.** This folder was seeded from your own captures:
- `samples/running-config.txt` is a sanitized copy (secrets, password hashes and certificates removed) but still contains your hostname, domain, IPs and DID plan.
- `tests/fixtures/options-only-recorder.log` is your original recorder log (internal IPs only).
- `Working DMM_VG.txt` and `DMM-CST-VG-R01(...).log` in the root are your **raw originals** (the config contains password hashes). **Do not upload those two files**; delete them or add them to `.gitignore`.
GitHub Pages on a private repo needs a paid plan; on a free plan a Pages site is public.

## Layout

```
index.html  css/style.css
js/app.js                UI wiring (inputs, checklist status, call list, detail)
js/pipeline.js           texts -> calls + analyses (pure, used by UI and tests)
js/parsers/              clean.js (recorder prefix, blocks) ccsip.js ccapi.js config.js summary.js
js/engine/               pattern.js translation.js matcher.js correlate.js itsp.js diagnose.js
js/render/               dom.js (escape, masking) ladder.js detail.js
js/ui/checklist.js       "what I need" commands + live input validation
samples/                 two synthetic calls + sanitized config
tools/                   make-samples.mjs make-config-sample.mjs
tests/                   node --test (21 tests)
```

## How matching is modelled (from Cisco "Understand IOS and IOS XE Call Routing")

- **Inbound SIP**: `incoming uri via > request > to > from`, then `incoming called-number` / `incoming called e164-pattern-map`, then `answer-address` / `incoming calling e164-pattern-map`, then `destination-pattern` compared with the **calling** number, else **dial-peer 0**.
  (This last step matters: a catch-all `destination-pattern .T` can make a dial-peer match inbound calls "by accident"; the tool flags it.)
- **Outbound SIP**: `destination dpg`, `destination uri`, then `destination-pattern` / `destination e164-pattern-map`; longest match, then `preference` (dial-peer hunt 0, or 2/3); shutdown / down / no-session-target dial-peers are excluded; no match = call fails.
- **Patterns**: `.` any of `0-9 A-F * # +`, `T` variable length, `%` `?` `[ ]` `( )` `$`; a `+` is a literal only at the **start** of a pattern, so `9661381052..` can never match `+966138105234`.
- **Translation rules**: top-down, first match wins, not anchored unless `^`, only the matched part is replaced; `\(..\)`, `\0`/`&`, `\1..\9`, `reject`.

## Known limits (please read)

- `debug voip ccapi inout` parsing follows Cisco's documented line prefix (`//<callid>/<GUID>/CCAPI/<function>:`) with tolerant `Key=Value` extraction (`Incoming Dial-peer=`, `Outgoing Dial-peer=`, `Calling/Called Number=`, `Cause Value=`). **It has not been verified against a real capture yet.** If a real log shows different field names, paste it and the regexes in `js/parsers/ccapi.js` are the only thing to adjust. Without CCAPI lines the tool still works, but the dial-peers are simulated from the config.
- A pattern with no `$` is treated as a prefix match (why `incoming called-number .` matches everything). Tie-breaking uses the count of literal characters, then preference, then config order.
- Not simulated: VRF/tenant filtering, SIP profiles, `num-exp`, dial-peer provision-policy, `dnis-map`, ISDN/numbering-type filters. These are listed as notes when present in the config.
- Calls are paired (in-leg + out-leg) by GUID, then by `show voip trace`, then by timing; timing-based pairing is flagged in the UI.
