# Phishing guard

An on-device phishing and scam site blocker for Manifest V3 browsers. It is
the client-side complement to DNS-level filtering: a DNS filter (in the
style of Nandi Security's Kavalan) blocks bad domains network-wide, while
this extension runs inside the browser to catch what DNS-level filtering
cannot. See [AGENTS.md](AGENTS.md) for the full project context and
[PRIVACY.md](PRIVACY.md) for the privacy policy — the extension makes no
network requests, collects no page content, and sends nothing off-device.

This is a practice project built with
[Plasmo](https://www.plasmo.com/) 0.90.5, TypeScript, React 18, and
[webextension-polyfill](https://github.com/mozilla/webextension-polyfill).

## Status

| Phase                          | Scope                                                                                                 | Status                                                   |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| 1 — Blocklist MVP (Chrome)     | Static bundled blocklist enforced via `declarativeNetRequest`, explainable blocked page, status popup | Done (code complete; manual Chrome verification pending) |
| 2 — Heuristic scoring (Chrome) | URL/domain feature scoring for domains not on the blocklist                                           | Not started                                              |
| 3 — Cross-browser port         | Verify behavior on Firefox and Edge                                                                   | Not started                                              |
| 4 — Safari port                | Xcode conversion and Safari fixes                                                                     | Not started                                              |
| 5 — On-device ML (stretch)     | TensorFlow.js scoring, still fully on-device                                                          | Not started                                              |

## How it works (Phase 1)

- The background service worker (`src/background/`) builds
  `declarativeNetRequest` session rules from the bundled blocklist and
  re-syncs them whenever you toggle protection.
- Each rule redirects main-frame navigations to a blocklisted domain (or its
  subdomains, over http/https) to the extension's local blocked page
  (`src/tabs/blocked.tsx`), which shows the matched domain, the source list
  it came from, and the original URL — no silent blocks.
- The toolbar popup (`src/popup.tsx`) shows whether protection is active,
  lets you toggle it, and shows the last blocked event.
- Blocklist entries live in `src/data/blocklist.json` (fields: `domain`,
  `source`, `note`). It currently ships five RFC 2606 reserved test domains.

## Development

Requires [pnpm](https://pnpm.io).

```bash
pnpm install        # install dependencies
pnpm dev            # dev build with live reload
pnpm build          # production build to build/chrome-mv3-prod
pnpm package        # zip the built extension for store submission
pnpm test           # run unit tests (vitest, 13 tests)
pnpm typecheck      # tsc --noEmit
```

## Load in Chrome

1. Run `pnpm build`.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select `build/chrome-mv3-prod`.

## Test blocking

Navigate to any blocklisted domain, for example:

```
http://paypa1-secure.example.com
```

All blocklist domains are RFC 2606 reserved (`example.com`, `.example`,
`.example.net`, `.example.org`), so these navigations are safe — nothing
real loads. You should be redirected to the Phishing guard blocked page,
which names the domain and the source list that matched it. To confirm the
extension does nothing on normal sites, browse anywhere else and verify no
interference. Toggle protection off and on from the popup to see the
blocked page stop and start working.

## Manual Chrome checklist (AGENTS.md section 6)

The per-browser checklist repeats every phase; Phase 1 covers the Chrome
row (Firefox/Edge/Safari rows apply to later phases):

- [ ] Load unpacked in Chrome (`chrome://extensions` → Developer mode → Load unpacked)
- [ ] Load temporarily in Firefox (`about:debugging` or `web-ext run`) — later phase
- [ ] Load unpacked in Edge (`edge://extensions`) — later phase
- [ ] Convert and run in Safari via Xcode — later phase
- [ ] Verify block/warn reason is shown correctly on each
- [ ] Verify no console errors specific to one browser

## Repo layout

```
src/
├── background/   # service worker: DNR session-rule sync, message routing
├── data/         # blocklist.json — bundled domain list
├── lib/          # rule building, storage helpers, explain copy (+ vitest tests)
├── tabs/         # blocked.tsx — the explainable blocked page
└── popup.tsx     # toolbar popup: status, toggle, last blocked
```

`src/platform/` and `src/models/` are placeholders for later phases
(browser-specific code and on-device ML respectively).
