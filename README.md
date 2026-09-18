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

---

## How a block happens, end to end

```
browser navigation to https://paypa1-secure.example.com/login
        │
        ▼
declarativeNetRequest (DNR) evaluates session rules installed by the
background service worker. Each blocklist entry became one session rule:
        │   condition.regexFilter  = ^(https?://(?:[^/]*\.)?paypa1-secure\.example\.com(?::\d+)?(?:[/?].*)?)$
        │   condition.resourceTypes = ["main_frame"]
        │   action    = redirect →  chrome-extension://<id>/tabs/blocked.html
        │                             ?source=bundled-test-list&url=\1
        ▼                       (\1 = the full original URL, capture group 1)
tabs/blocked.html opens inside the tab
        │   1. parses ?source=…&url=…          (src/lib/blocklist.ts)
        │   2. extracts the hostname           (new URL(url).hostname)
        │   3. VERIFIES hostname against the bundled blocklist
        │   4. renders the reason and records the event to storage
        ▼
you see: blocked domain, source list, original URL, note, close button
        │
        └── toolbar popup reads storage → "Last blocked: domain / source / time"
```

Three contract decisions make this work — they are the heart of the
design:

1. **Capture group 1 is the whole URL.** `hostToRegexPattern` wraps the
   entire match in `(...)`, so the redirect substitution `&url=\1` carries
   the exact original URL into the blocked page. Without it, a blocked
   page could not say _what_ it blocked.
2. **The URL is the last query param.** The original URL is appended raw
   (regex substitution can't percent-encode), so it may contain its own
   `&` and `?`. Placing it last means `parseBlockedPageParams` can split
   on the `&url=` marker and treat everything after it as the URL.
3. **The page verifies, never trusts.** `tabs/blocked.html` is in
   `web_accessible_resources` (`<all_urls>`), so any site could link users
   to it with crafted params. The page therefore looks the hostname up in
   the bundled blocklist (`findBlocklistEntry`) and only claims a block —
   and only records a `lastBlocked` event — when the hostname genuinely
   matches an entry. The `source` shown always comes from our data, never
   from the query string.

---

## The code, file by file

### `src/lib/types.ts` — shared vocabulary

```ts
BlocklistEntry  { domain: string; source: string; note?: string }
BlockEvent      { url: string; domain: string; source: string; blockedAt: number }
DnrRule         { id, priority, condition: { regexFilter, resourceTypes }, action: { type: "redirect", redirect: { regexSubstitution } } }
```

`BlocklistEntry` is the JSON schema of the blocklist; `BlockEvent` is what
storage remembers for the popup; `DnrRule` is a minimal structural copy of
Chrome's rule shape so the pure builder stays dependency-free (the
background casts it to the real type at the API boundary).

### `src/lib/blocklist.ts` — pure rule engine (the core)

- **`hostToRegexPattern(domain)`** — turns `"paypa1-secure.example.com"`
  into
  `^(https?://(?:[^/]*\.)?paypa1-secure\.example\.com(?::\d+)?(?:[/?].*)?)$`.
  Piece by piece: escape regex specials in the domain; `(?:[^/]*\.)?`
  allows any depth of subdomains (`a.b.example.com`) while anchoring the
  domain so `notexample.com` and `example.com.evil.io` never match;
  `(?::\d+)?` allows a port; `(?:[/?].*)?` allows a path/query; the whole
  thing is capture group 1.
- **`buildRules(entries, blockedPageBaseUrl, startId = 1)`** — one `DnrRule`
  per entry with deterministic ids (`startId + index`, so re-syncs are
  stable) and the substitution template
  `<blockedPageBaseUrl>?source=<encodeURIComponent(source)>&url=\1`.
- **`findBlocklistEntry(entries, hostname)`** — case-insensitive exact
  hostname lookup; the anti-spoofing gate used by the blocked page.
- **`parseBlockedPageParams(search)`** — parses `?source=<s>&url=<raw>`
  honoring contract decision 2; returns `null` when either part is
  missing (the page then shows a generic, still-explainable message).

Nothing here touches a browser API — that's what makes it unit-testable.

### `src/lib/explain.ts` — the "why" copy

`explainBlocklistMatch({ domain, source })` produces the human-readable
reason ("… appears in the <source> blocklist of known phishing and scam
sites"); `explainUnknownBlock()` covers the generic branch. One module
owns all user-facing block explanations so popup/page copy can never
drift apart.

### `src/lib/storage.ts` — the only place that touches `storage.local`

Two keys, one typed accessor per key:

| Key           | Value        | Writer                             | Reader    |
| ------------- | ------------ | ---------------------------------- | --------- |
| `enabled`     | `boolean`    | background (on message)            | SW, popup |
| `lastBlocked` | `BlockEvent` | blocked page (on a verified block) | popup     |

`getEnabled()` defaults to **on** (`!== false`) so a fresh install blocks
immediately. Reads pass through an `isBlockEvent` guard so corrupt
storage can't poison the popup.

### `src/background/index.ts` — the service worker entry

Three things, in this order:

1. Registers `runtime.onMessage` **synchronously** (MV3 rule: listeners
   must register before any await).
2. Fires `syncBlocklistRules()` top-level with `void` — runs on every
   service-worker wake (SWs are ephemeral; session rules persist for the
   browser session, this re-apply is idempotent insurance).
3. The message router: `{ type: "setEnabled", value: boolean }` → persists
   the state, re-syncs rules, responds `{ enabled }`. Unknown messages
   return `undefined` so the polyfill doesn't hold the response channel.

### `src/background/rules.ts` — rule sync

`syncBlocklistRules()` is idempotent and fail-safe:

1. Read `enabled` from storage; read existing session rules and collect
   their ids.
2. If disabled → `updateSessionRules({ removeRuleIds })` (clears ours).
3. If enabled → build fresh rules from `blocklist.json` (redirect base =
   `browser.runtime.getURL("tabs/blocked.html")`) and
   `updateSessionRules({ removeRuleIds, addRules })` — removing first
   makes the sync idempotent even if the entry list shrinks.
4. The whole body sits in `try/catch`: any DNR failure logs and degrades
   to "no filtering" — the worker never crashes, and the popup's state
   stays truthful because it reads storage, not assumptions.

### `src/tabs/blocked.tsx` — the explainable blocked page

Render pipeline (all memoized): parse params → extract hostname → verify
against the bundled blocklist. Two branches:

- **Verified block** (`entry` found): red badge, "Phishing guard blocked
  this page", the `explainBlocklistMatch` reason built from the _bundled_
  entry's `source`, the original URL, the entry's `note`, close button.
  The `useEffect` records the `BlockEvent` (only here — the verified
  branch).
- **Unverified / garbage params** (or a subdomain of a listed domain):
  "Request blocked" + `explainUnknownBlock()` + close button. Never a
  dead end, never a false claim.

Security notes: the URL is attacker-influenced and is only ever rendered
as React text (never `dangerouslySetInnerHTML`); the close button uses
`window.close()` (allowed for extension pages opened in a tab).

### `src/popup.tsx` — status surface

Reads `enabled` + `lastBlocked` straight from storage on mount (no
messaging needed for reads). The toggle is the only mutation and goes
through the background message contract; the UI updates optimistically
and re-reads fresh state on next open. Shows source + timestamp of the
last verified block.

### `src/data/blocklist.json` — the data

Five entries, all RFC 2606 reserved domains (`example.com` subdomains,
`.example`, `.example.net`, `.example.org`) so shipping test entries can
never block a real site. Schema `{ domain, source, note }` is deliberately
feed-shaped: an OpenPhish/PhishTank importer (Phase 2+) maps straight onto
it. The `source` field is what makes blocks explainable ("which list said
so").

---

## Manifest & build configuration

- **`package.json` → `"manifest"` key** — Plasmo merges this into the
  generated manifest (verified in `build/chrome-mv3-prod/manifest.json`):
  - `permissions: ["declarativeNetRequest", "storage"]`
  - `host_permissions: ["<all_urls>"]` — DNR **redirects** require host
    permission over redirected requests; a blocklist can name any domain,
    and nothing is read from or sent to these hosts.
  - `web_accessible_resources`: only `tabs/blocked.html`, for `<all_urls>`
    — required so DNR may redirect web navigations to it.
- **`pnpm-workspace.yaml`** — `allowBuilds` allowlist for native-build
  deps (esbuild, @swc/core, lmdb, sharp, @parcel/watcher,
  msgpackr-extract); pnpm 12 refuses their postinstall scripts otherwise.
- **`tsconfig.json`** — extends `plasmo/templates/tsconfig.base`; `~*`
  alias → `./src/*`; `resolveJsonModule` for `blocklist.json` imports.
- **Plasmo conventions used:** `src/` layout (entries auto-discovered:
  `background/index.ts`, `popup.tsx`, `tabs/*.tsx` → real HTML pages);
  `src/platform/` and `src/models/` are empty placeholders reserved for
  Phase 3+ (browser-specific escapes) and Phase 5 (TF.js).
- **`vitest.config.ts`** — node environment, `src/**/*.test.ts`, `~` alias
  mirrored from tsconfig.

---

## Testing & verification

- **16 vitest tests** across `src/lib/blocklist.test.ts` (11) and
  `src/lib/explain.test.ts` (2… plus 3 `findBlocklistEntry` cases): the
  regex is executed against realistic URLs — positives (http/https,
  paths, queries, ports, deep subdomains), negatives (`notexample.com`,
  `example.com.evil.io`, `example.comic.org`, other schemes), the
  builder↔parser round-trip contract, and explain copy.
- `pnpm exec tsc --noEmit` clean, `pnpm build` clean, prettier clean.
- What is _not_ unit-tested: browser glue (`storage.ts`, `rules.ts` —
  requires a real extension host) — covered by the manual Chrome checklist
  below.

## Development

Requires [pnpm](https://pnpm.io).

```bash
pnpm install        # install dependencies
pnpm dev            # dev build with live reload
pnpm build          # production build to build/chrome-mv3-prod
pnpm package        # zip the built extension for store submission
pnpm test           # run unit tests (vitest, 16 tests)
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
│   ├── index.ts  # entry: listener registration, enable-state messages
│   └── rules.ts  # syncBlocklistRules(): storage state → session rules
├── data/         # blocklist.json — bundled domain list
├── lib/          # pure logic: blocklist.ts, explain.ts (+ tests), types
│                 # impure glue: storage.ts (storage.local accessors)
├── tabs/         # blocked.tsx — the explainable blocked page
├── popup.tsx     # toolbar popup: status, toggle, last blocked
├── platform/     # (empty — browser-specific escapes, Phase 3+)
└── models/       # (empty — on-device TF.js, Phase 5+)
```

## How this was built (process record)

Work proceeded through a brainstormed design spec
(`docs/superpowers/specs/2026-09-17-phishing-guard-phase1-design.md`) and a
task-by-task implementation plan
(`docs/superpowers/plans/2026-09-17-phishing-guard-phase1.md`), executed
with a fresh implementer subagent per task and an independent reviewer per
diff. Notable verified decisions from that process:

- Scaffolded from the create-plasmo 0.90.5 template (driven through a
  PTY), adapted to the `src/` layout; pnpm 12 `allowBuilds` configured.
- DNR **session rules** (dynamic, toggle-friendly) over a static
  ruleset; **regex redirect with substitution** (preserves the original
  URL) over `requestDomains` + `extensionPath` (would lose it).
- Final whole-branch review hardened the blocked page: close affordance
  on every branch, and block claims verified against the bundled list
  before display/recording (anti content-spoofing).
