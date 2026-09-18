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

| Phase                          | Scope                                                                                                 | Status                                                                    |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| 1 — Blocklist MVP (Chrome)     | Static bundled blocklist enforced via `declarativeNetRequest`, explainable blocked page, status popup | Done (code complete; manual Chrome verification pending)                  |
| 2 — Heuristic scoring (Chrome) | URL/domain feature scoring for domains not on the blocklist                                           | Done (unit-tested; warn banner ships; manual Chrome verification pending) |
| 3 — Cross-browser port         | Verify behavior on Firefox and Edge                                                                   | Code + builds + `web-ext lint` done; manual browser passes pending        |
| 4 — Safari port                | Xcode conversion and Safari fixes                                                                     | Blocked: needs full Xcode; procedure documented below                     |
| 5 — On-device ML (stretch)     | TensorFlow.js scoring, still fully on-device                                                          | Baseline done: dependency-free logistic model behind a model adapter      |

---

## How a warning happens, end to end (Phases 2 + 5)

For URLs _not_ on the blocklist (those are redirected before any page
loads), a content script scores every page you open:

```
content script (src/contents/warning-banner.ts) runs on the page
        │
        ▼
scoreUrl(location.href)          ← src/lib/heuristics.ts (pure)
  11 URL features: brand typosquat/embed (Levenshtein vs 25 brands),
  punycode (xn--), bare-IP host, userinfo '@', suspicious TLDs,
  hostname entropy, credential-style path, digit ratio, hyphens,
  subdomain depth, host length
        │
        ├─ heuristicScore = Σ weight·feature   (WARN_THRESHOLD = 35)
        ▼
getModel().score(features)       ← src/models/logistic.ts (pure, on-device)
  logistic regression over the SAME feature vector
  (MODEL_THRESHOLD = 55)
        │
        ▼
warn if either threshold is crossed
        │   → dismissible red banner via shadow DOM (textContent only,
        │     every reason listed, both scores shown)
        └──→ WarnEvent recorded to storage.local["lastWarned"]
             → popup shows "Last warning"
```

Invariants: warnings **never block** navigation; scoring uses the URL only
(no page content, nothing off-device); a broken content script can never
break the page (guarded try/catch around the whole flow).

The model is a dependency-free logistic baseline (weights baked in
`src/models/logistic.ts`) behind the `PhishingModel` interface — when a
real trained TF.js model exists, it slots in as one new adapter
implementation with zero call-site changes. TF.js itself is deliberately
not bundled yet (~2 MB to multiply an 11-vector).

## Cross-browser notes (Phases 3–4)

- Every browser API call goes through `webextension-polyfill`; the one
  browser-specific concern — Firefox's DNR lacking session rules — is
  handled by capability detection in `src/platform/rules-backend.ts`
  (session rules on Chrome/Safari, dynamic rules on Firefox).
- Firefox: `pnpm build --target=firefox-mv2` (gecko id wired via
  `.env.firefox`) then `pnpm run lint:firefox` (0 errors). Interactive
  testing: `pnpm dlx web-ext run --source-dir build/firefox-mv2-prod`
  (needs Firefox installed).
- Edge: load `build/chrome-mv3-prod` via `edge://extensions` (same
  engine as Chrome).
- Safari (needs full Xcode, not just CommandLineTools):
  `xcrun safari-web-extension-converter build/chrome-mv3-prod
--project-location ./safari --app-name "Phishing guard"
--bundle-identifier dev.n1ecc.phishing-guard --no-open`, then open the
  generated Xcode project, build, and enable the extension in Safari's
  Settings → Extensions.

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
  `background/index.ts`, `popup.tsx`, `tabs/*.tsx` → real HTML pages,
  `contents/*` → content scripts); `src/platform/` holds the one
  browser-specific escape hatch (DNR rules backend); `src/models/` holds
  the on-device model behind its adapter interface.
- **`vitest.config.ts`** — node environment, `src/**/*.test.ts`, `~` alias
  mirrored from tsconfig.

---

## Testing & verification

- **35 vitest tests** across four files:
  - `src/lib/blocklist.test.ts` (14): the block regex executed against
    realistic URLs — positives (http/https, paths, queries, ports, deep
    subdomains), negatives (`notexample.com`, `example.com.evil.io`,
    `example.comic.org`, other schemes), the builder↔parser round-trip
    contract.
  - `src/lib/explain.test.ts` (5): block and unknown-block copy.
  - `src/lib/heuristics.test.ts` (11): Levenshtein, calibration
    invariants (google/github/apple score 0; typosquats, punycode,
    userinfo-@ warn; bare IP alone doesn't), score clamping, threshold.
  - `src/models/logistic.test.ts` (5): exact sigmoid values (4 / 27 / 65),
    threshold crossing, realistic-URL self-consistency.
- `pnpm exec tsc --noEmit` clean; `pnpm build` (chrome-mv3) and
  `pnpm build --target=firefox-mv2` clean; `web-ext lint` 0 errors.
- What is _not_ unit-tested: browser glue (`storage.ts`, `rules.ts`,
  content-script injection — requires a real extension host) — covered by
  the manual checklists below.

## Development

Requires [pnpm](https://pnpm.io).

```bash
pnpm install        # install dependencies
pnpm dev            # dev build with live reload
pnpm build          # production build to build/chrome-mv3-prod
pnpm package        # zip the built extension for store submission
pnpm test           # run unit tests (vitest, 35 tests)
pnpm typecheck      # tsc --noEmit
pnpm build --target=firefox-mv2   # Firefox build
pnpm run lint:firefox             # web-ext lint on the Firefox build
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

## Test warnings (heuristics + model)

Warnings only fire for URLs **not** on the blocklist, and never block
navigation. The banner is dismissible and lists its reasons. URLs that
trigger it (safe to type — they don't resolve):

```
https://paypa1-support.com/login     # brand typosquat + credential path
https://secure-chase-verify.net/     # embedded brand + credential path
https://google.com@evil-example.io/  # userinfo '@' disguise
https://xn--80ak6aa92e.com/          # punycode lookalike
```

Sites like `google.com`, `github.com`, or `apple.com` must show nothing.
The popup's "Last warning" section records the most recent one.

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
├── background/   # service worker: DNR rule sync (session or dynamic), messages
│   ├── index.ts  # entry: listener registration, enable-state messages
│   └── rules.ts  # syncBlocklistRules(): storage state → DNR rules
├── contents/     # warning-banner.ts — heuristic warning overlay (Phase 2)
├── data/         # blocklist.json — bundled domain list
├── lib/          # pure logic: blocklist.ts, heuristics.ts, explain.ts, types
│                 # (+ colocated vitest tests) · impure glue: storage.ts
├── models/       # logistic.ts + PhishingModel adapter (Phase 5 baseline)
├── platform/     # rules-backend.ts — session/dynamic DNR capability detect
├── tabs/         # blocked.tsx — the explainable blocked page
└── popup.tsx     # toolbar popup: status, toggle, last blocked, last warning
```

## How this was built (process record)

Work proceeded through a brainstormed design spec and a task-by-task
implementation plan per milestone (see
`docs/superpowers/specs/` and `docs/superpowers/plans/`), executed with a
fresh implementer subagent per task and an independent reviewer per diff.
Notable verified decisions from that process:

- Scaffolded from the create-plasmo 0.90.5 template (driven through a
  PTY), adapted to the `src/` layout; pnpm 12 `allowBuilds` configured.
- DNR **session rules** (dynamic, toggle-friendly) over a static
  ruleset; **regex redirect with substitution** (preserves the original
  URL) over `requestDomains` + `extensionPath` (would lose it).
- Final whole-branch review hardened the blocked page: close affordance
  on every branch, and block claims verified against the bundled list
  before display/recording (anti content-spoofing).
- Phases 2–5: heuristic `atSymbol` weight raised to 0.35 after review
  math showed 0.12 could never warn alone; Firefox handled via
  capability-detected DNR backend (session vs dynamic) instead of UA
  sniffing; the TF.js dependency deferred — the on-device baseline model
  ships dependency-free behind the `PhishingModel` adapter (swap point
  for a real trained model).
