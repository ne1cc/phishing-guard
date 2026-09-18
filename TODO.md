# TODO — phishing-guard

Mirrors the build phases in [AGENTS.md](AGENTS.md) section 5. Phases 1, 2,
3 (build-level), and 5 (baseline model) are code complete: unit tests,
typecheck, and builds pass. Remaining boxes need real browsers
(Chrome verification, Firefox `web-ext run`, Edge, Safari via Xcode).

## Phase 1 — Blocklist MVP (Chrome only)

- [x] Bundled blocklist of known-bad domains (`src/data/blocklist.json`,
      five RFC 2606 reserved test domains)
- [x] DNR rule building: host-to-regex, main-frame redirect rules
      (`src/lib/blocklist.ts`)
- [x] Background service worker syncs session rules with enable state
      (`src/background/rules.ts`, `src/background/index.ts`)
- [x] Explainable blocked page: matched domain, source list, original URL
      (`src/tabs/blocked.tsx`, `src/lib/explain.ts`)
- [x] Status popup: enable toggle, last blocked event (`src/popup.tsx`)
- [x] Local-only storage for `enabled` and `lastBlocked`
      (`src/lib/storage.ts`)
- [x] Unit tests pass (`pnpm test`, 13 tests) and `pnpm typecheck` is clean
- [ ] Integration verification in Chrome: load `build/chrome-mv3-prod`
      unpacked, confirm a test domain is blocked with a visible reason,
      confirm normal sites are untouched, and confirm no console errors

## Phase 2 — Heuristic scoring (Chrome only)

- [x] Extract URL/domain features for domains not on the blocklist
      (TLD/entropy as domain-age proxy, suspicious subdomain patterns) —
      `src/lib/heuristics.ts`, 11-feature vector
- [x] Levenshtein distance to a short list of commonly-spoofed brand names
      (typosquat + brand-embed signals; legit domains short-circuit)
- [x] Assign a risk score; above threshold warn (not hard-block) with the
      reason shown — `WARN_THRESHOLD = 35`, shadow-DOM banner in
      `src/contents/warning-banner.ts`, popup "Last warning"
- [ ] Done when hand-crafted lookalike URLs (e.g. `paypa1-secure.example.com`)
      are flagged and normal sites are not — unit-tested (35/35), manual
      Chrome verification pending

## Phase 3 — Cross-browser port

- [x] Confirm every API call goes through `browser.*` via
      `webextension-polyfill` (browser-specific capability code only in
      `src/platform/rules-backend.ts`)
- [x] Firefox build target builds clean and passes `web-ext lint`
      (0 errors); DNR backend auto-selects session (Chrome/Safari) vs
      dynamic (Firefox) rules
- [ ] Build and manually load into Firefox via `web-ext run`; fix API gaps
      (Firefox not installed on the dev machine)
- [ ] Build and load into Edge (expected near-identical to Chrome)
- [ ] Verify Phase 1–2 behavior is unchanged on Chrome, Firefox, and Edge

## Phase 4 — Safari

- [ ] Run `safari-web-extension-converter` against the built extension
      — BLOCKED: requires full Xcode (only CommandLineTools installed);
      procedure documented in README
- [ ] Fix WKWebView extension-host gaps (DNR rule complexity, content
      script APIs — check current Safari release notes)
- [ ] Verify it loads and blocks via Safari's Extensions preferences

## Phase 5 — On-device ML (stretch)

- [x] Model runs in the content script entirely on-device:
      `src/models/logistic.ts` — logistic regression over the same 11
      feature vector as Phase 2, behind the `PhishingModel` adapter
      (TF.js swap point; dependency deferred until a trained model exists)
- [x] Model score feeds warning decisions alongside the heuristic score
      (warn if either crosses its threshold); no page content sent
      off-device
- [ ] Replace baseline weights with a real trained TF.js model (stretch
      goal beyond the current milestone)

## Per-browser testing checklist

Repeat every phase, per AGENTS.md section 6:

- [ ] Load unpacked in Chrome (`chrome://extensions` → Developer mode → Load unpacked)
- [ ] Load temporarily in Firefox (`about:debugging` or `web-ext run`)
- [ ] Load unpacked in Edge (`edge://extensions`)
- [ ] (Phase 4+) Convert and run in Safari via Xcode
- [ ] Verify block/warn reason is shown correctly on each
- [ ] Verify no console errors specific to one browser
