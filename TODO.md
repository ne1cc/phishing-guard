# TODO — phishing-guard

Mirrors the build phases in [AGENTS.md](AGENTS.md) section 5. Phase 1 is
code complete (unit tests and typecheck pass); every box below stays
unchecked until integration verification in a real browser, per AGENTS.md
section 6.

## Phase 1 — Blocklist MVP (Chrome only)

- [ ] Bundled blocklist of known-bad domains (`src/data/blocklist.json`,
      five RFC 2606 reserved test domains)
- [ ] DNR rule building: host-to-regex, main-frame redirect rules
      (`src/lib/blocklist.ts`)
- [ ] Background service worker syncs session rules with enable state
      (`src/background/rules.ts`, `src/background/index.ts`)
- [ ] Explainable blocked page: matched domain, source list, original URL
      (`src/tabs/blocked.tsx`, `src/lib/explain.ts`)
- [ ] Status popup: enable toggle, last blocked event (`src/popup.tsx`)
- [ ] Local-only storage for `enabled` and `lastBlocked`
      (`src/lib/storage.ts`)
- [ ] Unit tests pass (`pnpm test`, 13 tests) and `pnpm typecheck` is clean
- [ ] Integration verification in Chrome: load `build/chrome-mv3-prod`
      unpacked, confirm a test domain is blocked with a visible reason,
      confirm normal sites are untouched, and confirm no console errors

## Phase 2 — Heuristic scoring (Chrome only)

- [ ] Extract URL/domain features for domains not on the blocklist
      (TLD/entropy as domain-age proxy, suspicious subdomain patterns)
- [ ] Levenshtein distance to a short list of commonly-spoofed brand names
- [ ] Assign a risk score; above threshold warn (not hard-block) with the
      reason shown
- [ ] Done when hand-crafted lookalike URLs (e.g. `paypa1-secure.example.com`)
      are flagged and normal sites are not

## Phase 3 — Cross-browser port

- [ ] Confirm every API call goes through `browser.*` via
      `webextension-polyfill` (browser-specific code only in
      `src/platform/<browser>.ts`)
- [ ] Build and manually load into Firefox via `web-ext run`; fix API gaps
- [ ] Build and load into Edge (expected near-identical to Chrome)
- [ ] Verify Phase 1–2 behavior is unchanged on Chrome, Firefox, and Edge

## Phase 4 — Safari

- [ ] Run `safari-web-extension-converter` against the built extension
- [ ] Fix WKWebView extension-host gaps (DNR rule complexity, content
      script APIs — check current Safari release notes)
- [ ] Verify it loads and blocks via Safari's Extensions preferences

## Phase 5 — On-device ML (stretch)

- [ ] Load a small TensorFlow.js model in the background service worker or
      content script
- [ ] Feed it the Phase 2 heuristic feature vector as a baseline; replace
      with real model output once trained
- [ ] Verify the model score is used instead of/alongside the heuristic
      score, with no page content sent off-device

## Per-browser testing checklist

Repeat every phase, per AGENTS.md section 6:

- [ ] Load unpacked in Chrome (`chrome://extensions` → Developer mode → Load unpacked)
- [ ] Load temporarily in Firefox (`about:debugging` or `web-ext run`)
- [ ] Load unpacked in Edge (`edge://extensions`)
- [ ] (Phase 4+) Convert and run in Safari via Xcode
- [ ] Verify block/warn reason is shown correctly on each
- [ ] Verify no console errors specific to one browser
