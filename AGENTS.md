# AGENTS.md — Phishing Detection Browser Extension (Practice Project)

> This file also works as `CLAUDE.md` — copy or symlink it if your tooling
> specifically looks for that name. It's written so any coding agent (or you)
> can pick up this repo cold and know what to build, in what order, and how.

## 1. Project Context

This is a **practice project** that mirrors real internship work: a browser
extension that detects and blocks phishing/scam sites, in the style of
Nandi Security's Kavalan product line. Kavalan itself is a **DNS-level**
filtering service (blocks bad domains network-wide, at the router). This
extension is the **client-side complement** — it runs inside the browser and
catches things DNS-level filtering can't (new/unlisted phishing pages, pages
scored by content rather than domain reputation), using:

1. A static/updatable **blocklist** of known-bad domains (declarativeNetRequest)
2. **Heuristic scoring** of page/URL features not yet on any blocklist
3. (Stretch) **On-device ML inference** (TensorFlow.js) to score pages locally,
   with no page content ever leaving the user's machine

Target browsers, in priority order: **Chrome → Firefox → Edge → Safari**.
Chrome/Edge share an engine and manifest behavior almost exactly; Firefox
diverges on some MV3 APIs; Safari is the hardest port (native wrapper required).

## 2. Ground Rules for the Agent

- **Manifest V3 only.** Do not write MV2-style persistent background pages or
  blocking `webRequest` listeners — use `declarativeNetRequest` and service
  workers. MV2 patterns will silently fail or get rejected on Chrome Web Store.
- **Always go through `webextension-polyfill`.** Never call `chrome.*` APIs
  directly in shared code — call `browser.*` (the polyfill normalizes Chrome's
  callback API into the same promise-based shape Firefox/Safari use natively).
  Browser-specific code (if unavoidable) goes in a clearly named
  `src/platform/<browser>.ts` file, never inline in shared logic.
- **No telemetry, no remote calls with page content**, by default. If a
  feature needs a server round-trip, it must be justified in a comment and
  documented in `PRIVACY.md` — the product's whole pitch is "on-device."
- **Every blocking decision must be explainable.** If the extension blocks a
  page, the popup/notification must say why (matched blocklist entry vs.
  heuristic score vs. model score) — never a silent or unexplained block.
- **Commit small, testable units.** One PR = one capability (e.g. "add
  blocklist matching," not "add blocklist + scoring + UI").
- **Never commit secrets, API keys, or real threat-intel feed credentials.**
  Use `.env.local` (gitignored) for anything like that.

## 3. Tech Stack Decisions

| Concern | Choice | Why |
|---|---|---|
| Language | TypeScript | Extension APIs have good type defs; catches cross-browser API mismatches at compile time |
| Extension scaffolding | [Plasmo](https://www.plasmo.com/) | Handles MV3 boilerplate + multi-browser builds out of the box; fallback to raw manifest + webpack if Plasmo's abstractions get in the way |
| Cross-browser API shim | `webextension-polyfill` | Standard, well-maintained, promise-based `browser.*` everywhere |
| Blocking mechanism | `chrome.declarativeNetRequest` (MV3) | Required approach on Chrome/Edge; Firefox supports it as of 102+ |
| On-device ML (stretch) | TensorFlow.js | Runs in-extension, no server dependency, matches "on-device AI" positioning |
| Testing | Vitest (unit) + `web-ext` (manual load/test in Firefox) + Chrome's `chrome://extensions` load-unpacked | No good automated cross-browser E2E for extensions yet — plan for manual pass per browser per milestone |

## 4. Scaffold Steps (from zero)

```bash
# 1. Scaffold with Plasmo
pnpm create plasmo phishing-guard
cd phishing-guard

# 2. Core dependencies
pnpm add webextension-polyfill
pnpm add -D @types/webextension-polyfill vitest typescript

# 3. Folder structure (adjust Plasmo defaults toward this shape)
mkdir -p src/background src/content src/popup src/lib src/platform src/models
```

Target repo layout:

```
phishing-guard/
├── src/
│   ├── background/        # service worker: blocklist sync, message routing
│   ├── content/           # content scripts: page feature extraction, warning overlay
│   ├── popup/              # toolbar popup UI (status, toggle, last-blocked info)
│   ├── lib/
│   │   ├── blocklist.ts    # declarativeNetRequest rule management
│   │   ├── heuristics.ts   # URL/domain feature scoring (entropy, edit-distance to known brands, TLD flags)
│   │   └── explain.ts      # turns a block decision into a human-readable reason
│   ├── platform/           # browser-specific escape hatches, kept minimal
│   └── models/             # (stretch) TF.js model + feature-vector code
├── assets/
├── manifest.json           # generated per-target by Plasmo/build step
├── PRIVACY.md
└── AGENTS.md               # this file
```

## 5. Build Phases (do these in order — do not skip ahead)

### Phase 1 — Blocklist MVP (Chrome only)
- Load a static public phishing-domain list (e.g. OpenPhish/PhishTank export)
  into a `declarativeNetRequest` ruleset.
- Block navigation to matching domains; show a plain "blocked" page with the
  matched domain and source list.
- **Done when:** loading the unpacked extension in Chrome blocks a test
  domain you added to the list, and does nothing on all other sites.

### Phase 2 — Heuristic scoring (Chrome only)
- For domains *not* on the static list, extract simple URL features
  (domain age proxy via TLD/entropy, Levenshtein distance to a short list of
  commonly-spoofed brand names, suspicious subdomain patterns).
- Assign a risk score; above threshold → warn (don't hard-block) with the
  reason shown.
- **Done when:** a handful of hand-crafted "lookalike" test URLs (e.g.
  `paypa1-secure.example.com`) get flagged, and normal sites don't.

### Phase 3 — Cross-browser port
- Swap every `chrome.*` call for `browser.*` via the polyfill.
- Build and manually load into Firefox via `web-ext run`; fix API gaps.
- Build and load into Edge (should be near-identical to Chrome).
- **Done when:** Phases 1–2 behavior is verified working, unmodified in
  behavior, on Chrome/Firefox/Edge.

### Phase 4 — Safari (hardest, do last)
- Run Apple's `safari-web-extension-converter` against the built extension.
- Fix anything Safari's WKWebView-based extension host doesn't support
  (expect gaps in `declarativeNetRequest` rule complexity and some content
  script APIs — check current Safari release notes, this shifts often).
- **Done when:** it loads and blocks in Safari's Extensions preferences pane.

### Phase 5 — On-device ML (stretch)
- Only start this after Phases 1–3 are solid. Load a small TF.js model in
  the background service worker or content script; feed it the same feature
  vector used in Phase 2's heuristics as a baseline, replace with real
  model output once trained.
- **Done when:** the model's score is used instead of/alongside the
  heuristic score, with no page content sent off-device.

## 6. Per-Browser Testing Checklist (repeat every phase)

- [ ] Load unpacked in Chrome (`chrome://extensions` → Developer mode → Load unpacked)
- [ ] Load temporarily in Firefox (`about:debugging` or `web-ext run`)
- [ ] Load unpacked in Edge (`edge://extensions`)
- [ ] (Phase 4+) Convert and run in Safari via Xcode
- [ ] Verify block/warn reason is shown correctly on each
- [ ] Verify no console errors specific to one browser

## 7. What "Done" Looks Like for the Whole Project

A working extension that: blocks known-bad domains via a static list, warns
on heuristically-suspicious unlisted domains with a visible reason, runs
identically on Chrome/Firefox/Edge, and (stretch) scores pages with a local
TF.js model instead of pure heuristics — with zero page content leaving the
device at any point.
