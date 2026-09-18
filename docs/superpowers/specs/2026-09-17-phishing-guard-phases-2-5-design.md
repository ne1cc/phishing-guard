# phishing-guard — Phases 2–5 Design Addendum

Date: 2026-09-17
Parent spec: `AGENTS.md`; Phase 1 design: `2026-09-17-phishing-guard-phase1-design.md`.
This addendum details Phases 2–5. Phase 1 is unchanged and continues to work as designed.

## Environment rulings (binding scope)

- **Ruling:** Firefox is not installed on this machine. Phase 3 ships code +
  firefox target builds + `web-ext lint` (automatable); interactive
  `web-ext run` verification is documented for the user, not faked.
  Cost if wrong: a Firefox-only API gap ships unverified — mitigated by
  lint + the feature-detection backend below.
- **Ruling:** full Xcode is absent (CommandLineTools only), so
  `safari-web-extension-converter` cannot run. Phase 4 ships the exact
  conversion procedure in README + TODO (unchecked), plus groundwork that
  de-risks Safari (rules-backend feature detection). Cost if wrong: none —
  no code claims Safari support it cannot have.
- **Ruling:** Phase 5 baseline model is a dependency-free logistic model
  over the Phase 2 feature vector with baked weights behind a
  `PhishingModel` adapter interface. TF.js is NOT added in this milestone:
  a ~2 MB dependency to multiply an 11-vector in a service worker is not
  justified until a real trained model exists; the adapter defines the
  swap-in point. Cost if wrong: revisiting = adding the dep + one adapter
  implementation.

## Phase 2 — Heuristic scoring (warn, never block)

`src/lib/heuristics.ts` (pure) computes an 11-feature vector from the URL
only — no page content, preserving the on-device/privacy guarantee:

| Feature | Meaning | Notes |
|---|---|---|
| `brandSimilarity` | 0/1 | typosquat (Levenshtein 1–2 vs brand token) or brand embedded in host without the brand's legit registrable domain |
| `punycode` | 0/1 | host contains `xn--` |
| `ipHost` | 0/1 | IPv4-literal host |
| `atSymbol` | 0/1 | `@` in URL before path/query |
| `suspiciousTld` | 0/1 | TLD in curated set (tk, ml, ga, cf, gq, xyz, top, buzz, …) |
| `hostEntropy` | 0–1 | Shannon entropy of hostname chars, normalized ((h−3.2)/1.3), clamped — common hostnames score 0 |
| `credentialPath` | 0/1 | path contains login/verify/secure/account/update/confirm/billing/webscr |
| `digitRatio` | 0–1 | digits / hostname length |
| `hyphenCount` | 0–1 | min(hyphens/4, 1) |
| `subdomainDepth` | 0–1 | min((labels−2)/4, 1) |
| `hostLength` | 0–1 | min(max(0, len−20)/30, 1) |

Weights (sum ×100, clamped 0–100): brandSimilarity .40, punycode .35,
ipHost .18, atSymbol .12, suspiciousTld .10, hostEntropy .10,
credentialPath .08, digitRatio .04, hyphenCount .04, subdomainDepth .04,
hostLength .01. `WARN_THRESHOLD = 35`.

- Brand list: ~24 high-value brands (`brand` → legit registrable domain);
  legit-domain suffix short-circuits to 0 (apple.com never warns on
  "apple"); typosquat compares Levenshtein (d ≤ 2) against the
  non-alphanumeric tokens of the registrable label, so
  `paypa1-support.com` → token `paypa1` → d=1 → flags.
- Delivery: `src/contents/warning-banner.ts` computes the score itself
  (pure import, no messaging), injects a dismissible fixed banner via
  shadow DOM (text only), and records a `WarnEvent` to
  `storage.local["lastWarned"]` when warning. Popup gains a
  "Last warning" section. `explain.ts` gains the warning reason builder.

## Phase 3 — Cross-browser port

- All shared code already goes through `webextension-polyfill`.
- **Ruling:** Firefox's DNR lacks session rules; Chrome/Safari have them.
  New `src/platform/rules-backend.ts` feature-detects
  (`"updateSessionRules" in declarativeNetRequest`) and `rules.ts` routes
  to `updateSessionRules` (Chrome/Safari) or `updateDynamicRules`
  (Firefox). This is the spec's `src/platform/<browser>.ts` escape hatch,
  implemented as capability detection instead of UA sniffing.
- Firefox manifest: `browser_specific_settings.gecko.id` via manifest
  override (env-var form `$FIREFOX_EXT_ID` if Plasmo per-target env
  works, else static `phishing-guard@n1ecc.dev`); gecko strict_min_version
  set to the first Firefox with DNR (113).
- Verification: `pnpm build --target=firefox-mv2` (fallback mv3 if mv2
  unsupported by Plasmo 0.90) + `web-ext lint` (new devDep) on the output;
  manual `web-ext run` documented for the user. Edge = chrome-mv3 build
  (same engine).

## Phase 4 — Safari

No code can be verified without Xcode. Deliverables: exact procedure in
README (install Xcode → `xcrun safari-web-extension-converter
build/chrome-mv3-prod --project-location ./safari --app-name "Phishing
guard" …`), TODO left unchecked, and the Phase 3 rules-backend already
covering Safari's DNR gaps. Any Safari-specific code later goes in
`src/platform/` per AGENTS.md.

## Phase 5 — On-device model (baseline)

- `src/models/logistic.ts` — `LogisticPhishingModel implements
  PhishingModel` where `PhishingModel { readonly name: string;
  score(features: HeuristicFeatures): number }` (0–100). Baked weights
  (brand 2.2, punycode 1.6, ip 1.2, at 1.0, tld 0.9, entropy 0.8,
  credential 0.7, digit 0.4, hyphen 0.4, depth 0.4, length 0.1, bias
  −3.2) → sigmoid → ×100. `MODEL_THRESHOLD = 55`.
- Decision: **warn if heuristic ≥ 35 OR model ≥ 55**; the banner shows
  both scores and the union of reasons. Blocked-page (blocklist) flow is
  untouched — the model only feeds warnings, never blocks.
- Swapping in a real trained TF.js model later = one new `PhishingModel`
  implementation + a loader in `src/models/`; no call-site changes.

## Error handling & privacy (unchanged invariants)

- Content script failures must never break the page: banner injection is
  wrapped in try/catch; score computation guarded.
- Still zero network calls; still zero page-content collection; warn
  events store URL/domain/scores/timestamp locally only.
