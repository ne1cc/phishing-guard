# phishing-guard Phases 2–5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add heuristic warn-scoring (Phase 2), cross-browser DNR backends + Firefox builds (Phase 3), the Safari procedure (Phase 4), and an on-device baseline model feeding the warnings (Phase 5).

**Architecture:** Pure feature/scoring modules in `src/lib/heuristics.ts` and `src/models/`; a capability-detecting rules backend in `src/platform/`; a shadow-DOM warning banner content script; popup gains "last warning". Blocklist blocking (Phase 1) is untouched — heuristics/model only ever WARN.

**Tech Stack:** unchanged (Plasmo 0.90.5, TS, React 18, webextension-polyfill, Vitest, pnpm) + `web-ext` devDep for Firefox lint.

**Spec:** `docs/superpowers/specs/2026-09-17-phishing-guard-phases-2-5-design.md` (binding; environment rulings there are scope law).

## Global Constraints

- All browser APIs via `webextension-polyfill` (`browser.*`); browser-specific capability code ONLY in `src/platform/`.
- No network calls, no page-content collection. Banner text via `textContent` only.
- Style: no semicolons, double quotes, printWidth 80, trailingComma "none"; `pnpm exec prettier --write` touched files.
- Verify: `pnpm exec tsc --noEmit && pnpm test && pnpm build` (per task; full target matrix in Task 5).
- Conventional commits.

---

### Task 1: Heuristic engine (pure) + tests

**Files:**
- Create: `src/lib/heuristics.ts`
- Create: `src/lib/heuristics.test.ts`

**Interfaces (produced; later tasks import exactly):**
- `HeuristicFeatures` (11 numeric fields), `HeuristicResult { score: number; features: HeuristicFeatures; reasons: string[] }`
- `WARN_THRESHOLD = 35`, `extractFeatures(rawUrl: string): HeuristicFeatures`, `computeScore(features): number`, `scoreUrl(rawUrl: string): HeuristicResult`, `shouldWarn(result: HeuristicResult): boolean`, `levenshtein(a: string, b: string): number`

- [ ] **Step 1: Write `src/lib/heuristics.ts`**

```ts
export interface HeuristicFeatures {
  brandSimilarity: number
  punycode: number
  ipHost: number
  atSymbol: number
  suspiciousTld: number
  hostEntropy: number
  credentialPath: number
  digitRatio: number
  hyphenCount: number
  subdomainDepth: number
  hostLength: number
}

export interface HeuristicResult {
  score: number
  features: HeuristicFeatures
  reasons: string[]
}

export const WARN_THRESHOLD = 35

const SUSPICIOUS_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "buzz",
  "click",
  "link",
  "work",
  "rest",
  "fit",
  "cam",
  "cfd",
  "sbs"
])

const BRANDS: Array<[string, string]> = [
  ["paypal", "paypal.com"],
  ["chase", "chase.com"],
  ["wellsfargo", "wellsfargo.com"],
  ["apple", "apple.com"],
  ["icloud", "icloud.com"],
  ["microsoft", "microsoft.com"],
  ["office365", "office365.com"],
  ["outlook", "outlook.com"],
  ["google", "google.com"],
  ["gmail", "gmail.com"],
  ["amazon", "amazon.com"],
  ["netflix", "netflix.com"],
  ["coinbase", "coinbase.com"],
  ["binance", "binance.com"],
  ["whatsapp", "whatsapp.com"],
  ["instagram", "instagram.com"],
  ["facebook", "facebook.com"],
  ["linkedin", "linkedin.com"],
  ["steam", "steampowered.com"],
  ["roblox", "roblox.com"],
  ["dhl", "dhl.com"],
  ["fedex", "fedex.com"],
  ["usps", "usps.com"],
  ["irs", "irs.gov"],
  ["dropbox", "dropbox.com"]
]

const CREDENTIAL_WORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "confirm",
  "billing",
  "webscr"
]

const FEATURE_WEIGHTS: Record<keyof HeuristicFeatures, number> = {
  brandSimilarity: 0.4,
  punycode: 0.35,
  ipHost: 0.18,
  atSymbol: 0.35,
  suspiciousTld: 0.1,
  hostEntropy: 0.1,
  credentialPath: 0.08,
  digitRatio: 0.04,
  hyphenCount: 0.04,
  subdomainDepth: 0.04,
  hostLength: 0.01
}

export function levenshtein(a: string, b: string): number {
  if (a === b) {
    return 0
  }
  if (!a.length) {
    return b.length
  }
  if (!b.length) {
    return a.length
  }
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    const current = [i]
    for (let j = 1; j <= b.length; j++) {
      const substitution = previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      current.push(
        Math.min(previous[j] + 1, current[j - 1] + 1, substitution)
      )
    }
    previous = current
  }
  return previous[b.length]
}

function shannonEntropy(text: string): number {
  if (!text.length) {
    return 0
  }
  const counts = new Map<string, number>()
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / text.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

const clamp01 = (value: number) => Math.min(1, Math.max(0, value))

function registrableDomain(hostname: string): string {
  const labels = hostname.split(".")
  return labels.length <= 2 ? hostname : labels.slice(-2).join(".")
}

function brandSignal(hostname: string): { value: number; reason: string | null } {
  const registrable = registrableDomain(hostname)
  for (const [, legit] of BRANDS) {
    if (registrable === legit || registrable.endsWith(`.${legit}`)) {
      return { value: 0, reason: null }
    }
  }
  for (const [brand, legit] of BRANDS) {
    if (hostname.includes(brand)) {
      return {
        value: 1,
        reason: `hostname mentions "${brand}" but is not the official ${legit} domain`
      }
    }
  }
  const registrableLabel = registrable.split(".")[0]
  const tokens = registrableLabel.split(/[^a-z0-9]+/).filter(Boolean)
  let best: { brand: string; distance: number } | null = null
  for (const [brand] of BRANDS) {
    for (const token of tokens) {
      const distance = levenshtein(token, brand)
      if (distance >= 1 && distance <= 2 && (!best || distance < best.distance)) {
        best = { brand, distance }
      }
    }
  }
  if (best) {
    return {
      value: 1,
      reason: `hostname token resembles brand "${best.brand}" (edit distance ${best.distance})`
    }
  }
  return { value: 0, reason: null }
}

export function extractFeatures(rawUrl: string): HeuristicFeatures {
  const url = new URL(rawUrl)
  const host = url.hostname.toLowerCase()
  const path = url.pathname.toLowerCase()
  const labels = host.split(".")
  const tld = labels[labels.length - 1] ?? ""
  const brand = brandSignal(host)
  const digits = (host.match(/\d/g) ?? []).length
  const hyphens = (host.match(/-/g) ?? []).length
  return {
    brandSimilarity: brand.value,
    punycode: host.includes("xn--") ? 1 : 0,
    ipHost: /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ? 1 : 0,
    atSymbol: url.username !== "" ? 1 : 0,
    suspiciousTld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    hostEntropy: clamp01((shannonEntropy(host) - 3.2) / 1.3),
    credentialPath: CREDENTIAL_WORDS.some((word) => path.includes(word)) ? 1 : 0,
    digitRatio: clamp01(host.length ? digits / host.length : 0),
    hyphenCount: Math.min(hyphens / 4, 1),
    subdomainDepth: clamp01(Math.max(0, labels.length - 2) / 4),
    hostLength: clamp01(Math.max(0, host.length - 20) / 30)
  }
}

export function computeScore(features: HeuristicFeatures): number {
  let total = 0
  for (const key of Object.keys(FEATURE_WEIGHTS) as Array<
    keyof HeuristicFeatures
  >) {
    total += FEATURE_WEIGHTS[key] * features[key]
  }
  return Math.min(100, Math.round(total * 100))
}

function buildReasons(rawUrl: string, features: HeuristicFeatures): string[] {
  const reasons: string[] = []
  const brand = brandSignal(new URL(rawUrl).hostname.toLowerCase())
  if (brand.reason) {
    reasons.push(brand.reason)
  }
  if (features.punycode) {
    reasons.push("hostname uses punycode (xn--), which can disguise lookalike domains")
  }
  if (features.ipHost) {
    reasons.push("the site is served from a bare IP address")
  }
  if (features.atSymbol) {
    reasons.push("the URL contains a userinfo '@', a classic disguise trick")
  }
  if (features.suspiciousTld) {
    reasons.push("the domain uses a TLD commonly abused for phishing")
  }
  if (features.hostEntropy > 0) {
    reasons.push("the hostname looks randomly generated (high entropy)")
  }
  if (features.credentialPath) {
    reasons.push("the path contains credential-style words like login/verify/secure")
  }
  return reasons
}

export function scoreUrl(rawUrl: string): HeuristicResult {
  const features = extractFeatures(rawUrl)
  return {
    score: computeScore(features),
    features,
    reasons: buildReasons(rawUrl, features)
  }
}

export function shouldWarn(result: HeuristicResult): boolean {
  return result.score >= WARN_THRESHOLD
}
```

- [ ] **Step 2: Write `src/lib/heuristics.test.ts`**

```ts
import { describe, expect, it } from "vitest"
import {
  WARN_THRESHOLD,
  computeScore,
  extractFeatures,
  levenshtein,
  scoreUrl,
  shouldWarn
} from "./heuristics"

describe("levenshtein", () => {
  it("measures edit distance", () => {
    expect(levenshtein("paypa1", "paypal")).toBe(1)
    expect(levenshtein("gooogle", "google")).toBe(1)
    expect(levenshtein("github", "github")).toBe(0)
    expect(levenshtein("", "abc")).toBe(3)
  })
})

describe("scoreUrl on normal sites", () => {
  it("scores known-good sites at zero", () => {
    expect(scoreUrl("https://www.google.com/").score).toBe(0)
    expect(scoreUrl("https://github.com/lex").score).toBe(0)
    expect(scoreUrl("https://apple.com/mac/").score).toBe(0)
  })

  it("does not warn on a bare-IP internal host alone", () => {
    const result = scoreUrl("http://192.168.1.1/admin")
    expect(result.features.ipHost).toBe(1)
    expect(shouldWarn(result)).toBe(false)
  })
})

describe("scoreUrl on suspicious sites", () => {
  it("flags a brand typosquat with a credential path", () => {
    const result = scoreUrl("https://paypa1-support.com/login")
    expect(result.features.brandSimilarity).toBe(1)
    expect(result.reasons.join(" ")).toContain('resembles brand "paypal"')
    expect(shouldWarn(result)).toBe(true)
  })

  it("flags an embedded brand on an unofficial domain", () => {
    const result = scoreUrl("https://secure-chase-verify.net/")
    expect(result.features.brandSimilarity).toBe(1)
    expect(result.features.credentialPath).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })

  it("flags punycode hosts on their own", () => {
    const result = scoreUrl("https://xn--80ak6aa92e.com/")
    expect(result.features.punycode).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })

  it("treats the real brand domain as safe even with credential paths", () => {
    const result = scoreUrl("https://www.paypal.com/signin")
    expect(result.features.brandSimilarity).toBe(0)
    expect(shouldWarn(result)).toBe(false)
  })

  it("flags a userinfo '@' with a spoofed display host", () => {
    const result = scoreUrl("https://google.com@evil-example.io/")
    expect(result.features.atSymbol).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })
})

describe("computeScore", () => {
  it("is zero for an all-zero feature vector", () => {
    const zero = extractFeatures("https://www.google.com/")
    expect(computeScore({ ...zero })).toBe(0)
  })

  it("caps at 100", () => {
    const maxed = {
      brandSimilarity: 1,
      punycode: 1,
      ipHost: 1,
      atSymbol: 1,
      suspiciousTld: 1,
      hostEntropy: 1,
      credentialPath: 1,
      digitRatio: 1,
      hyphenCount: 1,
      subdomainDepth: 1,
      hostLength: 1
    }
    expect(computeScore(maxed)).toBe(100)
  })
})

describe("threshold", () => {
  it("is 35", () => {
    expect(WARN_THRESHOLD).toBe(35)
  })
})
```

- [ ] **Step 3: Verify** — `pnpm exec tsc --noEmit && pnpm test` (16 + 9 = 25 passing expected; if a hand-computed threshold case lands within a point of the boundary due to entropy rounding, adjust the TEST URL, never the weights).
- [ ] **Step 4: Commit** — `feat: add URL heuristic scoring engine with tests`

### Task 2: Warning delivery — content script, storage, popup, explain

**Files:**
- Modify: `src/lib/types.ts` (add `WarnEvent`)
- Modify: `src/lib/storage.ts` (add `lastWarned` accessors)
- Modify: `src/lib/explain.ts` (add warning reason builder)
- Create: `src/contents/warning-banner.ts`
- Modify: `src/popup.tsx` (add "Last warning" section)

**Interfaces:**
- Consumes Task 1's `scoreUrl`, `shouldWarn`, `WARN_THRESHOLD`, `HeuristicFeatures`.
- Produces: `WarnEvent { url: string; domain: string; heuristicScore: number; modelScore: number; reasons: string[]; warnedAt: number }` (types.ts), `getLastWarned(): Promise<WarnEvent | null>`, `recordWarnEvent(event: WarnEvent): Promise<void>` (storage.ts), `explainHeuristicWarning(reasons: string[], heuristicScore: number, modelScore: number): string` (explain.ts). `modelScore` is part of the schema now (Task 4 fills it; Task 2 passes 0).

- [ ] **Step 1: types.ts — append**

```ts
export interface WarnEvent {
  url: string
  domain: string
  heuristicScore: number
  modelScore: number
  reasons: string[]
  warnedAt: number
}
```

- [ ] **Step 2: storage.ts — add key, accessors, guard** (`LAST_WARNED_KEY = "lastWarned"`; `getLastWarned(): Promise<WarnEvent | null>`; `recordWarnEvent(event: WarnEvent): Promise<void>`; `isWarnEvent` guard checking url/domain strings, numeric scores/warnedAt, and `Array.isArray(reasons) && reasons.every((r) => typeof r === "string")` — same shape as `isBlockEvent`.)

- [ ] **Step 3: explain.ts — add**

```ts
export function explainHeuristicWarning(
  reasons: string[],
  heuristicScore: number,
  modelScore: number
): string {
  const lead = `Phishing guard finds this site suspicious (heuristic risk ${heuristicScore}/100, model risk ${modelScore}/100).`
  if (!reasons.length) {
    return `${lead} Multiple weak signals combined.`
  }
  return `${lead} Why: ${reasons.join("; ")}.`
}
```

- [ ] **Step 4: Write `src/contents/warning-banner.ts`** — Plasmo content script (default matches). All text via `textContent`; banner in a shadow root so page CSS can't restyle it; failures logged, never thrown.

```ts
import { explainHeuristicWarning } from "~/lib/explain"
import { shouldWarn, scoreUrl, WARN_THRESHOLD } from "~/lib/heuristics"
import { recordWarnEvent } from "~/lib/storage"
import { getModel } from "~/models"

const BANNER_ID = "phishing-guard-banner"

function evaluate(url: string) {
  const heuristic = scoreUrl(url)
  const modelScore = getModel().score(heuristic.features)
  return {
    heuristic,
    modelScore,
    warn: shouldWarn(heuristic) || modelScore >= MODEL_THRESHOLD
  }
}

function injectBanner(reasons: string[], heuristicScore: number, modelScore: number): void {
  if (document.getElementById(BANNER_ID)) {
    return
  }
  const host = document.createElement("div")
  host.id = BANNER_ID
  const shadow = host.attachShadow({ mode: "open" })
  const bar = document.createElement("div")
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b3261e;color:#fff;font:14px/1.45 system-ui,sans-serif;padding:12px 16px;display:flex;gap:12px;align-items:flex-start;box-shadow:0 2px 8px rgba(0,0,0,0.35)"
  const text = document.createElement("div")
  text.style.cssText = "flex:1;min-width:0;word-break:break-word"
  const title = document.createElement("strong")
  title.textContent = "Phishing guard: this site looks suspicious"
  const body = document.createElement("div")
  body.textContent = explainHeuristicWarning(reasons, heuristicScore, modelScore)
  text.append(title, body)
  const dismiss = document.createElement("button")
  dismiss.type = "button"
  dismiss.textContent = "Dismiss"
  dismiss.style.cssText =
    "background:rgba(255,255,255,0.18);color:#fff;border:1px solid rgba(255,255,255,0.5);border-radius:6px;padding:6px 12px;font:inherit;cursor:pointer"
  dismiss.addEventListener("click", () => host.remove())
  bar.append(text, dismiss)
  shadow.append(bar)
  document.documentElement.append(host)
}

const verdict = evaluate(window.location.href)
if (verdict.warn) {
  try {
    injectBanner(verdict.heuristic.reasons, verdict.heuristic.score, verdict.modelScore)
    void recordWarnEvent({
      url: window.location.href,
      domain: window.location.hostname,
      heuristicScore: verdict.heuristic.score,
      modelScore: verdict.modelScore,
      reasons: verdict.heuristic.reasons,
      warnedAt: Date.now()
    })
  } catch (error) {
    console.error("[phishing-guard] failed to show warning banner", error)
  }
}
```

Note: `MODEL_THRESHOLD` comes from `~/models` (Task 4 defines it as 55; until then this file will not typecheck — that is expected mid-branch; Tasks 2 and 4 may be implemented in either order but the branch must typecheck after both). To keep every commit green, Task 2 creates a minimal `src/models/index.ts` exporting `getModel()` returning a stub model scoring 0 and `MODEL_THRESHOLD = 55`; Task 4 replaces the stub with the real logistic model.

- [ ] **Step 5: Create stub `src/models/index.ts`** (Task 4 replaces):

```ts
import type { HeuristicFeatures } from "~/lib/heuristics"

export interface PhishingModel {
  readonly name: string
  score(features: HeuristicFeatures): number
}

export const MODEL_THRESHOLD = 55

const STUB_MODEL: PhishingModel = {
  name: "stub",
  score: () => 0
}

export function getModel(): PhishingModel {
  return STUB_MODEL
}
```

- [ ] **Step 6: popup.tsx — add `lastWarned` state + "Last warning" section** below "Last blocked" (same read-on-mount pattern via `getLastWarned()`; shows domain, `heuristic {score}/100 · model {score}/100`, timestamp; empty text "No warnings yet.").
- [ ] **Step 7: Verify** — `pnpm exec tsc --noEmit && pnpm test && pnpm build` (build must emit a content script: `build/chrome-mv3-prod/manifest.json` gains `content_scripts`).
- [ ] **Step 8: Commit** — `feat: warn on suspicious URLs via content-script banner with popup history`

### Task 3: Cross-browser rules backend + Firefox build

**Files:**
- Create: `src/platform/rules-backend.ts`
- Modify: `src/background/rules.ts` (route through backend)
- Modify: `package.json` (gecko settings via env var, `web-ext` devDep, `lint:firefox` script)
- Create: `.env.firefox-mv2` (or the per-target file Plasmo actually loads — verify empirically)

**Interfaces:**
- Produces: `type RulesBackend = "session" | "dynamic"`, `detectRulesBackend(dnr: typeof browser.declarativeNetRequest): RulesBackend` — capability detection: `"updateSessionRules" in dnr && typeof (dnr as …).updateSessionRules === "function"`. If `@types/webextension-polyfill` lacks session-rule typings (Firefox schema), adapt with a local structural type in `src/platform/` — the escape-hatch file; never widen lib types.

- [ ] **Step 1: rules-backend.ts** — detection as above.
- [ ] **Step 2: rules.ts** — `const backend = detectRulesBackend(browser.declarativeNetRequest)`; disabled path clears via `removeRules of that backend`; enabled path adds via that backend. Both paths stay inside the existing try/catch.
- [ ] **Step 3: Firefox manifest** — manifest override gains `"browser_specific_settings": { "gecko": { "id": "$FIREFOX_EXT_ID", "strict_min_version": "113.0" } }`; create the env file Plasmo loads for the firefox target (try `.env.firefox-mv2` with `FIREFOX_EXT_ID=phishing-guard@n1ecc.dev`). Verify: `pnpm build --target=firefox-mv2` output manifest contains the gecko id AND the chrome build's manifest does NOT (env var absent → field removed). If per-target env doesn't work, fall back to the static id and note Chrome's "unrecognized key" warning is cosmetic.
- [ ] **Step 4: web-ext** — `pnpm add -D web-ext`; script `"lint:firefox": "web-ext lint --source-dir build/firefox-mv2"`. Run it; resolve only **errors** (warnings acceptable, list them in the report).
- [ ] **Step 5: Verify** — `pnpm exec tsc --noEmit && pnpm test && pnpm build && pnpm build --target=firefox-mv2 && pnpm run lint:firefox`; confirm chrome manifest unchanged apart from nothing (gecko block absent).
- [ ] **Step 6: Commit** — `feat: add capability-detected DNR rules backend and Firefox build config`

### Task 4: On-device baseline model (Phase 5)

**Files:**
- Modify: `src/models/index.ts` (real model, keep `PhishingModel`/`MODEL_THRESHOLD`/`getModel` exports)
- Create: `src/models/logistic.ts`
- Create: `src/models/logistic.test.ts`
- Modify: `src/contents/warning-banner.ts` (no changes expected — it already consumes `getModel()`)

**Interfaces:**
- Consumes: `HeuristicFeatures` from `~/lib/heuristics`.
- Produces: `LogisticPhishingModel implements PhishingModel` (name `"logistic-baseline-v1"`), same `getModel(): PhishingModel` signature — call sites unchanged.

- [ ] **Step 1: `src/models/logistic.ts`**

```ts
import type { HeuristicFeatures } from "~/lib/heuristics"
import type { PhishingModel } from "./index"

const WEIGHTS: Array<[keyof HeuristicFeatures, number]> = [
  ["brandSimilarity", 2.2],
  ["punycode", 1.6],
  ["ipHost", 1.2],
  ["atSymbol", 1.0],
  ["suspiciousTld", 0.9],
  ["hostEntropy", 0.8],
  ["credentialPath", 0.7],
  ["digitRatio", 0.4],
  ["hyphenCount", 0.4],
  ["subdomainDepth", 0.4],
  ["hostLength", 0.1]
]

const BIAS = -3.2

export class LogisticPhishingModel implements PhishingModel {
  readonly name = "logistic-baseline-v1"

  score(features: HeuristicFeatures): number {
    let z = BIAS
    for (const [key, weight] of WEIGHTS) {
      z += weight * features[key]
    }
    return Math.round(100 / (1 + Math.exp(-z)))
  }
}
```

- [ ] **Step 2: `src/models/index.ts`** — replace stub body with `export function getModel(): PhishingModel { return new LogisticPhishingModel() }`; keep `PhishingModel` and `MODEL_THRESHOLD` exports; add a doc-free re-export `export type { PhishingModel } from "./logistic"`? No — keep the interface defined in `index.ts` (logistic imports it from there; avoid circular type imports by leaving `PhishingModel` where it is).
- [ ] **Step 3: `src/models/logistic.test.ts`** — exact sigmoid math: all-zero features → 4; brandSimilarity only → 27; brandSimilarity + punycode → 65 (crosses `MODEL_THRESHOLD` 55); a realistic suspicious URL (`https://paypa1-support.com/login` via `extractFeatures`) scores above the stub-warning bar and equals `new LogisticPhishingModel().score(extractFeatures(...))`.
- [ ] **Step 4: Verify** — `pnpm exec tsc --noEmit && pnpm test && pnpm build`.
- [ ] **Step 5: Commit** — `feat: add on-device logistic baseline model to warning decisions`

### Task 5: Docs + integration verification (controller)

- [ ] README: phase table (2 done, 3 code-complete/build-verified with manual Firefox steps documented, 4 procedure documented, 5 baseline done), "How a warning happens" section mirroring the block flow, note the logistic-model ruling + TF.js swap path.
- [ ] TODO.md: Phase 2–5 checkboxes updated to actual verification state; Phase 4 left unchecked with the Xcode blocker noted.
- [ ] PRIVACY.md: storage inventory gains `lastWarned`.
- [ ] Full matrix: `pnpm exec tsc --noEmit && pnpm test && pnpm build && pnpm build --target=firefox-mv2 && pnpm run lint:firefox && pnpm exec prettier --check src README.md PRIVACY.md TODO.md`.
- [ ] Final whole-branch review, fix wave, ledger closure.

## Self-Review

- **Spec coverage:** heuristic features/weights/threshold (T1 ↔ spec table, entropy normalization matches the corrected spec line), warn-not-block delivery + storage + popup (T2), platform escape hatch + gecko manifest + lint (T3), model adapter + thresholds + call-site stability (T4), Safari procedure + docs (T5). Environment rulings from the spec are enforced as scope law in T3/T5.
- **Placeholder scan:** all code complete; the only intentional stub (models stub in T2) is explicitly replaced in T4 and exists to keep each commit green.
- **Type consistency:** `WarnEvent` fields used by T2 storage/popup match; `PhishingModel`/`getModel`/`MODEL_THRESHOLD` names identical across T2 stub, T4 real model, and banner import; `detectRulesBackend` returns `"session" | "dynamic"` consumed by `rules.ts` only.
