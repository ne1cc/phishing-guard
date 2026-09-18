# phishing-guard Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Phase 1 (Blocklist MVP): a Plasmo MV3 extension that blocks bundled blocklist domains via `declarativeNetRequest` session rules and shows an explainable blocked page.

**Architecture:** Thin Plasmo entries (`src/background/index.ts`, `src/popup.tsx`, `src/tabs/blocked.tsx`) over pure logic modules in `src/lib/` (rule building, param parsing, explain copy) plus impure glue (`src/lib/storage.ts`, `src/background/rules.ts`). DNR rules redirect main-frame requests to `tabs/blocked.html?source=<name>&url=<original>`, keeping every block explainable.

**Tech Stack:** TypeScript, Plasmo 0.90.5, React 18, `webextension-polyfill`, Vitest, pnpm 12.

**Spec:** `docs/superpowers/specs/2026-09-17-phishing-guard-phase1-design.md` (read together with this plan; the plan argues from the spec).

## Global Constraints

- Manifest V3 only; no MV2 persistent background pages or blocking `webRequest`.
- All browser API calls via `webextension-polyfill` default import `browser from "webextension-polyfill"` — never raw `chrome.*`.
- No telemetry, no network calls; page content never leaves the device.
- Every block must show its reason (source list attribution).
- Code style: repo `.prettierrc.mjs` — no semicolons, double quotes, printWidth 80, trailingComma "none". Run `pnpm exec prettier --write <files>` before finishing each task.
- Import alias: `~/` maps to `src/` (tsconfig + vitest alias).
- Verify with: `pnpm exec tsc --noEmit`, `pnpm test`, `pnpm build`.
- Never commit secrets; no `.env` files in this phase.

---

### Task 0: Scaffold (COMPLETED — do not redo)

Plasmo 0.90.5 template adapted to `src/` layout; `pnpm-workspace.yaml` `allowBuilds` for native deps; tsconfig `~*` → `./src/*`; package.json `manifest` override with `permissions: ["declarativeNetRequest", "storage"]`, `host_permissions: ["<all_urls>"]`, `web_accessible_resources: ["tabs/blocked.html"]`; deps `webextension-polyfill@0.12.0`, `vitest@3.2.4`. Verified: `pnpm build` → `build/chrome-mv3-prod/manifest.json` contains merged keys. Committed at `4e78126`, `229620a`.

### Task 1: Pure lib modules, blocklist data, vitest setup + tests

**Files:**
- Create: `src/lib/types.ts`
- Create: `src/data/blocklist.json`
- Create: `src/lib/blocklist.ts`
- Create: `src/lib/explain.ts`
- Create: `src/lib/blocklist.test.ts`
- Create: `src/lib/explain.test.ts`
- Create: `vitest.config.ts`
- Modify: `tsconfig.json` (add `"resolveJsonModule": true` to `compilerOptions`)

**Interfaces:**
- Consumes: nothing (pure modules, no browser API imports).
- Produces (later tasks import these exact names):
  - `types.ts`: `interface BlocklistEntry { domain: string; source: string; note?: string }`, `interface BlockEvent { url: string; domain: string; source: string; blockedAt: number }`, `interface DnrRule { id: number; priority: number; condition: { regexFilter: string; resourceTypes: Array<"main_frame"> }; action: { type: "redirect"; redirect: { regexSubstitution: string } } }`
  - `blocklist.ts`: `RULE_TAG = "phishing-guard-blocklist"`, `BLOCKED_PAGE_PATH = "tabs/blocked.html"`, `hostToRegexPattern(domain: string): string`, `buildRules(entries: readonly BlocklistEntry[], blockedPageBaseUrl: string, startId?: number): DnrRule[]`, `parseBlockedPageParams(search: string): { source: string; url: string } | null`
  - `explain.ts`: `explainBlocklistMatch(entry: Pick<BlocklistEntry, "domain" | "source">): string`, `explainUnknownBlock(): string`

- [ ] **Step 1: Write `src/lib/types.ts`**

```ts
export interface BlocklistEntry {
  domain: string
  source: string
  note?: string
}

export interface BlockEvent {
  url: string
  domain: string
  source: string
  blockedAt: number
}

export interface DnrRule {
  id: number
  priority: number
  condition: {
    regexFilter: string
    resourceTypes: Array<"main_frame">
  }
  action: {
    type: "redirect"
    redirect: { regexSubstitution: string }
  }
}
```

- [ ] **Step 2: Write `src/data/blocklist.json`** — all domains under RFC 2606 reserved names so no real site can be affected.

```json
[
  {
    "domain": "paypa1-secure.example.com",
    "source": "bundled-test-list",
    "note": "PayPal lookalike used for testing; RFC 2606 reserved domain."
  },
  {
    "domain": "secure-chase-online.example",
    "source": "bundled-test-list",
    "note": "Fake banking login page used for testing."
  },
  {
    "domain": "appleid-verify.example.net",
    "source": "bundled-test-list",
    "note": "Fake Apple ID verification page used for testing."
  },
  {
    "domain": "login-microsoft-secure.example.org",
    "source": "bundled-test-list",
    "note": "Fake Microsoft login page used for testing."
  },
  {
    "domain": "crypto-doubler-bonus.example.org",
    "source": "bundled-test-list",
    "note": "Fake crypto giveaway page used for testing."
  }
]
```

- [ ] **Step 3: Write `src/lib/blocklist.ts`**

```ts
import type { BlocklistEntry, DnrRule } from "./types"

export const RULE_TAG = "phishing-guard-blocklist"
export const BLOCKED_PAGE_PATH = "tabs/blocked.html"

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g

export function hostToRegexPattern(domain: string): string {
  const escaped = domain.replace(REGEX_SPECIALS, "\\$&")
  return `^(https?://(?:[^/]*\\.)?${escaped}(?::\\d+)?(?:[/?].*)?)$`
}

export function buildRules(
  entries: readonly BlocklistEntry[],
  blockedPageBaseUrl: string,
  startId = 1
): DnrRule[] {
  return entries.map((entry, index) => ({
    id: startId + index,
    priority: 1,
    condition: {
      regexFilter: hostToRegexPattern(entry.domain),
      resourceTypes: ["main_frame"]
    },
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution: `${blockedPageBaseUrl}?source=${encodeURIComponent(
          entry.source
        )}&url=\\1`
      }
    }
  }))
}

export interface BlockedPageParams {
  source: string
  url: string
}

export function parseBlockedPageParams(
  search: string
): BlockedPageParams | null {
  const raw = search.startsWith("?") ? search.slice(1) : search
  const marker = "&url="
  const markerIndex = raw.indexOf(marker)
  if (markerIndex === -1) {
    return null
  }
  const sourcePart = raw.slice(0, markerIndex)
  if (!sourcePart.startsWith("source=")) {
    return null
  }
  const source = decodeURIComponent(sourcePart.slice("source=".length))
  const url = raw.slice(markerIndex + marker.length)
  if (!source || !url) {
    return null
  }
  return { source, url }
}
```

Design notes for the implementer: the redirect substitution relies on `regexFilter` capture group 1 holding the full original URL — that is why `hostToRegexPattern` wraps the whole match in `(...)`. The original URL is placed **last** in the query so its raw `&`/`?` characters cannot corrupt `source` parsing. URL is never rendered as HTML.

- [ ] **Step 4: Write `src/lib/explain.ts`**

```ts
import type { BlocklistEntry } from "./types"

export function explainBlocklistMatch(
  entry: Pick<BlocklistEntry, "domain" | "source">
): string {
  return `This page was blocked because the domain "${entry.domain}" appears in the "${entry.source}" blocklist of known phishing and scam sites.`
}

export function explainUnknownBlock(): string {
  return "This request was blocked by Phishing guard. No matching rule details were provided."
}
```

- [ ] **Step 5: Write `vitest.config.ts`**

```ts
import path from "node:path"
import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"]
  },
  resolve: {
    alias: {
      "~": path.resolve(__dirname, "src")
    }
  }
})
```

- [ ] **Step 6: Write `src/lib/blocklist.test.ts`**

```ts
import { describe, expect, it } from "vitest"
import { BLOCKED_PAGE_PATH, buildRules, hostToRegexPattern, parseBlockedPageParams } from "./blocklist"
import type { BlocklistEntry } from "./types"

const entry: BlocklistEntry = {
  domain: "paypa1-secure.example.com",
  source: "bundled-test-list"
}

describe("hostToRegexPattern", () => {
  it("escapes regex specials in the domain", () => {
    expect(hostToRegexPattern("a.b.example.com")).toBe(
      "^(https?://(?:[^/]*\\.)?a\\.b\\.example\\.com(?::\\d+)?(?:[/?].*)?)$"
    )
  })
})

describe("buildRules", () => {
  const base = `chrome-extension://test-id/${BLOCKED_PAGE_PATH}`

  it("assigns deterministic ids and main_frame resource type", () => {
    const [rule] = buildRules([entry], base)
    expect(rule.id).toBe(1)
    expect(rule.priority).toBe(1)
    expect(rule.condition.resourceTypes).toEqual(["main_frame"])
    expect(rule.action.type).toBe("redirect")
  })

  it("builds a substitution with source attribution and url capture group", () => {
    const [rule] = buildRules([entry], base)
    expect(rule.action.redirect.regexSubstitution).toBe(
      `${base}?source=bundled-test-list&url=\\1`
    )
  })

  it("respects startId for deterministic ranges", () => {
    const rules = buildRules([entry, { ...entry, domain: "b.example.com" }], base, 10)
    expect(rules.map((r) => r.id)).toEqual([10, 11])
  })
})

describe("blocklist regex matching", () => {
  const pattern = new RegExp(hostToRegexPattern("paypa1-secure.example.com"))

  const matches = (url: string) => {
    const result = pattern.exec(url)
    return result ? result[1] : null
  }

  it("matches the listed domain over https and http", () => {
    expect(matches("https://paypa1-secure.example.com")).toBe(
      "https://paypa1-secure.example.com"
    )
    expect(matches("http://paypa1-secure.example.com/")).toBe(
      "http://paypa1-secure.example.com/"
    )
  })

  it("matches paths, queries, ports, and deep subdomains", () => {
    expect(matches("https://paypa1-secure.example.com/login?next=%2F")).not.toBeNull()
    expect(matches("https://paypa1-secure.example.com:8443/x")).not.toBeNull()
    expect(matches("https://a.b.paypa1-secure.example.com/")).not.toBeNull()
  })

  it("does not match lookalike or suffixed hosts", () => {
    expect(matches("https://notpaypa1-secure.example.com/")).toBeNull()
    expect(matches("https://paypa1-secure.example.com.evil.io/")).toBeNull()
    expect(matches("https://paypa1-secure.example.comic.org/")).toBeNull()
    expect(matches("https://example.org/")).toBeNull()
  })

  it("does not match non-http schemes", () => {
    expect(matches("ftp://paypa1-secure.example.com/")).toBeNull()
  })
})

describe("parseBlockedPageParams", () => {
  it("parses source and raw url when url contains separators", () => {
    const parsed = parseBlockedPageParams(
      "?source=bundled-test-list&url=https://paypa1-secure.example.com/login?next=%2Fx&more=1"
    )
    expect(parsed).toEqual({
      source: "bundled-test-list",
      url: "https://paypa1-secure.example.com/login?next=%2Fx&more=1"
    })
  })

  it("decodes the source", () => {
    const parsed = parseBlockedPageParams("?source=my%20list&url=https://x.example/")
    expect(parsed?.source).toBe("my list")
  })

  it("returns null when url or source is missing", () => {
    expect(parseBlockedPageParams("?source=bundled-test-list")).toBeNull()
    expect(parseBlockedPageParams("?url=https://x.example/")).toBeNull()
    expect(parseBlockedPageParams("")).toBeNull()
  })
})
```

- [ ] **Step 7: Write `src/lib/explain.test.ts`**

```ts
import { describe, expect, it } from "vitest"
import { explainBlocklistMatch, explainUnknownBlock } from "./explain"

describe("explainBlocklistMatch", () => {
  it("names the domain and the source list", () => {
    const reason = explainBlocklistMatch({
      domain: "paypa1-secure.example.com",
      source: "bundled-test-list"
    })
    expect(reason).toContain("paypa1-secure.example.com")
    expect(reason).toContain("bundled-test-list")
    expect(reason).toContain("phishing")
  })
})

describe("explainUnknownBlock", () => {
  it("returns a non-empty generic reason", () => {
    expect(explainUnknownBlock().length).toBeGreaterThan(0)
  })
})
```

- [ ] **Step 8: Add `"resolveJsonModule": true` to `tsconfig.json` `compilerOptions`** (keep existing keys).

- [ ] **Step 9: Run tests + typecheck**

Run: `pnpm test && pnpm exec tsc --noEmit`
Expected: all tests PASS, typecheck clean.

- [ ] **Step 10: Commit**

```bash
git add src/lib src/data vitest.config.ts tsconfig.json
git commit -m "feat: add blocklist rule building, param parsing, and explain copy with tests"
```

### Task 2: Impure glue — storage accessors + background service worker

**Files:**
- Create: `src/lib/storage.ts`
- Create: `src/background/rules.ts`
- Create: `src/background/index.ts`

**Interfaces:**
- Consumes: `BlocklistEntry`, `BlockEvent`, `DnrRule`, `buildRules`, `BLOCKED_PAGE_PATH`, `RULE_TAG` from `~/lib/*` (Task 1); `blocklist.json` import (default export: `BlocklistEntry[]`).
- Produces:
  - `src/lib/storage.ts`: `getEnabled(): Promise<boolean>`, `setEnabled(value: boolean): Promise<void>`, `getLastBlocked(): Promise<BlockEvent | null>`, `recordBlockEvent(event: BlockEvent): Promise<void>`
  - `src/background/rules.ts`: `syncBlocklistRules(): Promise<void>` — idempotent; reapplies or clears session rules from stored enabled state.
  - `src/background/index.ts`: Plasmo background entry; message contract `{ type: "setEnabled"; value: boolean }` → responds `{ enabled: boolean }`.

- [ ] **Step 1: Write `src/lib/storage.ts`**

```ts
import browser from "webextension-polyfill"
import type { BlockEvent } from "./types"

const ENABLED_KEY = "enabled"
const LAST_BLOCKED_KEY = "lastBlocked"

export async function getEnabled(): Promise<boolean> {
  const stored = await browser.storage.local.get(ENABLED_KEY)
  return stored[ENABLED_KEY] !== false
}

export async function setEnabled(value: boolean): Promise<void> {
  await browser.storage.local.set({ [ENABLED_KEY]: value })
}

export async function getLastBlocked(): Promise<BlockEvent | null> {
  const stored = await browser.storage.local.get(LAST_BLOCKED_KEY)
  const event = stored[LAST_BLOCKED_KEY]
  return isBlockEvent(event) ? event : null
}

export async function recordBlockEvent(event: BlockEvent): Promise<void> {
  await browser.storage.local.set({ [LAST_BLOCKED_KEY]: event })
}

function isBlockEvent(value: unknown): value is BlockEvent {
  if (typeof value !== "object" || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.url === "string" &&
    typeof candidate.domain === "string" &&
    typeof candidate.source === "string" &&
    typeof candidate.blockedAt === "number"
  )
}
```

- [ ] **Step 2: Write `src/background/rules.ts`**

```ts
import browser from "webextension-polyfill"
import blocklist from "~/data/blocklist.json"
import { BLOCKED_PAGE_PATH, buildRules } from "~/lib/blocklist"
import { getEnabled } from "~/lib/storage"
import type { DnrRule } from "~/lib/types"

type UpdateSessionRulesArgs = Parameters<
  typeof browser.declarativeNetRequest.updateSessionRules
>[0]

export async function syncBlocklistRules(): Promise<void> {
  const enabled = await getEnabled()
  const existing = await browser.declarativeNetRequest.getSessionRules()
  const existingIds = existing.map((rule) => rule.id)
  if (!enabled) {
    await browser.declarativeNetRequest.updateSessionRules({
      removeRuleIds: existingIds
    })
    return
  }
  const rules = buildRules(
    blocklist as BlocklistEntry[],
    browser.runtime.getURL(BLOCKED_PAGE_PATH)
  )
  try {
    await browser.declarativeNetRequest.updateSessionRules({
      removeRuleIds: existingIds,
      addRules: rules as unknown as NonNullable<UpdateSessionRulesArgs["addRules"]>
    })
  } catch (error) {
    console.error("[phishing-guard] failed to apply blocklist rules", error)
  }
}
```

(Add `import type { BlocklistEntry } from "~/lib/types"` — the implementer must include it; the `as` cast adapts the structural `DnrRule` to the schema enum type at the boundary only.)

- [ ] **Step 3: Write `src/background/index.ts`**

```ts
import browser from "webextension-polyfill"
import { getEnabled, setEnabled } from "~/lib/storage"
import { syncBlocklistRules } from "./rules"

interface SetEnabledMessage {
  type: "setEnabled"
  value: boolean
}

function isSetEnabledMessage(message: unknown): message is SetEnabledMessage {
  if (typeof message !== "object" || message === null) {
    return false
  }
  const candidate = message as Record<string, unknown>
  return candidate.type === "setEnabled" && typeof candidate.value === "boolean"
}

void syncBlocklistRules()

browser.runtime.onMessage.addListener((message) => {
  if (!isSetEnabledMessage(message)) {
    return
  }
  return (async () => {
    await setEnabled(message.value)
    await syncBlocklistRules()
    return { enabled: message.value }
  })()
})
```

Notes: `syncBlocklistRules()` runs top-level on every service-worker wake, so rules re-apply idempotently (remove existing ours, add fresh). The `void` is intentional — never await at top level before listener registration. Unknown messages return `undefined` so the polyfill does not hold the channel open.

- [ ] **Step 4: Verify**

Run: `pnpm exec tsc --noEmit && pnpm build`
Expected: typecheck clean; build emits `background.js` in `build/chrome-mv3-prod` and manifest declares `background.service_worker`.

- [ ] **Step 5: Commit**

```bash
git add src/lib/storage.ts src/background
git commit -m "feat: apply blocklist as DNR session rules with enable-state sync"
```

### Task 3: Popup UI + blocked tab page

**Files:**
- Create: `src/popup.tsx` (replaces scaffold placeholder — delete the root-level `popup.tsx` if one still exists; the `src/` one wins)
- Create: `src/tabs/blocked.tsx`
- Create: `src/tabs/blocked.css` (optional plain CSS imported by blocked.tsx)

**Interfaces:**
- Consumes: `getEnabled`, `setEnabled`, `getLastBlocked` from `~/lib/storage`; `BlockEvent` from `~/lib/types`; `parseBlockedPageParams` from `~/lib/blocklist`; `explainBlocklistMatch`, `explainUnknownBlock` from `~/lib/explain`; `blocklist.json` (for `note` lookup); `browser.runtime.sendMessage({ type: "setEnabled", value })` → `{ enabled }`.
- Produces: UI only. Popup reads state directly from storage; writes go through the background message.

- [ ] **Step 1: Write `src/popup.tsx`**

```tsx
import { useEffect, useState } from "react"
import browser from "webextension-polyfill"
import { getEnabled, getLastBlocked } from "~/lib/storage"
import type { BlockEvent } from "~/lib/types"

function Popup() {
  const [enabled, setEnabledState] = useState<boolean | null>(null)
  const [lastBlocked, setLastBlocked] = useState<BlockEvent | null>(null)

  useEffect(() => {
    void (async () => {
      setEnabledState(await getEnabled())
      setLastBlocked(await getLastBlocked())
    })()
  }, [])

  async function toggleEnabled() {
    const next = !(enabled ?? true)
    setEnabledState(next)
    await browser.runtime.sendMessage({ type: "setEnabled", value: next })
  }

  return (
    <div
      style={{
        padding: 16,
        minWidth: 260,
        fontFamily: "system-ui, sans-serif"
      }}>
      <h2 style={{ margin: "0 0 8px", fontSize: 16 }}>Phishing guard</h2>
      <label
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          cursor: "pointer"
        }}>
        <input
          type="checkbox"
          checked={enabled ?? true}
          onChange={toggleEnabled}
        />
        <span>
          {enabled === null ? "Loading…" : enabled ? "Active" : "Disabled"}
        </span>
      </label>
      <div style={{ marginTop: 12 }}>
        <h3 style={{ margin: "0 0 4px", fontSize: 13 }}>Last blocked</h3>
        {lastBlocked ? (
          <div style={{ fontSize: 12 }}>
            <div style={{ fontWeight: 600 }}>{lastBlocked.domain}</div>
            <div>Source: {lastBlocked.source}</div>
            <div>
              {new Date(lastBlocked.blockedAt).toLocaleString()}
            </div>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: "#666" }}>
            Nothing blocked yet.
          </div>
        )}
      </div>
    </div>
  )
}

export default Popup
```

- [ ] **Step 2: Write `src/tabs/blocked.tsx`** — renders the explainable block page. The URL is only ever interpolated as text (React escapes by default; never use `dangerouslySetInnerHTML`).

```tsx
import { useEffect, useMemo } from "react"
import blocklist from "~/data/blocklist.json"
import { parseBlockedPageParams } from "~/lib/blocklist"
import { explainBlocklistMatch, explainUnknownBlock } from "~/lib/explain"
import { recordBlockEvent } from "~/lib/storage"
import type { BlocklistEntry } from "~/lib/types"

function extractHostname(url: string): string | null {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
}

function BlockedPage() {
  const params = useMemo(
    () => parseBlockedPageParams(window.location.search),
    []
  )
  const hostname = useMemo(
    () => (params ? extractHostname(params.url) : null),
    [params]
  )
  const note = useMemo(() => {
    if (!hostname) {
      return null
    }
    return (
      (blocklist as BlocklistEntry[]).find(
        (entry) => entry.domain === hostname
      )?.note ?? null
    )
  }, [hostname])

  useEffect(() => {
    if (params && hostname) {
      void recordBlockEvent({
        url: params.url,
        domain: hostname,
        source: params.source,
        blockedAt: Date.now()
      })
    }
  }, [params, hostname])

  const containerStyle = {
    display: "flex",
    flexDirection: "column" as const,
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    margin: 0,
    fontFamily: "system-ui, sans-serif",
    background: "#faf7f2",
    color: "#1a1a1a",
    padding: 24,
    textAlign: "center" as const
  }

  if (!params || !hostname) {
    return (
      <main style={containerStyle}>
        <h1>Request blocked</h1>
        <p style={{ maxWidth: 480 }}>{explainUnknownBlock()}</p>
      </main>
    )
  }

  return (
    <main style={containerStyle}>
      <div
        style={{
          width: 64,
          height: 64,
          borderRadius: "50%",
          background: "#b3261e",
          color: "#fff",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 32,
          marginBottom: 16
        }}>
        !
      </div>
      <h1 style={{ margin: "0 0 8px" }}>Phishing guard blocked this page</h1>
      <p style={{ maxWidth: 480, fontSize: 14 }}>
        {explainBlocklistMatch({ domain: hostname, source: params.source })}
      </p>
      <p
        style={{
          maxWidth: 480,
          fontSize: 12,
          color: "#555",
          wordBreak: "break-all"
        }}>
        {params.url}
      </p>
      {note && (
        <p style={{ maxWidth: 480, fontSize: 12, color: "#555" }}>{note}</p>
      )}
      <button
        type="button"
        onClick={() => window.close()}
        style={{
          marginTop: 16,
          padding: "8px 16px",
          fontSize: 14,
          cursor: "pointer"
        }}>
        Close this tab
      </button>
    </main>
  )
}

export default BlockedPage
```

- [ ] **Step 3: Verify**

Run: `pnpm exec tsc --noEmit && pnpm build && ls build/chrome-mv3-prod/tabs`
Expected: typecheck clean; build contains `tabs/blocked.html` and `popup.html`.

- [ ] **Step 4: Commit**

```bash
git add src/popup.tsx src/tabs
git commit -m "feat: add status popup and explainable blocked page"
```

### Task 4: Docs

**Files:**
- Create: `PRIVACY.md`
- Create: `README.md`
- Create: `TODO.md`

**Interfaces:** none (docs).

- [ ] **Step 1: `PRIVACY.md`** — must state: no network requests, no telemetry, no page content collection, blocklist bundled locally, storage only holds enable state + last blocked event (domain/source/timestamp, local-only), `web_accessible_resources` exposes only `tabs/blocked.html`, host permission `<all_urls>` is required for DNR redirects but no browsing data is read or transmitted.

- [ ] **Step 2: `README.md`** — project one-liner (client-side complement to DNS-level filtering, per AGENTS.md); status table for phases 1–5 (Phase 1 done, others pending); dev quickstart: `pnpm install`, `pnpm dev`, `pnpm build`, `pnpm test`, `pnpm typecheck`; load-unpacked instructions for Chrome (`chrome://extensions` → Developer mode → Load unpacked → `build/chrome-mv3-prod`); how to test blocking (navigate to any blocklist domain, e.g. `paypa1-secure.example.com` — reserved test domains, safe); manual Chrome checklist from AGENTS.md section 6; note that blocklist entries live in `src/data/blocklist.json`.

- [ ] **Step 3: `TODO.md`** — hierarchical checkboxes mirroring AGENTS.md build phases; Phase 1 items marked `[x]` only after integration verification, Phases 2–5 unchecked.

- [ ] **Step 4: Commit**

```bash
git add PRIVACY.md README.md TODO.md
git commit -m "docs: add privacy policy, readme, and phase checklist"
```

### Task 5: Integration verification (owner: main session)

- [ ] **Step 1:** `pnpm exec prettier --write src/**/*.{ts,tsx}` — normalize style.
- [ ] **Step 2:** `pnpm exec tsc --noEmit && pnpm test && pnpm build` — all must pass; verify `build/chrome-mv3-prod/manifest.json` retains `permissions`, `host_permissions`, `web_accessible_resources`, `background.service_worker`, and `tabs/blocked.html` exists in output.
- [ ] **Step 3:** Manually load `build/chrome-mv3-prod` in Chrome; confirm: (a) navigating to a listed domain lands on the blocked page with domain + source + reason; (b) normal sites unaffected; (c) popup toggle disables/re-enables; (d) no console errors. **Blocked on user environment** — requires interactive Chrome; checklist lives in README.
- [ ] **Step 4:** Final commits per conventional-commit style.

## Self-Review

- **Spec coverage:** rule building (Task 1), session-rule sync + toggle (Task 2), explainable blocked page + popup (Task 3), WAR/permissions already in scaffold (Task 0), docs/testing checklists (Task 4), fallback for `regexSubstitution` risk documented in spec (manual verification step). All spec sections map to tasks.
- **Placeholder scan:** no TBDs; all code blocks complete; Task 4 docs steps enumerate required content explicitly instead of "write docs".
- **Type consistency:** `BlocklistEntry`/`BlockEvent`/`DnrRule` names match across Tasks 1–3; `buildRules(entries, base, startId?)` signature consistent; message contract `{ type: "setEnabled"; value: boolean }` consistent between background and popup.
