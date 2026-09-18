# phishing-guard — Phase 1 (Blocklist MVP, Chrome) Design

Date: 2026-09-17
Source spec: `AGENTS.md` (repo root) — this document details Phase 1 only.

## Goal

A Manifest V3 browser extension that blocks navigation to known-bad domains
using a bundled static blocklist and `declarativeNetRequest`, showing an
explainable "blocked" page for every match. Scaffolded with Plasmo so later
phases (heuristics, cross-browser, ML) slot in without rework.

## Scope

**In scope (this milestone):** Plasmo scaffold, repo layout per AGENTS.md,
bundled blocklist data, DNR session-rule management, blocked page with
reason, minimal status popup, Vitest unit tests, PRIVACY/README/TODO docs.

**Out of scope:** Phase 2 heuristic scoring, Phase 3 Firefox/Edge port,
Phase 4 Safari, Phase 5 TF.js model. Real feed imports (OpenPhish/PhishTank)
are deferred; the blocklist schema is designed so they drop in later.

## Decisions

| Decision | Choice | Rationale | Alternatives rejected |
|---|---|---|---|
| Scaffolding | Plasmo | MV3 boilerplate + multi-target builds per AGENTS.md | Raw manifest + webpack (more boilerplate, no benefit for MVP) |
| API surface | `webextension-polyfill` (`browser.*`) everywhere | Spec ground rule; makes Phase 3 a straight port | Direct `chrome.*` |
| Rule storage | DNR **session rules** via `updateSessionRules` | Dynamic toggle support, no static-ruleset manifest wiring, single atomic update call | Static ruleset JSON in manifest (harder to toggle, more Plasmo manifest surgery) |
| Match + redirect | `regexFilter` + `action.redirect.regexSubstitution` | Only mechanism that preserves the original URL into the blocked page (capture group `\1` appended as query), so blocks stay explainable | `condition.requestDomains` + `extensionPath` (loses original URL); `action.block` + webNavigation interstitial (racy, loses URL) |
| Blocked page | `src/tabs/blocked.tsx` Plasmo Tab Page → emits `tabs/blocked.html` | Plasmo-idiomatic (Tab Pages are the supported mechanism for custom pages), typed, no asset-copy uncertainty — verified against Plasmo 0.90.5 docs | Root-level static `blocked.html` (Plasmo copy semantics unverified) |
| Package manager | pnpm (installed via corepack) | AGENTS.md scaffold steps specify pnpm | npm/bun |
| Testing | Vitest unit tests on pure lib functions | DNR/browser APIs aren't unit-testable; keep logic pure and test the transforms | Playwright/extension E2E (no good cross-browser story yet per AGENTS.md) |

## Architecture

```
src/
├── background.ts        # entry: SW wake → ensure rules applied; message routing
├── popup.tsx            # entry: status, enable/disable toggle, last-blocked info
├── tabs/blocked.tsx     # Tab Page: renders tabs/blocked.html with url+source params
├── contents/plasmo.ts   # no-op content script (pipeline placeholder for Phase 2)
├── data/blocklist.json  # bundled entries: { domain, source, note? }
├── lib/
│   ├── types.ts         # BlocklistEntry, BlockDecision, RuleBuildInput
│   ├── blocklist.ts     # pure: entries → DNR rules; SW-side apply/remove helpers
│   └── explain.ts       # pure: decision → human-readable reason
├── platform/            # (empty; browser-specific escape hatches, Phase 3+)
└── models/              # (empty; TF.js, Phase 5+)
```

Manifest extras merged via Plasmo's `manifest` key in `package.json`:
`permissions: ["declarativeNetRequest", "storage"]`,
`host_permissions: ["<all_urls>"]` (DNR redirects require host permission over
redirected requests),
`web_accessible_resources: [{ resources: ["tabs/blocked.html"], matches: ["<all_urls>"] }]`.

## Data flow

1. SW wakes (`onInstalled`, `onStartup`, and top-level idempotent call).
2. `applyBlocklist()` reads enabled state from `storage.local` (default: on)
   and `blocklist.json`, builds rules, and issues one `updateSessionRules`
   call (`removeRules: [RULE_TAG]` + `addRules`). Deterministic rule IDs.
3. Navigation to a listed domain: DNR redirects the main frame to
   `browser.runtime.getURL("tabs/blocked.html")` +
   `?source=<name>&url=<original URL raw>` (original URL is the **last**
   query param so its unencoded `&`/`?` characters don't corrupt parsing).
4. `tabs/blocked.tsx` parses params, records the event to `storage.local`
   (timestamp, domain, source) for the popup's "last blocked" display, and
   renders the reason via `explain.ts`.
5. Popup toggle sends `{ type: "setEnabled", value }` to the background,
   which applies or clears session rules and persists state.

## Error handling

- `updateSessionRules` failure: logged to console, disabled state surfaced
  in popup; extension degrades to "no filtering", never crashes the SW.
- Blocked page: unknown/missing params render a generic "request blocked"
  message with a close-tab affordance; never a dead end.
- **XSS guard:** the original URL is attacker-influenced — it is only ever
  rendered with `textContent`, never `innerHTML`.
- Session-rule budget (5000 in Chrome) documented; feed imports at scale are
  a Phase 2+ concern requiring static rulesets.

## Testing

- Vitest, colocated `src/lib/*.test.ts`:
  - `buildRules`: correct regex escaping, tag, IDs, `main_frame` type,
    substitution template containing base URL and source.
  - Match behavior via `new RegExp(rule.regexFilter)`: listed domain matches;
    `notexample.com`, `example.com.evil.io` do not; ports and subdomain
    depth (`a.b.example.com`) do.
  - `explain`: blocklist decision → reason string naming source list.
- Typecheck: `pnpm exec tsc --noEmit`.
- Build: `pnpm build` must produce `build/chrome-mv3` with
  `manifest.json` containing the merged permissions/WAR and `blocked.html`.
- Manual Chrome pass (checklist in README): load unpacked, confirm block of
  a test domain, confirm no effect on other sites.

## Risks / verification status

- ~~Non-interactive `create plasmo`~~ — resolved: scaffolded from the
  create-plasmo 0.90.5 template (driven through a PTY), adapted to the `src/`
  layout; `pnpm build` verified producing `build/chrome-mv3-prod` with merged
  manifest keys.
- ~~Plasmo manifest-merge key name~~ — resolved: `"manifest"` key in
  `package.json` merges `permissions`, `host_permissions`, and
  `web_accessible_resources` (verified in build output).
- pnpm 12 requires `allowBuilds` map in `pnpm-workspace.yaml` for
  native-build deps (esbuild, @swc/core, lmdb, sharp, @parcel/watcher,
  msgpackr-extract) — configured.
- `regexSubstitution` targeting `chrome-extension://` in current Chrome MV3 —
  to be verified with a manual load; fallback: `extensionPath` redirect plus
  storage-recorded recent-block list (loses per-URL display, keeps
  explainability via source attribution).
