# Privacy Policy — Phishing guard

Last updated: 2026-09-17

Phishing guard is an on-device phishing and scam site blocker. Everything it
does happens locally in your browser. It collects nothing and sends nothing.

## What the extension does not do

- **No network requests.** The extension itself makes zero network requests.
  There is no fetch call anywhere in the codebase.
- **No telemetry or analytics.** No usage stats, crash reports, or tracking
  of any kind.
- **No page content collection.** The extension never reads, stores, or
  transmits the contents of pages you visit.

## Blocklist

The blocklist is bundled with the extension at `src/data/blocklist.json` and
is matched locally. No blocklist is downloaded from a server, and no
information about which sites you visit is shared with anyone.

## Data storage

The extension uses `browser.storage.local` only, which never leaves your
device and is not synced to any account. It stores exactly two keys:

- `enabled` — whether protection is on or off.
- `lastBlocked` — the most recent blocked navigation: URL, matched domain,
  source list name, and timestamp. Only the single most recent event is kept.

Uninstalling the extension removes all of this data.

## Permissions

- `declarativeNetRequest` — used to install session rules that redirect
  navigation to known-bad blocklist domains to the local blocked page.
- `storage` — used for the two local keys described above.
- `host_permissions: <all_urls>` — required so the declarativeNetRequest
  rules can match and redirect main-frame navigations on any site. The
  extension does not read or transmit any data to those hosts; the permission
  exists only because redirect rules must be able to apply to any URL.

## Web-accessible resources

The extension exposes exactly one resource to web pages:
`tabs/blocked.html`, the local page a blocked navigation is redirected to.
No other extension file is reachable from the web.

## Explainable blocking

Every block is explainable: the blocked page states which domain was
matched, which source list it came from, and the original URL. Nothing is
blocked silently.

## Future changes

If a later phase ever introduces a network call (for example, blocklist
updates), that change will be documented here first. The current design
sends nothing off-device.
