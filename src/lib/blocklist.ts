import type { BlocklistEntry, DnrRule } from "./types"

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
