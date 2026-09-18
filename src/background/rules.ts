import browser from "webextension-polyfill"

import blocklist from "~/data/blocklist.json"
import { BLOCKED_PAGE_PATH, buildRules } from "~/lib/blocklist"
import { getEnabled } from "~/lib/storage"
import type { BlocklistEntry } from "~/lib/types"

type UpdateSessionRulesArgs = Parameters<
  typeof browser.declarativeNetRequest.updateSessionRules
>[0]

export async function syncBlocklistRules(): Promise<void> {
  try {
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
    await browser.declarativeNetRequest.updateSessionRules({
      removeRuleIds: existingIds,
      addRules: rules as unknown as NonNullable<
        UpdateSessionRulesArgs["addRules"]
      >
    })
  } catch (error) {
    console.error("[phishing-guard] failed to sync blocklist rules", error)
  }
}
