import browser from "webextension-polyfill"

import blocklist from "~/data/blocklist.json"
import { BLOCKED_PAGE_PATH, buildRules } from "~/lib/blocklist"
import { getEnabled } from "~/lib/storage"
import type { BlocklistEntry } from "~/lib/types"
import { detectRulesBackend } from "~/platform/rules-backend"
import type { RulesBackend } from "~/platform/rules-backend"

type UpdateRulesArgs = Parameters<
  typeof browser.declarativeNetRequest.updateSessionRules
>[0]

async function updateRules(
  backend: RulesBackend,
  options: UpdateRulesArgs
): Promise<void> {
  if (backend === "session") {
    await browser.declarativeNetRequest.updateSessionRules(options)
    return
  }
  await browser.declarativeNetRequest.updateDynamicRules(options)
}

export async function syncBlocklistRules(): Promise<void> {
  try {
    const enabled = await getEnabled()
    const dnr = browser.declarativeNetRequest
    const backend = detectRulesBackend(dnr)
    const existing =
      backend === "session"
        ? await dnr.getSessionRules()
        : await dnr.getDynamicRules()
    const existingIds = existing.map((rule) => rule.id)
    if (!enabled) {
      await updateRules(backend, { removeRuleIds: existingIds })
      return
    }
    const rules = buildRules(
      blocklist as BlocklistEntry[],
      browser.runtime.getURL(BLOCKED_PAGE_PATH)
    )
    await updateRules(backend, {
      removeRuleIds: existingIds,
      addRules: rules as unknown as NonNullable<UpdateRulesArgs["addRules"]>
    })
  } catch (error) {
    console.error("[phishing-guard] failed to sync blocklist rules", error)
  }
}
