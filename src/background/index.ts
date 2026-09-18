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
