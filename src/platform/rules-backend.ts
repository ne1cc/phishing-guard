import type browser from "webextension-polyfill"

type DeclarativeNetRequest = typeof browser.declarativeNetRequest

export type RulesBackend = "session" | "dynamic"

export function detectRulesBackend(dnr: DeclarativeNetRequest): RulesBackend {
  return "updateSessionRules" in dnr &&
    typeof dnr.updateSessionRules === "function"
    ? "session"
    : "dynamic"
}
