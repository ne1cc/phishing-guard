import browser from "webextension-polyfill"

import type { BlockEvent, WarnEvent } from "./types"

const ENABLED_KEY = "enabled"
const LAST_BLOCKED_KEY = "lastBlocked"
const LAST_WARNED_KEY = "lastWarned"

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

export async function getLastWarned(): Promise<WarnEvent | null> {
  const stored = await browser.storage.local.get(LAST_WARNED_KEY)
  const event = stored[LAST_WARNED_KEY]
  return isWarnEvent(event) ? event : null
}

export async function recordWarnEvent(event: WarnEvent): Promise<void> {
  await browser.storage.local.set({ [LAST_WARNED_KEY]: event })
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

function isWarnEvent(value: unknown): value is WarnEvent {
  if (typeof value !== "object" || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.url === "string" &&
    typeof candidate.domain === "string" &&
    typeof candidate.heuristicScore === "number" &&
    typeof candidate.modelScore === "number" &&
    Array.isArray(candidate.reasons) &&
    candidate.reasons.every((reason) => typeof reason === "string") &&
    typeof candidate.warnedAt === "number"
  )
}
