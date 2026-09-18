import { useEffect, useState } from "react"
import browser from "webextension-polyfill"

import { getEnabled, getLastBlocked, getLastWarned } from "~/lib/storage"
import type { BlockEvent, WarnEvent } from "~/lib/types"

function Popup() {
  const [enabled, setEnabledState] = useState<boolean | null>(null)
  const [lastBlocked, setLastBlocked] = useState<BlockEvent | null>(null)
  const [lastWarned, setLastWarned] = useState<WarnEvent | null>(null)

  useEffect(() => {
    void (async () => {
      setEnabledState(await getEnabled())
      setLastBlocked(await getLastBlocked())
      setLastWarned(await getLastWarned())
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
            <div>{new Date(lastBlocked.blockedAt).toLocaleString()}</div>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: "#666" }}>
            Nothing blocked yet.
          </div>
        )}
      </div>
      <div style={{ marginTop: 12 }}>
        <h3 style={{ margin: "0 0 4px", fontSize: 13 }}>Last warning</h3>
        {lastWarned ? (
          <div style={{ fontSize: 12 }}>
            <div style={{ fontWeight: 600 }}>{lastWarned.domain}</div>
            <div>
              heuristic {lastWarned.heuristicScore}/100 · model{" "}
              {lastWarned.modelScore}/100
            </div>
            <div>{new Date(lastWarned.warnedAt).toLocaleString()}</div>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: "#666" }}>No warnings yet.</div>
        )}
      </div>
    </div>
  )
}

export default Popup
