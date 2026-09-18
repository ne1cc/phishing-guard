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
            <div>{new Date(lastBlocked.blockedAt).toLocaleString()}</div>
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
