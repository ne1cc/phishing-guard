import { useEffect, useMemo } from "react"

import blocklist from "~/data/blocklist.json"
import { findBlocklistEntry, parseBlockedPageParams } from "~/lib/blocklist"
import { explainBlocklistMatch, explainUnknownBlock } from "~/lib/explain"
import { recordBlockEvent } from "~/lib/storage"
import type { BlocklistEntry } from "~/lib/types"

function extractHostname(url: string): string | null {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
}

function BlockedPage() {
  const params = useMemo(
    () => parseBlockedPageParams(window.location.search),
    []
  )
  const hostname = useMemo(
    () => (params ? extractHostname(params.url) : null),
    [params]
  )
  const entry = useMemo(
    () =>
      hostname
        ? findBlocklistEntry(blocklist as BlocklistEntry[], hostname)
        : null,
    [hostname]
  )

  useEffect(() => {
    if (params && hostname && entry) {
      void recordBlockEvent({
        url: params.url,
        domain: hostname,
        source: entry.source,
        blockedAt: Date.now()
      })
    }
  }, [params, hostname, entry])

  const containerStyle = {
    display: "flex",
    flexDirection: "column" as const,
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    margin: 0,
    fontFamily: "system-ui, sans-serif",
    background: "#faf7f2",
    color: "#1a1a1a",
    padding: 24,
    textAlign: "center" as const
  }

  const closeButton = (
    <button
      type="button"
      onClick={() => window.close()}
      style={{
        marginTop: 16,
        padding: "8px 16px",
        fontSize: 14,
        cursor: "pointer"
      }}>
      Close this tab
    </button>
  )

  if (!params || !hostname || !entry) {
    return (
      <main style={containerStyle}>
        <h1>Request blocked</h1>
        <p style={{ maxWidth: 480 }}>{explainUnknownBlock()}</p>
        {closeButton}
      </main>
    )
  }

  return (
    <main style={containerStyle}>
      <div
        style={{
          width: 64,
          height: 64,
          borderRadius: "50%",
          background: "#b3261e",
          color: "#fff",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 32,
          marginBottom: 16
        }}>
        !
      </div>
      <h1 style={{ margin: "0 0 8px" }}>Phishing guard blocked this page</h1>
      <p style={{ maxWidth: 480, fontSize: 14 }}>
        {explainBlocklistMatch({ domain: hostname, source: entry.source })}
      </p>
      <p
        style={{
          maxWidth: 480,
          fontSize: 12,
          color: "#555",
          wordBreak: "break-all"
        }}>
        {params.url}
      </p>
      {entry.note && (
        <p style={{ maxWidth: 480, fontSize: 12, color: "#555" }}>
          {entry.note}
        </p>
      )}
      {closeButton}
    </main>
  )
}

export default BlockedPage
