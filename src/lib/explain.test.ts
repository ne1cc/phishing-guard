import { describe, expect, it } from "vitest"

import { explainBlocklistMatch, explainUnknownBlock } from "./explain"

describe("explainBlocklistMatch", () => {
  it("names the domain and the source list", () => {
    const reason = explainBlocklistMatch({
      domain: "paypa1-secure.example.com",
      source: "bundled-test-list"
    })
    expect(reason).toContain("paypa1-secure.example.com")
    expect(reason).toContain("bundled-test-list")
    expect(reason).toContain("phishing")
  })
})

describe("explainUnknownBlock", () => {
  it("returns a non-empty generic reason", () => {
    expect(explainUnknownBlock().length).toBeGreaterThan(0)
  })
})
