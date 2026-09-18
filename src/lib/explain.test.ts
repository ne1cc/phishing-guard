import { describe, expect, it } from "vitest"

import {
  explainBlocklistMatch,
  explainHeuristicWarning,
  explainUnknownBlock
} from "./explain"

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

describe("explainHeuristicWarning", () => {
  it("leads with both scores and lists every reason", () => {
    const text = explainHeuristicWarning(
      ['hostname token resembles brand "paypal" (edit distance 1)'],
      62,
      0
    )
    expect(text).toContain("heuristic risk 62/100")
    expect(text).toContain("model risk 0/100")
    expect(text).toContain('resembles brand "paypal"')
  })

  it("joins multiple reasons with semicolons", () => {
    const text = explainHeuristicWarning(["reason one", "reason two"], 50, 10)
    expect(text).toContain("reason one; reason two")
  })

  it("falls back to weak-signal copy without reasons", () => {
    const text = explainHeuristicWarning([], 40, 0)
    expect(text).toContain("Multiple weak signals combined")
  })
})
