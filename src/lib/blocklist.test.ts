import { describe, expect, it } from "vitest"

import {
  BLOCKED_PAGE_PATH,
  buildRules,
  hostToRegexPattern,
  parseBlockedPageParams
} from "./blocklist"
import type { BlocklistEntry } from "./types"

const entry: BlocklistEntry = {
  domain: "paypa1-secure.example.com",
  source: "bundled-test-list"
}

describe("hostToRegexPattern", () => {
  it("escapes regex specials in the domain", () => {
    expect(hostToRegexPattern("a.b.example.com")).toBe(
      "^(https?://(?:[^/]*\\.)?a\\.b\\.example\\.com(?::\\d+)?(?:[/?].*)?)$"
    )
  })
})

describe("buildRules", () => {
  const base = `chrome-extension://test-id/${BLOCKED_PAGE_PATH}`

  it("assigns deterministic ids and main_frame resource type", () => {
    const [rule] = buildRules([entry], base)
    expect(rule.id).toBe(1)
    expect(rule.priority).toBe(1)
    expect(rule.condition.resourceTypes).toEqual(["main_frame"])
    expect(rule.action.type).toBe("redirect")
  })

  it("builds a substitution with source attribution and url capture group", () => {
    const [rule] = buildRules([entry], base)
    expect(rule.action.redirect.regexSubstitution).toBe(
      `${base}?source=bundled-test-list&url=\\1`
    )
  })

  it("respects startId for deterministic ranges", () => {
    const rules = buildRules(
      [entry, { ...entry, domain: "b.example.com" }],
      base,
      10
    )
    expect(rules.map((r) => r.id)).toEqual([10, 11])
  })
})

describe("blocklist regex matching", () => {
  const pattern = new RegExp(hostToRegexPattern("paypa1-secure.example.com"))

  const matches = (url: string) => {
    const result = pattern.exec(url)
    return result ? result[1] : null
  }

  it("matches the listed domain over https and http", () => {
    expect(matches("https://paypa1-secure.example.com")).toBe(
      "https://paypa1-secure.example.com"
    )
    expect(matches("http://paypa1-secure.example.com/")).toBe(
      "http://paypa1-secure.example.com/"
    )
  })

  it("matches paths, queries, ports, and deep subdomains", () => {
    expect(
      matches("https://paypa1-secure.example.com/login?next=%2F")
    ).not.toBeNull()
    expect(matches("https://paypa1-secure.example.com:8443/x")).not.toBeNull()
    expect(matches("https://a.b.paypa1-secure.example.com/")).not.toBeNull()
  })

  it("does not match lookalike or suffixed hosts", () => {
    expect(matches("https://notpaypa1-secure.example.com/")).toBeNull()
    expect(matches("https://paypa1-secure.example.com.evil.io/")).toBeNull()
    expect(matches("https://paypa1-secure.example.comic.org/")).toBeNull()
    expect(matches("https://example.org/")).toBeNull()
  })

  it("does not match non-http schemes", () => {
    expect(matches("ftp://paypa1-secure.example.com/")).toBeNull()
  })
})

describe("parseBlockedPageParams", () => {
  it("parses source and raw url when url contains separators", () => {
    const parsed = parseBlockedPageParams(
      "?source=bundled-test-list&url=https://paypa1-secure.example.com/login?next=%2Fx&more=1"
    )
    expect(parsed).toEqual({
      source: "bundled-test-list",
      url: "https://paypa1-secure.example.com/login?next=%2Fx&more=1"
    })
  })

  it("decodes the source", () => {
    const parsed = parseBlockedPageParams(
      "?source=my%20list&url=https://x.example/"
    )
    expect(parsed?.source).toBe("my list")
  })

  it("returns null when url or source is missing", () => {
    expect(parseBlockedPageParams("?source=bundled-test-list")).toBeNull()
    expect(parseBlockedPageParams("?url=https://x.example/")).toBeNull()
    expect(parseBlockedPageParams("")).toBeNull()
  })
})
