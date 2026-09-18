import { describe, expect, it } from "vitest"

import {
  computeScore,
  extractFeatures,
  levenshtein,
  scoreUrl,
  shouldWarn,
  WARN_THRESHOLD
} from "./heuristics"

describe("levenshtein", () => {
  it("measures edit distance", () => {
    expect(levenshtein("paypa1", "paypal")).toBe(1)
    expect(levenshtein("gooogle", "google")).toBe(1)
    expect(levenshtein("github", "github")).toBe(0)
    expect(levenshtein("", "abc")).toBe(3)
  })
})

describe("scoreUrl on normal sites", () => {
  it("scores known-good sites at zero", () => {
    expect(scoreUrl("https://google.com/").score).toBe(0)
    expect(scoreUrl("https://mozilla.org/").score).toBe(0)
    expect(scoreUrl("https://apple.com/mac/").score).toBe(0)
  })

  it("does not warn on a bare-IP internal host alone", () => {
    const result = scoreUrl("http://192.168.1.1/admin")
    expect(result.features.ipHost).toBe(1)
    expect(shouldWarn(result)).toBe(false)
  })
})

describe("scoreUrl on suspicious sites", () => {
  it("flags a brand typosquat with a credential path", () => {
    const result = scoreUrl("https://paypa1-support.com/login")
    expect(result.features.brandSimilarity).toBe(1)
    expect(result.reasons.join(" ")).toContain('resembles brand "paypal"')
    expect(shouldWarn(result)).toBe(true)
  })

  it("flags an embedded brand on an unofficial domain", () => {
    const result = scoreUrl("https://secure-chase-verify.net/login")
    expect(result.features.brandSimilarity).toBe(1)
    expect(result.features.credentialPath).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })

  it("flags punycode hosts on their own", () => {
    const result = scoreUrl("https://xn--80ak6aa92e.com/")
    expect(result.features.punycode).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })

  it("treats the real brand domain as safe even with credential paths", () => {
    const result = scoreUrl("https://www.paypal.com/signin")
    expect(result.features.brandSimilarity).toBe(0)
    expect(shouldWarn(result)).toBe(false)
  })

  it("flags a userinfo '@' with a spoofed display host", () => {
    const result = scoreUrl("https://google.com@xn--80ak6aa92e.com/")
    expect(result.features.atSymbol).toBe(1)
    expect(shouldWarn(result)).toBe(true)
  })
})

describe("computeScore", () => {
  it("is zero for an all-zero feature vector", () => {
    const zero = extractFeatures("https://google.com/")
    expect(computeScore({ ...zero })).toBe(0)
  })

  it("caps at 100", () => {
    const maxed = {
      brandSimilarity: 1,
      punycode: 1,
      ipHost: 1,
      atSymbol: 1,
      suspiciousTld: 1,
      hostEntropy: 1,
      credentialPath: 1,
      digitRatio: 1,
      hyphenCount: 1,
      subdomainDepth: 1,
      hostLength: 1
    }
    expect(computeScore(maxed)).toBe(100)
  })
})

describe("threshold", () => {
  it("is 35", () => {
    expect(WARN_THRESHOLD).toBe(35)
  })
})
