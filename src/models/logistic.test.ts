import { describe, expect, it } from "vitest"

import { extractFeatures } from "~/lib/heuristics"
import type { HeuristicFeatures } from "~/lib/heuristics"

import { getModel, MODEL_THRESHOLD } from "./index"
import { LogisticPhishingModel } from "./logistic"

function zeroFeatures(): HeuristicFeatures {
  return {
    brandSimilarity: 0,
    punycode: 0,
    ipHost: 0,
    atSymbol: 0,
    suspiciousTld: 0,
    hostEntropy: 0,
    credentialPath: 0,
    digitRatio: 0,
    hyphenCount: 0,
    subdomainDepth: 0,
    hostLength: 0
  }
}

describe("LogisticPhishingModel", () => {
  const model = new LogisticPhishingModel()

  it("scores all-zero features at 4 (bias-only sigmoid)", () => {
    expect(model.score(zeroFeatures())).toBe(4)
  })

  it("scores brandSimilarity alone at 27", () => {
    expect(model.score({ ...zeroFeatures(), brandSimilarity: 1 })).toBe(27)
  })

  it("crosses the warning threshold with brandSimilarity plus punycode", () => {
    const score = model.score({
      ...zeroFeatures(),
      brandSimilarity: 1,
      punycode: 1
    })
    expect(score).toBe(65)
    expect(score).toBeGreaterThanOrEqual(MODEL_THRESHOLD)
  })

  it("flags a realistic lookalike URL above the all-zero score", () => {
    const url = "https://paypa1-support.com/login"
    const features = extractFeatures(url)
    const score = model.score(features)
    expect(score).toBe(50)
    expect(getModel().score(features)).toBe(score)
    expect(score).toBeGreaterThan(model.score(zeroFeatures()))
  })

  it("is the model served by getModel()", () => {
    expect(getModel().name).toBe("logistic-baseline-v1")
  })
})
