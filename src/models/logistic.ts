import type { HeuristicFeatures } from "~/lib/heuristics"

import type { PhishingModel } from "./index"

const WEIGHTS: Array<[keyof HeuristicFeatures, number]> = [
  ["brandSimilarity", 2.2],
  ["punycode", 1.6],
  ["ipHost", 1.2],
  ["atSymbol", 1.0],
  ["suspiciousTld", 0.9],
  ["hostEntropy", 0.8],
  ["credentialPath", 0.7],
  ["digitRatio", 0.4],
  ["hyphenCount", 0.4],
  ["subdomainDepth", 0.4],
  ["hostLength", 0.1]
]

const BIAS = -3.2

export class LogisticPhishingModel implements PhishingModel {
  readonly name = "logistic-baseline-v1"

  score(features: HeuristicFeatures): number {
    let z = BIAS
    for (const [key, weight] of WEIGHTS) {
      z += weight * features[key]
    }
    return Math.round(100 / (1 + Math.exp(-z)))
  }
}
