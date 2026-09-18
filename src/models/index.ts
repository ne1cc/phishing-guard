import type { HeuristicFeatures } from "~/lib/heuristics"

export interface PhishingModel {
  readonly name: string
  score(features: HeuristicFeatures): number
}

export const MODEL_THRESHOLD = 55

const STUB_MODEL: PhishingModel = {
  name: "stub",
  score: () => 0
}

export function getModel(): PhishingModel {
  return STUB_MODEL
}
