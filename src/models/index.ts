import type { HeuristicFeatures } from "~/lib/heuristics"

import { LogisticPhishingModel } from "./logistic"

export interface PhishingModel {
  readonly name: string
  score(features: HeuristicFeatures): number
}

export const MODEL_THRESHOLD = 55

export function getModel(): PhishingModel {
  return new LogisticPhishingModel()
}
