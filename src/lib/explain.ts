import type { BlocklistEntry } from "./types"

export function explainBlocklistMatch(
  entry: Pick<BlocklistEntry, "domain" | "source">
): string {
  return `This page was blocked because the domain "${entry.domain}" appears in the "${entry.source}" blocklist of known phishing and scam sites.`
}

export function explainUnknownBlock(): string {
  return "This request was blocked by Phishing guard. No matching rule details were provided."
}

export function explainHeuristicWarning(
  reasons: string[],
  heuristicScore: number,
  modelScore: number
): string {
  const lead = `Phishing guard finds this site suspicious (heuristic risk ${heuristicScore}/100, model risk ${modelScore}/100).`
  if (!reasons.length) {
    return `${lead} Multiple weak signals combined.`
  }
  return `${lead} Why: ${reasons.join("; ")}.`
}
