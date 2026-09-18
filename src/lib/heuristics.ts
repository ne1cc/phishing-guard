export interface HeuristicFeatures {
  brandSimilarity: number
  punycode: number
  ipHost: number
  atSymbol: number
  suspiciousTld: number
  hostEntropy: number
  credentialPath: number
  digitRatio: number
  hyphenCount: number
  subdomainDepth: number
  hostLength: number
}

export interface HeuristicResult {
  score: number
  features: HeuristicFeatures
  reasons: string[]
}

export const WARN_THRESHOLD = 35

const SUSPICIOUS_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "buzz",
  "click",
  "link",
  "work",
  "rest",
  "fit",
  "cam",
  "cfd",
  "sbs"
])

const BRANDS: Array<[string, string]> = [
  ["paypal", "paypal.com"],
  ["chase", "chase.com"],
  ["wellsfargo", "wellsfargo.com"],
  ["apple", "apple.com"],
  ["icloud", "icloud.com"],
  ["microsoft", "microsoft.com"],
  ["office365", "office365.com"],
  ["outlook", "outlook.com"],
  ["google", "google.com"],
  ["gmail", "gmail.com"],
  ["amazon", "amazon.com"],
  ["netflix", "netflix.com"],
  ["coinbase", "coinbase.com"],
  ["binance", "binance.com"],
  ["whatsapp", "whatsapp.com"],
  ["instagram", "instagram.com"],
  ["facebook", "facebook.com"],
  ["linkedin", "linkedin.com"],
  ["steam", "steampowered.com"],
  ["roblox", "roblox.com"],
  ["dhl", "dhl.com"],
  ["fedex", "fedex.com"],
  ["usps", "usps.com"],
  ["irs", "irs.gov"],
  ["dropbox", "dropbox.com"]
]

const CREDENTIAL_WORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "confirm",
  "billing",
  "webscr"
]

const FEATURE_WEIGHTS: Record<keyof HeuristicFeatures, number> = {
  brandSimilarity: 0.4,
  punycode: 0.35,
  ipHost: 0.18,
  atSymbol: 0.35,
  suspiciousTld: 0.1,
  hostEntropy: 0.1,
  credentialPath: 0.08,
  digitRatio: 0.04,
  hyphenCount: 0.04,
  subdomainDepth: 0.04,
  hostLength: 0.01
}

export function levenshtein(a: string, b: string): number {
  if (a === b) {
    return 0
  }
  if (!a.length) {
    return b.length
  }
  if (!b.length) {
    return a.length
  }
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    const current = [i]
    for (let j = 1; j <= b.length; j++) {
      const substitution = previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      current.push(Math.min(previous[j] + 1, current[j - 1] + 1, substitution))
    }
    previous = current
  }
  return previous[b.length]
}

function shannonEntropy(text: string): number {
  if (!text.length) {
    return 0
  }
  const counts = new Map<string, number>()
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / text.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

const clamp01 = (value: number) => Math.min(1, Math.max(0, value))

function registrableDomain(hostname: string): string {
  const labels = hostname.split(".")
  return labels.length <= 2 ? hostname : labels.slice(-2).join(".")
}

function brandSignal(hostname: string): {
  value: number
  reason: string | null
} {
  const registrable = registrableDomain(hostname)
  for (const [, legit] of BRANDS) {
    if (registrable === legit || registrable.endsWith(`.${legit}`)) {
      return { value: 0, reason: null }
    }
  }
  for (const [brand, legit] of BRANDS) {
    if (hostname.includes(brand)) {
      return {
        value: 1,
        reason: `hostname mentions "${brand}" but is not the official ${legit} domain`
      }
    }
  }
  const registrableLabel = registrable.split(".")[0]
  const tokens = registrableLabel.split(/[^a-z0-9]+/).filter(Boolean)
  let best: { brand: string; distance: number } | null = null
  for (const [brand] of BRANDS) {
    for (const token of tokens) {
      const distance = levenshtein(token, brand)
      if (
        distance >= 1 &&
        distance <= 2 &&
        (!best || distance < best.distance)
      ) {
        best = { brand, distance }
      }
    }
  }
  if (best) {
    return {
      value: 1,
      reason: `hostname token resembles brand "${best.brand}" (edit distance ${best.distance})`
    }
  }
  return { value: 0, reason: null }
}

export function extractFeatures(rawUrl: string): HeuristicFeatures {
  const url = new URL(rawUrl)
  const host = url.hostname.toLowerCase()
  const path = url.pathname.toLowerCase()
  const labels = host.split(".")
  const tld = labels[labels.length - 1] ?? ""
  const brand = brandSignal(host)
  const digits = (host.match(/\d/g) ?? []).length
  const hyphens = (host.match(/-/g) ?? []).length
  return {
    brandSimilarity: brand.value,
    punycode: host.includes("xn--") ? 1 : 0,
    ipHost: /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ? 1 : 0,
    atSymbol: url.username !== "" ? 1 : 0,
    suspiciousTld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    hostEntropy: clamp01((shannonEntropy(host) - 3.2) / 1.3),
    credentialPath: CREDENTIAL_WORDS.some((word) => path.includes(word))
      ? 1
      : 0,
    digitRatio: clamp01(host.length ? digits / host.length : 0),
    hyphenCount: Math.min(hyphens / 4, 1),
    subdomainDepth: clamp01(Math.max(0, labels.length - 2) / 4),
    hostLength: clamp01(Math.max(0, host.length - 20) / 30)
  }
}

export function computeScore(features: HeuristicFeatures): number {
  let total = 0
  for (const key of Object.keys(FEATURE_WEIGHTS) as Array<
    keyof HeuristicFeatures
  >) {
    total += FEATURE_WEIGHTS[key] * features[key]
  }
  return Math.min(100, Math.round(total * 100))
}

function buildReasons(rawUrl: string, features: HeuristicFeatures): string[] {
  const reasons: string[] = []
  const brand = brandSignal(new URL(rawUrl).hostname.toLowerCase())
  if (brand.reason) {
    reasons.push(brand.reason)
  }
  if (features.punycode) {
    reasons.push(
      "hostname uses punycode (xn--), which can disguise lookalike domains"
    )
  }
  if (features.ipHost) {
    reasons.push("the site is served from a bare IP address")
  }
  if (features.atSymbol) {
    reasons.push("the URL contains a userinfo '@', a classic disguise trick")
  }
  if (features.suspiciousTld) {
    reasons.push("the domain uses a TLD commonly abused for phishing")
  }
  if (features.hostEntropy > 0) {
    reasons.push("the hostname looks randomly generated (high entropy)")
  }
  if (features.credentialPath) {
    reasons.push(
      "the path contains credential-style words like login/verify/secure"
    )
  }
  return reasons
}

export function scoreUrl(rawUrl: string): HeuristicResult {
  const features = extractFeatures(rawUrl)
  return {
    score: computeScore(features),
    features,
    reasons: buildReasons(rawUrl, features)
  }
}

export function shouldWarn(result: HeuristicResult): boolean {
  return result.score >= WARN_THRESHOLD
}
