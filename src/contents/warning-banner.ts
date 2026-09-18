import { explainHeuristicWarning } from "~/lib/explain"
import { scoreUrl, shouldWarn } from "~/lib/heuristics"
import { getEnabled, recordWarnEvent } from "~/lib/storage"
import { getModel, MODEL_THRESHOLD } from "~/models"

const BANNER_ID = "phishing-guard-banner"

function evaluate(url: string) {
  const heuristic = scoreUrl(url)
  const modelScore = getModel().score(heuristic.features)
  return {
    heuristic,
    modelScore,
    warn: shouldWarn(heuristic) || modelScore >= MODEL_THRESHOLD
  }
}

function injectBanner(
  reasons: string[],
  heuristicScore: number,
  modelScore: number
): void {
  if (document.getElementById(BANNER_ID)) {
    return
  }
  const host = document.createElement("div")
  host.id = BANNER_ID
  const shadow = host.attachShadow({ mode: "open" })
  const bar = document.createElement("div")
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b3261e;color:#fff;font:14px/1.45 system-ui,sans-serif;padding:12px 16px;display:flex;gap:12px;align-items:flex-start;box-shadow:0 2px 8px rgba(0,0,0,0.35)"
  const text = document.createElement("div")
  text.style.cssText = "flex:1;min-width:0;word-break:break-word"
  const title = document.createElement("strong")
  title.textContent = "Phishing guard: this site looks suspicious"
  const body = document.createElement("div")
  body.textContent = explainHeuristicWarning(
    reasons,
    heuristicScore,
    modelScore
  )
  text.append(title, body)
  const dismiss = document.createElement("button")
  dismiss.type = "button"
  dismiss.textContent = "Dismiss"
  dismiss.style.cssText =
    "background:rgba(255,255,255,0.18);color:#fff;border:1px solid rgba(255,255,255,0.5);border-radius:6px;padding:6px 12px;font:inherit;cursor:pointer"
  dismiss.addEventListener("click", () => host.remove())
  bar.append(text, dismiss)
  shadow.append(bar)
  document.documentElement.append(host)
}

void (async () => {
  try {
    const enabled = await getEnabled()
    if (!enabled) return
    const verdict = evaluate(window.location.href)
    if (verdict.warn) {
      injectBanner(
        verdict.heuristic.reasons,
        verdict.heuristic.score,
        verdict.modelScore
      )
      void recordWarnEvent({
        url: window.location.href,
        domain: window.location.hostname,
        heuristicScore: verdict.heuristic.score,
        modelScore: verdict.modelScore,
        reasons: verdict.heuristic.reasons,
        warnedAt: Date.now()
      })
    }
  } catch (error) {
    console.error("[phishing-guard] failed to evaluate or show warning", error)
  }
})()
