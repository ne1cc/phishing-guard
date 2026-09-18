export interface BlocklistEntry {
  domain: string
  source: string
  note?: string
}

export interface BlockEvent {
  url: string
  domain: string
  source: string
  blockedAt: number
}

export interface DnrRule {
  id: number
  priority: number
  condition: {
    regexFilter: string
    resourceTypes: Array<"main_frame">
  }
  action: {
    type: "redirect"
    redirect: { regexSubstitution: string }
  }
}
