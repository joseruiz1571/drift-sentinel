export type Kind = "setting" | "dnssec" | "ruleset";
export type Severity = "low" | "medium" | "high";

export interface Control {
  id: string; // stable identifier, like a control number in a register
  name: string; // human-readable name
  kind: Kind; // tells the scan engine HOW to fetch and read the value
  path: string; // Cloudflare API path after /zones/{ZONE_ID}/
  allowed: string[]; // observed values that count as compliant
  severity: Severity; // impact if this control has drifted
  citation: string; // framework mapping — SOC 2 + ISO 27001:2022 Annex A
}

// ── The baseline ─────────────────────────────────────────────────────

export const CONTROLS: Control[] = [
  {
    id: "CTL-01",
    name: "Minimum TLS version",
    kind: "setting",
    path: "settings/min_tls_version",
    allowed: ["1.2", "1.3"],
    severity: "high",
    citation: "SOC 2 CC6.7; ISO 27001 A.8.24",
  },
  {
    id: "CTL-02",
    name: "Always Use HTTPS",
    kind: "setting",
    path: "settings/always_use_https",
    allowed: ["on"],
    severity: "high",
    citation: "SOC 2 CC6.7; ISO 27001 A.8.24",
  },
  {
    id: "CTL-03",
    name: "Security level",
    kind: "setting",
    path: "settings/security_level",
    allowed: ["medium", "high", "under_attack"],
    severity: "medium",
    citation: "SOC 2 CC6.6; ISO 27001 A.8.9",
  },
  {
    id: "CTL-04",
    name: "Browser integrity check",
    kind: "setting",
    path: "settings/browser_check",
    allowed: ["on"],
    severity: "low",
    citation: "SOC 2 CC6.6; ISO 27001 A.8.23",
  },
  {
    id: "CTL-05",
    name: "DNSSEC",
    kind: "dnssec",
    path: "dnssec",
    allowed: ["active"],
    severity: "medium",
    citation: "SOC 2 CC6.6; ISO 27001 A.8.20",
  },
  {
    id: "CTL-06",
    name: "WAF managed ruleset deployed",
    kind: "ruleset",
    path: "rulesets",
    allowed: ["http_request_firewall_managed"], // phase that must exist
    severity: "high",
    citation: "SOC 2 CC6.6; ISO 27001 A.8.20, A.8.23",
  },
];
