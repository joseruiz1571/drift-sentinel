# Drift Sentinel

A Cloudflare-native compliance drift detector. Scans zone security settings against a declared baseline, persists append-only evidence to D1, and serves compliance reports with SOC 2 and ISO 27001 citations.

**Status:** Live at `eggrollindex.com`. Free Cloudflare plan only. $0 marginal cost.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Cloudflare Workers (TypeScript, edge-deployed)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Cron Trigger (every 6 hours)                                   │
│       │                                                           │
│       └──> Scan Engine (src/scan.ts)                            │
│            │ 1. Fetch zone settings from Cloudflare API        │
│            │ 2. Compare against baseline (src/baseline.ts)     │
│            │ 3. Return per-control status (pass/drift/error)   │
│            │                                                     │
│            └──> D1 Database (append-only snapshots table)      │
│                  │ One row per control per scan                 │
│                  │ Indexed by scan_id and timestamp             │
│                  │ Zero UPDATE or DELETE paths in code (ISC-16) │
│                  │                                               │
│                  └──> Report Endpoints                           │
│                       │ /report (JSON, latest scan)             │
│                       │ /report?format=html (rendered report)   │
│                       │ /report?asof=TIMESTAMP (historical)     │
│                       └──> Compliance citations (SOC 2, ISO)    │
│                                                                  │
│  HTTP Handlers                                                   │
│   • POST /scan (manual trigger)                                 │
│   • GET /report (latest compliance state)                       │
│   • GET /report?format=html (readable report)                   │
│   • GET /report?asof=2026-08-11T00:00:00Z (point-in-time)      │
│   • 404 on unknown routes                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Control Baseline

**Six controls**, all Free-plan auditable:

| ID | Control | Expected | Severity | Citation |
|---|---|---|---|---|
| CTL-01 | Minimum TLS version | 1.2+ | HIGH | SOC 2 CC6.7; ISO 27001 A.8.24 |
| CTL-02 | Always Use HTTPS | on | HIGH | SOC 2 CC6.7; ISO 27001 A.8.24 |
| CTL-03 | Security level | medium+ | MEDIUM | SOC 2 CC6.6; ISO 27001 A.8.9 |
| CTL-04 | Browser integrity check | on | LOW | SOC 2 CC6.6; ISO 27001 A.8.23 |
| CTL-05 | DNSSEC | active | MEDIUM | SOC 2 CC6.6; ISO 27001 A.8.20 |
| CTL-06 | WAF managed ruleset | deployed | HIGH | SOC 2 CC6.6; ISO 27001 A.8.20, A.8.23 |

Every control maps to specific Cloudflare APIs (settings, dnssec, rulesets). Drift is detected by comparing observed values against `allowed` values in the baseline.

## Data Model

### Snapshots Table (D1)

```sql
CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  scan_id TEXT,          -- unique identifier per scan run
  scan_timestamp INTEGER, -- unix milliseconds (indexed for ?asof queries)
  control_id TEXT,
  observed TEXT,         -- what the API returned
  expected TEXT,         -- baseline allowed values (comma-separated)
  status TEXT,           -- pass | drift | error
  detail TEXT,           -- error reason if status=error
  created_at INTEGER
);
```

**Append-only constraint:** Code audit (ISC-16) confirms zero UPDATE or DELETE statements. New scans INSERT rows; old rows never change. This design:
- Preserves audit trail (every decision is a row)
- Enables point-in-time queries (`?asof=DATE`)
- Prevents accidental data loss
- Makes evidence chain auditable

## API Examples

### Trigger a scan
```bash
curl https://drift-sentinel.workers.dev/scan
```

Returns:
```json
{
  "scan_id": "scan-1723391400000",
  "results": [
    {
      "id": "CTL-01",
      "name": "Minimum TLS version",
      "observed": "1.3",
      "expected": ["1.2", "1.3"],
      "status": "pass",
      "severity": "high",
      "citation": "SOC 2 CC6.7; ISO 27001 A.8.24"
    },
    ...
  ]
}
```

### Get latest compliance report (JSON)
```bash
curl https://drift-sentinel.workers.dev/report
```

### Get compliance report as HTML
```bash
curl https://drift-sentinel.workers.dev/report?format=html
```

Renders a readable table with status summary, per-control results, and framework citations.

### Point-in-time query
```bash
curl "https://drift-sentinel.workers.dev/report?asof=2026-08-11T06:00:00Z"
```

Returns the compliance state as of that timestamp (pulls the latest scan on or before that time).

## Token Hygiene

**Read-only API token** (ISC-26):
- Scoped to: `Zone:Read`, `Settings:Read`, `DNS:Read`, `Account:Read`
- Stored via `wrangler secret put CF_API_TOKEN` (never committed)
- Verified at startup: `wrangler whoami` confirms account access
- No literal token appears in code (fetched from Worker env binding)
- Leaked token risk is minimal (read-only for your zone only)

**Zone ID** (public):
- `838bd540f4c21f053378ea01854d9363` (eggrollindex.com)
- Not secret; publicly derivable from DNS
- Account ID is similarly safe (account-level read, no modifications)

## Governance Rationale (ISC-25)

Why append-only evidence?

Standard compliance monitoring tunes thresholds on a Tuesday, and the policy the board approves on Wednesday is a different thing than what the system ran last Monday. Append-only snapshots create a documented loop: the system asserts what is true; the assertion is auditable; the assertion binds the evidence trail. If someone asks "was this zone compliant on July 15th?" the answer comes from a row, not a memory.

Drift Sentinel is that pattern applied to zone configuration: **declared state → scan → evidence → report**. Every step is reversible via the query interface. The cron-scanned results are not scrubbed, not aggregated away, not even summarized — they're rows in a table. That's the difference between monitoring and audit readiness.

## At Scale: What Breaks (ISC-27)

This design is validated for a single zone (eggrollindex.com) on Cloudflare's Free plan. Current constraints:

- **Subrequests:** Scan makes 6 API calls (one per control). Free plan allows 50/min. Safe for 6-hour intervals (< 1/min average).
- **D1 writes:** ~6 rows per scan, 4 scans/day = ~24 rows/day. Free plan allows unlimited reads/writes; no row cap.
- **Query latency:** Point-in-time queries scan full table on each request. Safe to ~10,000 rows (6 months of 4/day scans). After that, add time-based partition or archive old data.
- **Multiple zones:** Would require parallel scan agents or zone-loop inside a single agent. Free plan Worker size is 1MB; multiple endpoints are feasible but untested.

To scale beyond one zone: add zone parameter, fan out to parallel Workers, or migrate to Pages Functions if D1 limit is hit.

## Deployment

1. Fork or clone this repo
2. Install dependencies: `bun install`
3. Authenticate: `bunx wrangler login`
4. Create a Cloudflare account and register a domain in the dashboard
5. Create a read-only API token (User Settings → API Tokens)
6. Deploy: `bunx wrangler deploy`
7. Test:
   ```bash
   curl https://<your-subdomain>.workers.dev/scan
   curl https://<your-subdomain>.workers.dev/report
   ```

The cron trigger activates after deploy; first scan will run at the next 6-hour boundary (UTC).

## Repository

- **Compliance:** CC BY 4.0
- **Framework coverage:** SOC 2 CC6.x, ISO 27001 Annex A.8
- **Code:** TypeScript, no external dependencies (Cloudflare SDK included)
- **Evidence:** Append-only D1 snapshots, point-in-time queryable

---

**Author:** Jose Ruiz-Vazquez | Controlled Vocabulary
