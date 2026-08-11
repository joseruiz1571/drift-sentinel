import { ScanResult } from "./scan";

export interface ReportSummary {
  scan_id: string;
  scanned_at: string;
  controls: Array<{
    id: string;
    name: string;
    status: "pass" | "drift" | "error";
    observed: string;
    expected: string;
    severity: string;
    citation: string;
    detail?: string;
  }>;
  summary: {
    total: number;
    pass: number;
    drift: number;
    error: number;
  };
}

// Query snapshots from D1 and build a report
export async function getReport(
  db: D1Database,
  asof?: string,
): Promise<ReportSummary | null> {
  // Default to latest scan if no asof date provided
  let query: D1PreparedStatement;
  let bindings: unknown[];

  if (asof) {
    // ISC-19: Point-in-time query: latest snapshot as of timestamp
    const asofMs = new Date(asof).getTime();
    query = db.prepare(`
      SELECT DISTINCT scan_id FROM snapshots
      WHERE scan_timestamp <= ?
      ORDER BY scan_timestamp DESC
      LIMIT 1
    `);
    bindings = [asofMs];
  } else {
    // Latest scan
    query = db.prepare(`
      SELECT DISTINCT scan_id FROM snapshots
      ORDER BY scan_timestamp DESC
      LIMIT 1
    `);
    bindings = [];
  }

  const scanResult = await query.bind(...bindings).first<{ scan_id: string }>();
  if (!scanResult) return null;

  const scanId = scanResult.scan_id;

  // Fetch all controls for this scan
  const results = await db
    .prepare(
      `
    SELECT scan_id, scan_timestamp, control_id, observed, expected, status, detail
    FROM snapshots
    WHERE scan_id = ?
    ORDER BY control_id ASC
  `,
    )
    .bind(scanId)
    .all<{
      scan_id: string;
      scan_timestamp: number;
      control_id: string;
      observed: string;
      expected: string;
      status: "pass" | "drift" | "error";
      detail?: string;
    }>();

  if (!results.results || results.results.length === 0) return null;

  // Map DB rows to report format (need to enrich with control metadata)
  const controls = results.results.map((row) => ({
    id: row.control_id,
    name: controlNameById(row.control_id),
    status: row.status,
    observed: row.observed,
    expected: row.expected,
    severity: controlSeverityById(row.control_id),
    citation: controlCitationById(row.control_id),
    detail: row.detail,
  }));

  const summary = {
    total: controls.length,
    pass: controls.filter((c) => c.status === "pass").length,
    drift: controls.filter((c) => c.status === "drift").length,
    error: controls.filter((c) => c.status === "error").length,
  };

  return {
    scan_id: scanId,
    scanned_at: new Date(results.results[0].scan_timestamp).toISOString(),
    controls,
    summary,
  };
}

// Metadata lookups — hydrate from baseline
function controlNameById(id: string): string {
  const names: Record<string, string> = {
    "CTL-01": "Minimum TLS version",
    "CTL-02": "Always Use HTTPS",
    "CTL-03": "Security level",
    "CTL-04": "Browser integrity check",
    "CTL-05": "DNSSEC",
    "CTL-06": "WAF managed ruleset deployed",
  };
  return names[id] || id;
}

function controlSeverityById(id: string): string {
  const severities: Record<string, string> = {
    "CTL-01": "high",
    "CTL-02": "high",
    "CTL-03": "medium",
    "CTL-04": "low",
    "CTL-05": "medium",
    "CTL-06": "high",
  };
  return severities[id] || "unknown";
}

function controlCitationById(id: string): string {
  const citations: Record<string, string> = {
    "CTL-01": "SOC 2 CC6.7; ISO 27001 A.8.24",
    "CTL-02": "SOC 2 CC6.7; ISO 27001 A.8.24",
    "CTL-03": "SOC 2 CC6.6; ISO 27001 A.8.9",
    "CTL-04": "SOC 2 CC6.6; ISO 27001 A.8.23",
    "CTL-05": "SOC 2 CC6.6; ISO 27001 A.8.20",
    "CTL-06": "SOC 2 CC6.6; ISO 27001 A.8.20, A.8.23",
  };
  return citations[id] || "unknown";
}

// HTML rendering of report (ISC-18)
export function renderReportHTML(report: ReportSummary): string {
  const controlsHtml = report.controls
    .map(
      (c) => `
    <tr class="control control-${c.status}">
      <td class="control-id">${escapeHtml(c.id)}</td>
      <td class="control-name">${escapeHtml(c.name)}</td>
      <td class="status ${c.status}">${c.status.toUpperCase()}</td>
      <td class="observed">${escapeHtml(c.observed)}</td>
      <td class="expected">${escapeHtml(c.expected)}</td>
      <td class="citation">${escapeHtml(c.citation)}</td>
    </tr>
  `,
    )
    .join("");

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Drift Sentinel Report</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; padding: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
    h1 { color: #333; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
    .summary-card { background: #f9f9f9; padding: 15px; border-radius: 4px; text-align: center; border-left: 4px solid #ddd; }
    .summary-card.pass { border-left-color: #28a745; }
    .summary-card.drift { border-left-color: #ffc107; }
    .summary-card.error { border-left-color: #dc3545; }
    .summary-card .number { font-size: 24px; font-weight: bold; }
    .summary-card .label { font-size: 12px; color: #666; text-transform: uppercase; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { background: #f9f9f9; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: 600; }
    td { padding: 12px; border-bottom: 1px solid #eee; }
    .control-pass { background: rgba(40, 167, 69, 0.05); }
    .control-drift { background: rgba(255, 193, 7, 0.05); }
    .control-error { background: rgba(220, 53, 69, 0.05); }
    .status { font-weight: bold; text-transform: uppercase; font-size: 12px; }
    .status.pass { color: #28a745; }
    .status.drift { color: #ffc107; }
    .status.error { color: #dc3545; }
    .metadata { color: #666; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Drift Sentinel Report</h1>
    <p>Scan: <code>${escapeHtml(report.scan_id)}</code> | Timestamp: ${escapeHtml(report.scanned_at)}</p>

    <div class="summary">
      <div class="summary-card">
        <div class="number">${report.summary.total}</div>
        <div class="label">Total Controls</div>
      </div>
      <div class="summary-card pass">
        <div class="number">${report.summary.pass}</div>
        <div class="label">Pass</div>
      </div>
      <div class="summary-card drift">
        <div class="number">${report.summary.drift}</div>
        <div class="label">Drift</div>
      </div>
      <div class="summary-card error">
        <div class="number">${report.summary.error}</div>
        <div class="label">Error</div>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Control</th>
          <th>Status</th>
          <th>Observed</th>
          <th>Expected</th>
          <th>Citation</th>
        </tr>
      </thead>
      <tbody>
        ${controlsHtml}
      </tbody>
    </table>

    <div class="metadata">
      <p>Drift Sentinel — compliance-as-code for eggrollindex.com</p>
    </div>
  </div>
</body>
</html>
  `;
}

function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  };
  return text.replace(/[&<>"']/g, (c) => map[c]);
}
