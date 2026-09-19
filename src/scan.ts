import { CONTROLS, type Control } from "./baseline";

// One row per control after a scan. `status` is the diff verdict (ISC-11);
// `error` is a third state so an API failure never masquerades as a pass.
export interface ScanResult {
  id: string;
  name: string;
  kind: Control["kind"];
  observed: string;
  expected: string[];
  status: "pass" | "drift" | "error";
  severity: Control["severity"];
  citation: string;
  detail?: string; // error reason, only present when status === "error"
}

export interface ScanSnapshot {
  scan_id: string;
  results: ScanResult[];
}

const CF_API = "https://api.cloudflare.com/client/v4";
export const CF_FETCH_TIMEOUT_MS = 10_000;

interface CfEnvelope {
  success: boolean;
  result: unknown;
  errors?: { code: number; message: string }[];
}

// Single authenticated GET against the zone. Throws on transport or API error
// so the caller records `status: "error"` instead of a false observed value.
async function cfGet(env: Env, path: string, timeoutMs: number): Promise<unknown> {
  const res = await fetch(`${CF_API}/zones/${env.ZONE_ID}/${path}`, {
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  const body = (await res.json()) as CfEnvelope;
  if (!res.ok || !body.success) {
    const reason =
      body.errors?.map((e) => e.message).join("; ") || `HTTP ${res.status}`;
    throw new Error(reason);
  }
  return body.result;
}

// The three `kind`s return three different JSON shapes — this is where that
// difference is absorbed so the rest of the engine sees one flat string.
function readObserved(kind: Control["kind"], result: unknown): string {
  switch (kind) {
    case "setting":
      // GET settings/<name> → { result: { value: "1.2" | "on" | ... } }
      return String((result as { value?: unknown })?.value ?? "");
    case "dnssec":
      // GET dnssec → { result: { status: "active" | "disabled" | ... } }
      return String((result as { status?: unknown })?.status ?? "");
    case "ruleset": {
      // GET rulesets → { result: [ { phase, ... }, ... ] }
      const rulesets = Array.isArray(result) ? result : [];
      const hasManaged = rulesets.some(
        (r) => (r as { phase?: string })?.phase === "http_request_firewall_managed",
      );
      return hasManaged ? "http_request_firewall_managed" : "absent";
    }
  }
}

// ISC-15: Store one row per control. scan_id is a unique identifier for this run.
// The row id must be supplied explicitly: `id TEXT PRIMARY KEY` without NOT NULL
// is SQLite's one PK that admits NULLs, so omitting it silently writes rows with
// a useless NULL key. All rows go in one db.batch() — a scan's evidence lands
// atomically or not at all, never as a partial snapshot.
async function storeSnapshot(
  db: D1Database,
  scanId: string,
  timestamp: number,
  results: ScanResult[],
): Promise<void> {
  const stmt = db.prepare(`
    INSERT INTO snapshots (id, scan_id, scan_timestamp, control_id, observed, expected, status, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  await db.batch(
    results.map((r) =>
      stmt.bind(
        `${scanId}:${r.id}`,
        scanId,
        timestamp,
        r.id,
        r.observed,
        r.expected.join(","),
        r.status,
        r.detail ?? null,
      ),
    ),
  );
}

// Scan every control against the live zone. Fetches run concurrently — six
// subrequests, well inside the Free-plan subrequest budget.
export async function scanZone(
  env: Env,
  options?: { fetchTimeoutMs?: number },
): Promise<ScanSnapshot> {
  const fetchTimeoutMs = options?.fetchTimeoutMs ?? CF_FETCH_TIMEOUT_MS;
  // One clock read: scan_id and scan_timestamp must agree by construction.
  const timestamp = Date.now();
  const scanId = `scan-${timestamp}`;

  const results = await Promise.all(
    CONTROLS.map(async (control): Promise<ScanResult> => {
      const base = {
        id: control.id,
        name: control.name,
        kind: control.kind,
        expected: control.allowed,
        severity: control.severity,
        citation: control.citation,
      };
      try {
        const result = await cfGet(env, control.path, fetchTimeoutMs);
        const observed = readObserved(control.kind, result);
        return {
          ...base,
          observed,
          status: control.allowed.includes(observed) ? "pass" : "drift",
        };
      } catch (err) {
        return {
          ...base,
          observed: "unknown",
          status: "error",
          detail: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  // ISC-15: Persist snapshot (one row per control)
  await storeSnapshot(env.DB, scanId, timestamp, results);

  return { scan_id: scanId, results };
}
