import { scanZone } from "./scan";
import { getReport, renderReportHTML } from "./report";

export const REPORT_CACHE_TTL_LATEST_SECONDS = 60;
export const REPORT_CACHE_TTL_ASOF_SECONDS = 86_400;
// Hard bound: latest JSON + HTML plus a modest set of ?asof= windows.
// Unique query strings must not be allowed to grow this Map without limit.
export const REPORT_CACHE_MAX_ENTRIES = 64;

// Isolate-local TTL cache. Cloudflare's Cache API is documented as functional
// for Workers on custom domains and for Pages Functions, not as a guarantee
// on *.workers.dev (https://developers.cloudflare.com/workers/runtime-apis/cache/).
// This Worker is served on workers.dev, so repeated hits are absorbed here.
type ReportCacheEntry = {
  body: string;
  status: number;
  headers: [string, string][];
  expiresAt: number;
};

const reportCache = new Map<string, ReportCacheEntry>();

export function clearReportCache(): void {
  reportCache.clear();
}

export function reportCacheSize(): number {
  return reportCache.size;
}

function reportFormat(request: Request, url: URL): "html" | "json" {
  const requested = url.searchParams.get("format");
  if (requested === "html") return "html";
  if (requested === "json") return "json";
  return request.headers.get("Accept")?.includes("text/html") ? "html" : "json";
}

function reportCacheKey(format: "html" | "json", asofMs?: number): string {
  return asofMs === undefined ? `latest:${format}` : `asof:${asofMs}:${format}`;
}

function reportCacheTtlSeconds(asofMs?: number): number {
  if (asofMs !== undefined && asofMs < Date.now()) {
    return REPORT_CACHE_TTL_ASOF_SECONDS;
  }
  return REPORT_CACHE_TTL_LATEST_SECONDS;
}

function reportCacheMatch(key: string): Response | null {
  const entry = reportCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    reportCache.delete(key);
    return null;
  }
  reportCache.delete(key);
  reportCache.set(key, entry);
  return new Response(entry.body, { status: entry.status, headers: entry.headers });
}

function evictExpiredAndOverflow(): void {
  const now = Date.now();
  for (const [key, entry] of reportCache) {
    if (entry.expiresAt <= now) {
      reportCache.delete(key);
    }
  }
  while (reportCache.size > REPORT_CACHE_MAX_ENTRIES) {
    const oldest = reportCache.keys().next().value;
    if (oldest === undefined) break;
    reportCache.delete(oldest);
  }
}

function reportCachePut(key: string, body: string, response: Response, ttlSeconds: number): void {
  if (reportCache.has(key)) {
    reportCache.delete(key);
  }
  reportCache.set(key, {
    body,
    status: response.status,
    headers: [...response.headers.entries()],
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
  evictExpiredAndOverflow();
}

// Hash both sides to a fixed 32-byte digest, then XOR-fold every byte.
// That avoids short-circuiting on the first mismatch and does not leak the
// secret's length through comparison time.
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const aHash = new Uint8Array(left);
  const bHash = new Uint8Array(right);
  let diff = 0;
  for (let i = 0; i < aHash.byteLength; i++) {
    diff |= aHash[i] ^ bHash[i];
  }
  return diff === 0;
}

export default {
  // ISC-21/22: Cron trigger — scan every 6 hours. Cron does not use SCAN_SECRET.
  async scheduled(event, env, ctx): Promise<void> {
    await scanZone(env);
  },

  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // /scan: trigger a scan and persist results to D1 (ISC-15).
    // POST-only — a GET that writes to the evidence table invites crawlers and
    // drive-by requests to burn subrequest quota and pollute the audit trail.
    // SCAN_SECRET is required; an unset or empty secret fails closed with 503.
    if (url.pathname === "/scan") {
      if (request.method !== "POST") {
        return new Response("Method not allowed. Use POST /scan", { status: 405 });
      }
      if (!env.SCAN_SECRET) {
        return new Response("SCAN_SECRET is not configured", { status: 503 });
      }
      const presented = request.headers.get("Authorization") ?? "";
      const expected = `Bearer ${env.SCAN_SECRET}`;
      if (!(await timingSafeEqual(presented, expected))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const snapshot = await scanZone(env);
      return Response.json(snapshot);
    }

    // ISC-17/18: /report endpoints (JSON + HTML with citations)
    if (url.pathname === "/report") {
      const asof = url.searchParams.get("asof");

      // Validate asof parameter (ISC-20: malformed returns 400). Parsed once
      // here; getReport takes milliseconds so it never re-parses the string.
      let asofMs: number | undefined;
      if (asof) {
        asofMs = new Date(asof).getTime();
        if (isNaN(asofMs)) {
          return new Response("Invalid asof parameter", { status: 400 });
        }
      }

      // Content negotiation: ?format=html or Accept header. Extra query
      // params are ignored so they cannot bust or unbounded-grow the cache.
      const format = reportFormat(request, url);

      // Latest reports: ~60s. Past ?asof= evidence cannot change, so it may live longer.
      const cacheKey = reportCacheKey(format, asofMs);
      const cached = reportCacheMatch(cacheKey);
      if (cached) {
        return cached;
      }

      const report = await getReport(env.DB, asofMs);
      if (!report) {
        return new Response("No scan data found", { status: 404 });
      }

      const ttl = reportCacheTtlSeconds(asofMs);
      const cacheControl = `public, s-maxage=${ttl}`;
      const body = format === "html" ? renderReportHTML(report) : JSON.stringify(report);
      const headers: Record<string, string> =
        format === "html"
          ? {
              "Content-Type": "text/html; charset=utf-8",
              "Content-Security-Policy":
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
              "X-Content-Type-Options": "nosniff",
              "Referrer-Policy": "no-referrer",
              "Cache-Control": cacheControl,
            }
          : {
              "Content-Type": "application/json",
              "X-Content-Type-Options": "nosniff",
              "Cache-Control": cacheControl,
            };

      const response = new Response(body, { headers });
      reportCachePut(cacheKey, body, response, ttl);
      return response;
    }

    // ISC-20: Unknown routes return 404
    return new Response("Not found. Try /report or /scan", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
