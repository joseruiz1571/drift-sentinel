import { scanZone } from "./scan";
import { getReport, renderReportHTML } from "./report";

export default {
  // ISC-21/22: Cron trigger — scan every 6 hours
  async scheduled(event, env, ctx): Promise<void> {
    await scanZone(env);
  },

  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // /scan: trigger a scan and persist results to D1 (ISC-15).
    // POST-only — a GET that writes to the evidence table invites crawlers and
    // drive-by requests to burn subrequest quota and pollute the audit trail.
    // If SCAN_SECRET is configured, the caller must present it as a bearer token.
    if (url.pathname === "/scan") {
      if (request.method !== "POST") {
        return new Response("Method not allowed. Use POST /scan", { status: 405 });
      }
      if (env.SCAN_SECRET) {
        const auth = request.headers.get("Authorization");
        if (auth !== `Bearer ${env.SCAN_SECRET}`) {
          return new Response("Unauthorized", { status: 401 });
        }
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

      const report = await getReport(env.DB, asofMs);
      if (!report) {
        return new Response("No scan data found", { status: 404 });
      }

      // Content negotiation: ?format=html or Accept header
      const format =
        url.searchParams.get("format") ||
        (request.headers.get("Accept")?.includes("text/html") ? "html" : "json");

      if (format === "html") {
        return new Response(renderReportHTML(report), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      return Response.json(report);
    }

    // ISC-20: Unknown routes return 404
    return new Response("Not found. Try /report or /scan", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
