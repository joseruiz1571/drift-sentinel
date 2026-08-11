import { scanZone } from "./scan";
import { getReport, renderReportHTML } from "./report";

export default {
  // ISC-21/22: Cron trigger — scan every 6 hours
  async scheduled(event, env, ctx): Promise<void> {
    await scanZone(env);
  },

  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // /scan: trigger a scan and persist results to D1 (ISC-15)
    if (url.pathname === "/scan") {
      const snapshot = await scanZone(env);
      return Response.json(snapshot);
    }

    // ISC-17/18: /report endpoints (JSON + HTML with citations)
    if (url.pathname === "/report") {
      const asof = url.searchParams.get("asof");

      // Validate asof parameter (ISC-20: malformed returns 400)
      if (asof) {
        const asofDate = new Date(asof);
        if (isNaN(asofDate.getTime())) {
          return new Response("Invalid asof parameter", { status: 400 });
        }
      }

      const report = await getReport(env.DB, asof ?? undefined);
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
