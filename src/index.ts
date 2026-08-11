import { scanZone } from "./scan";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // /scan: trigger a scan and persist results to D1 (ISC-15)
    if (url.pathname === "/scan") {
      const snapshot = await scanZone(env);
      return Response.json(snapshot);
    }

    return new Response("Drift Sentinel — try /scan\n");
  },
} satisfies ExportedHandler<Env>;
