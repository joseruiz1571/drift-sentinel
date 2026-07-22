import { scanZone } from "./scan";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // Temporary probe route — the curl proof for ISC-10/11. Block 4 replaces
    // this with /report (persisted, cited) once D1 is wired.
    if (url.pathname === "/scan") {
      const results = await scanZone(env);
      return Response.json(results);
    }

    return new Response("Drift Sentinel — try /scan\n");
  },
} satisfies ExportedHandler<Env>;
