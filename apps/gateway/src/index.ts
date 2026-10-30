// Public entry for agents: Agent Auth host, capabilities and MCP (phase 4).
// Every task operation is forwarded to the private Rust API over the API binding.

export interface Env {
  API: Fetcher;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      const api = await env.API.fetch("https://api.internal/health");
      return Response.json(
        { service: "runlater-gateway", status: "ok", api: api.ok ? "ok" : "unavailable" },
        { status: api.ok ? 200 : 503 },
      );
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
