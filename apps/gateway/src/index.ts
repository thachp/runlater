// Public entry for agents. Serves Agent Auth discovery and the agent endpoints, and turns
// capability executions into signed calls on the private Rust API (API binding).

import { importSigningKey } from "./api";
import { BASE_PATH, createAuth, type AuthEnv } from "./auth";

export { AuthStore } from "./store";

export interface Env extends AuthEnv {
  /** Hex-encoded 32-byte Ed25519 seed; its public key is the API's GATEWAY_PUBLIC_KEY. */
  ASSERTION_PRIVATE_KEY: string;
  REGISTER_RATE: RateLimit;
}

/** Agent Auth endpoints an autonomous agent needs; everything else is not served. */
const AGENT_ROUTES = new Set([
  "/agent/register",
  "/agent/status",
  "/agent/revoke",
  "/agent/rotate-key",
  "/agent/reactivate",
  "/capability/list",
  "/capability/describe",
  "/capability/execute",
  "/host/revoke",
  "/host/rotate-key",
]);

/** A schedule_http body can be 64 KiB of string; leave room for JSON escaping. */
const MAX_BODY_BYTES = 192 * 1024;

const json = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
const error = (status: number, code: string, message: string) => json({ error: code, message }, status);

let keyCache: { seed: string; key: Promise<CryptoKey> } | undefined;
function signingKey(env: Env): Promise<CryptoKey> {
  if (keyCache?.seed !== env.ASSERTION_PRIVATE_KEY) {
    keyCache = { seed: env.ASSERTION_PRIVATE_KEY, key: importSigningKey(env.ASSERTION_PRIVATE_KEY) };
  }
  return keyCache.key;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      const api = await env.API.fetch("https://api.internal/health");
      return json(
        { service: "runlater-gateway", status: "ok", api: api.ok ? "ok" : "unavailable" },
        api.ok ? 200 : 503,
      );
    }

    const isDiscovery = url.pathname === "/.well-known/agent-configuration";
    const route = url.pathname.startsWith(BASE_PATH + "/") ? url.pathname.slice(BASE_PATH.length) : null;
    if (!isDiscovery && !(route && AGENT_ROUTES.has(route))) return error(404, "not_found", "no such route");

    const length = Number(request.headers.get("Content-Length") ?? 0);
    if (length > MAX_BODY_BYTES) return error(413, "too_large", "request body is too large");

    if (route === "/agent/register") {
      const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const { success } = await env.REGISTER_RATE.limit({ key: ip });
      if (!success) return error(429, "rate_limited", "too many registrations; try again shortly");
    }

    let key: CryptoKey;
    try {
      key = await signingKey(env);
    } catch {
      return error(500, "misconfigured", "assertion signing key is not configured");
    }
    const auth = createAuth(env, ctx, key);

    if (isDiscovery) {
      const config = await auth.api.getAgentConfiguration();
      // Advertise only the endpoints served above.
      if (config.endpoints) {
        config.endpoints = Object.fromEntries(
          Object.entries(config.endpoints).filter(([, u]) => AGENT_ROUTES.has(new URL(u).pathname.slice(BASE_PATH.length))),
        );
      }
      return json(config);
    }
    return auth.handler(request);
  },
} satisfies ExportedHandler<Env>;
