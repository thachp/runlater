// The OAuth consent page hosted MCP clients open once. There is no account: approving creates a
// new owner, and its grant is that owner's identity from then on, as a key pair is for an
// Agent Auth agent. Each approval is a new project with its own trial.

import { AuthorizationError, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { McpProps } from "./mcp";

export interface ConsentEnv {
  OAUTH_PROVIDER: OAuthHelpers;
  /** Per-IP limit on the OAuth endpoints, separate from Agent Auth registration's. */
  OAUTH_RATE: RateLimit;
}

const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

function page(title: string, body: string, headers: Headers = new Headers(), status = 200): Response {
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  // No form-action: browsers apply it to the redirect after the POST, and that goes to the
  // client's own redirect URI (https, loopback or an app scheme). The handle's binding cookie
  // is what stops a forged post.
  headers.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
  headers.set("X-Frame-Options", "DENY");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)} · RunLater</title><style>
:root{color-scheme:light dark;--fg:#16181d;--muted:#5d6370;--bg:#f7f7f5;--card:#fff;--line:#e3e3df;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--fg:#ecedf0;--muted:#a0a5b0;--bg:#121318;--card:#1b1d24;--line:#2c2f39;--accent:#7d9cf0}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box}
main{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;max-width:440px;width:100%;box-sizing:border-box}
h1{font-size:21px;margin:0 0 12px}p{margin:0 0 12px}.muted{color:var(--muted);font-size:14px}code{font-size:14px;overflow-wrap:anywhere}
.warn{border-left:3px solid #c98a12;padding:6px 12px;font-size:14px}
.actions{display:flex;gap:10px;margin-top:20px}button{font:inherit;border-radius:8px;padding:9px 16px;cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--fg)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
</style></head><body><main>${body}</main></body></html>`;
  return new Response(html, { status, headers });
}

function failure(message: string, status = 400): Response {
  return page("Can't connect", `<h1>Can't connect</h1><p>${escape(message)}</p>`, undefined, status);
}

/** GET shows the consent page; POST approves or declines it. */
export async function handleAuthorize(request: Request, env: ConsentEnv): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  try {
    if (request.method === "GET") {
      let authRequest;
      try {
        authRequest = await oauth.parseAuthRequest(request);
      } catch (e) {
        // The client sent a bad authorization request; its reason helps whoever set it up.
        return failure(`This sign-in request isn't valid${e instanceof Error ? `: ${e.message}` : "."}`);
      }
      const about = await oauth.describeConsent(authRequest);
      const { handle, headers } = await oauth.beginConsent(authRequest);
      const name = about.clientDomain ? `${about.clientName} (${about.clientDomain})` : about.clientName;
      const local = about.redirectIsLoopback
        ? `<p class="warn">This app is on your computer (<code>${escape(about.redirectHost)}</code>). Any local program could be listening there, whatever it calls itself.</p>`
        : "";
      return page(
        "Connect",
        `<h1>Connect ${escape(name)} to RunLater?</h1>
<p>It will be able to schedule HTTP requests, crons and watches, and read their results. They run from a new RunLater project with a free trial: 100 delivery attempts over 7 days.</p>
<p class="muted">There's no account. This connection is the project's only key: if it is removed, so is access to the project.</p>
<p class="muted">You'll return to <code>${escape(about.redirectHost)}</code>.</p>${local}
<form method="post"><input type="hidden" name="handle" value="${escape(handle)}">
<div class="actions"><button class="primary" name="action" value="approve">Connect</button><button name="action" value="deny">Cancel</button></div></form>`,
        headers,
      );
    }
    if (request.method !== "POST") return failure("Unsupported method.", 405);

    const form = await request.formData();
    const handle = String(form.get("handle") ?? "");
    if (form.get("action") !== "approve") {
      const { redirectTo, headers } = await oauth.denyConsent(request, handle);
      headers.set("Location", redirectTo);
      return new Response(null, { status: 302, headers });
    }
    const { request: authRequest, headers } = await oauth.approveConsent(request, handle);
    const id = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const props: McpProps = { owner: `mcp:${id}` };
    const { redirectTo } = await oauth.completeAuthorization({ request: authRequest, userId: id, metadata: {}, scope: [], props });
    headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers });
  } catch (e) {
    if (e instanceof AuthorizationError) return failure("This sign-in link has expired or was already used. Start again from your app.");
    console.error("consent failed", e);
    return failure("Something went wrong on RunLater's side. Start again from your app.", 500);
  }
}
