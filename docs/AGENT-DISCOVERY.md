# Published agent discovery contract

Issues13/26 prepare the landing/docs publication from this repository. `npm run build:discovery` assembles the two static roots without network calls or provider mutations. Hosted URLs are release targets until actual deployment verification; the retained restricted-alpha API is separately deployed. See [host publication and rollback](HOSTS.md) and the [Next.js web build and rollout](WEB-NEXTJS.md).

The service descriptor at `/runlater-service.v1.json` is RunLater-owned v1.1 metadata. It explicitly distinguishes operator-only task/enrollment capability, owned synthetic delivery, local fixtures and disabled public signup/payments. It is a published configuration snapshot, not a live entitlement probe or installed executor. Its authority flags remain false. llms.txt follows a community filename proposal and grants no execution or payment authority.

The separate `/agent/alpha.v1.json` and schema describe the actual hosted task/enrollment route subset, exact Ed25519 framing and body definitions. They are custom metadata, not an industry authorization standard or a claim of exhaustive administration API coverage. `/agent/quickstart.md` and the executable Node client show safe public discovery/health followed by explicitly invoked operator-approved enrollment and synthetic scheduling. Private material stays local; no key generation, automatic retry/task loop, arbitrary endpoint, wallet delegation or payment action occurs.

`/openapi.json` remains byte-identical to the canonical local emulator contract. `/agent/tools.v1.json` retains its local bearer/fixture tools and clearly disabled nonbinding public-onboarding/payment proposals; it now links to the hosted alpha contract rather than advertising those local bindings as hosted ones. This preserves the local canonical schema without silently converting fixture credentials into production authority. Callback-v2 keys are distinct from request-signing keys.

The pricing-status schema still permits no offered price/currency/trial, payment methods, live purchases or auto-top-up. The provisioned24-hour operator/20-attempt internal allowance is not a public commercial offer. Unknown/disabled capabilities are not inferred from tool names or discovery text. Public registration and purchases require their separately reviewed implementations and activation.

Tests validate schema conformance, deterministic assembly, offline links including page anchors, local OpenAPI identity, hosted body definitions, fixed origin, exact request/proof bytes, bounded responses and redaction. Actual local Wrangler HTTP checks verify static MIME/security headers and404 behavior. These source/local checks do not replace TLS/link verification after publication or another controlled real delivery campaign.

## MCP implementation source

[The separate MCP server](MCP.md) implements legacy HTTP+SSE with typed signed-task tools. Its intended endpoint is `https://mcp.runlater.io/sse`; hosted publication and authorized live verification remain pending. The local/proposed tool bundle above is still non-executable metadata, not this MCP server or an authorization grant.
