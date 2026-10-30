# Legacy MCP public ingress retirement

This intentionally breaks all existing hosted MCP clients. On the canonical MCP
origin, `/authorize`, `/oauth/token`, both OAuth discovery paths, `/sse`,
`/messages`, and `/mcp` return HTTP 410 with `legacy_mcp_retired` for every method,
including requests with query strings or bearer credentials. No OAuth challenge,
redirect, rate-limit call, Durable Object request, or provider action occurs.
Agent Auth remains incomplete and unavailable; this change does not enable it.

`/health` reports `configured: false`, `mode: legacy_retired`,
`legacy_public_ingress_retired: true`, and `agent_auth_ready: false`.
`cleanup_configured` reports the existing gateway configuration check only; it
is not evidence of a successful private-key match or a completed cleanup queue.
Existing source feature flags remain informational, not public readiness.

The gate is independent of `MCP_ENABLED` and `MCP_OAUTH_ENABLED`. Keep both at
their existing production values. Constructor initialization, the OAuth instance,
revocation pre-arming/draining/retry alarms, storage, keys and bindings remain.
Pending cleanup count is unknown. Retain internals until a separately authorized
state inventory proves removal safe. No credentials, projects, or tasks are
revoked or deleted by this retirement; the API task execution service is unchanged.

## Deployment boundary and rollback

Production baseline: source `dccdb5a4e65de384220cfd5631d3129f2d3bb1ff`, live version
`a36ee403-fce2-4a12-840c-a7fee8f4e8a7`, MCP namespace
`ac04370472e7475fad087c2dec6b6155`.

Deploy only `runlater-mcp` after the requested independent QA and parent diff
review. Build with `node scripts/build-mcp.mjs`. Do not deploy the example config:
it contains disabled values/placeholders. Do not run the repository root deploy.

Minimum Wrangler method: generate an ignored, MCP-only production config from the
current nonsecret Worker settings, pointing `main` to this built bundle. Preserve
all existing settings, compatibility flags/date, limits, named secret bindings,
rate-limit bindings and MCP_HUB namespace/class; no migrations or new bindings.
Use `wrangler versions upload --config <that-config> --keep-vars`, compare the new
version's nonsecret metadata with the live version, then
`wrangler versions deploy <new-version-id>@100% --config <that-config> --yes`.
Do not supply a secrets file or read secret values. Keep existing variable values,
including the enable flags; source provenance may be updated to the tested commit
only if explicitly recorded as the single intentional metadata difference.
`--keep-vars` alone is insufficient if the config replaces other live settings.
Existing routes, domains, workers.dev, previews and observability stay unchanged.

After activation, canary all seven paths for 410 without Location or
WWW-Authenticate; GET `/health` must report retired and Agent Auth not ready.
Check the API's existing public health endpoint remains healthy, without creating
a test identity or remote task. Do not inspect private DO credential storage.

Rollback: deploy the previous version at 100% using
`wrangler versions deploy a36ee403-fce2-4a12-840c-a7fee8f4e8a7@100% --config <that-config> --yes`.
This restores legacy public ingress and its security exposure. No settings,
secrets, namespaces, storage or API worker changes are needed for rollback.
