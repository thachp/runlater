# Host plan — no provisioning performed

| Host | Intended role | Source | Present state |
| --- | --- | --- | --- |
| runlater.io | Static landing page | web/landing | Local source only |
| docs.runlater.io | Static documentation | web/docs | Local source only |
| api.runlater.io | Rust HTTP API | src/runtime.rs | Local fixtures only |
| www.runlater.io | HTTPS 308 redirect to apex | web/redirect | Local tested source only |

Deploy static pages separately from the API so documentation does not share secrets or API bindings. Future reviewed configuration should use exact host routes and managed HTTPS certificates. No wildcard routes. The www Worker preserves the original path and query and canonicalizes scheme/host. API configuration currently has no production routes and workers.dev is disabled.

Before hosting: verify domain ownership and current DNS, preserve existing records, approve exact deployment/provisioning actions and costs, complete API authentication/outbound/network/limits launch gates, replace fixture-only configuration, and review immutable artifact promotion. Never deploy public fixture tokens as customer credentials. The local Wrangler configuration is not a production template. Do not point live DNS to this prototype.
