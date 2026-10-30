# Next.js web Workers

Landing (`runlater.io`, plus canonical www redirects) and documentation
(`docs.runlater.io`) are independent Next.js 16 applications, built with
`@opennextjs/cloudflare` for the existing `runlater-web-landing` and
`runlater-web-docs` Workers. The API Rust/WASM Worker and JavaScript MCP gateway
are separate and unchanged. No API, OAuth, egress, storage or secret bindings are
available to either web Worker. This migration does not activate Agent Auth or
change public Worker Fetch HTTPS delivery/trial availability.

## Framework choice (2026-10-30)

[Cloudflare's current guide](https://developers.cloudflare.com/workers/framework-guides/web-apps/nextjs/)
recommends vinext by default. It describes vinext as a beta Vite reimplementation
of Next.js APIs and asks production users to review compatibility. This migration
chooses [OpenNext](https://opennext.js.org/cloudflare) to run the actual Next.js
compiler/runtime requested here, with standard App Router source. OpenNext
supports Next.js 16 and its Node runtime on Workers through `nodejs_compat`.
This is an explicit runtime choice, not a claim that OpenNext is Cloudflare's
current default. Future vinext adoption should be a separate evaluated change.

Pinned versions and the lockfile make the build reproducible. The scoped glob
override patches OpenNext's build-only `@node-minify/core` transitive dependency
(GHSA-5j98-mcp5-4vw2); remove it once upstream updates its pin.

## Sources and preservation matrix

| Surface | Source / behavior | Verification |
| --- | --- | --- |
| Landing and docs `/` | Existing `web/{landing,docs}/index.html` supplies unchanged React page content and head | Browser compares title, SEO tags, links, IDs, code blocks |
| Shared design | `web/shared/site.css`, icon and clipboard enhancement retain exact bytes | All public asset bytes compared over workerd; desktop/mobile screenshots |
| Client-first Connect | CTA still targets docs `/#connect`; no bare authorization signup | Existing source checks plus browser link checks |
| Agent guides, JSON, schemas, llms, robots and module trees | Existing `scripts/discovery.mjs` remains canonical | Existing discovery/link/schema tests plus every public asset fetched and compared |
| www and HTTP canonicalization | Custom Worker runs before every asset/Next request; 308 preserves method/path/query | Wrapper tests and 10 local runtime redirect cases |
| `/index.html`, `/index` | 307 to `/` preserving query | Local runtime checks |
| `/404.html`, `/404/`, `/404` | 307 aliases to `/404`; directly addressed legacy document returns 200 | Baseline static runtime compared with new local runtime |
| Unknown paths | Next `not-found` renders original per-site 404 content with HTTP 404 | HTTP and browser checks |
| Security | Original restrictions plus per-response script nonce; no unsafe-inline/eval | Nonce spoofing/uniqueness unit checks and browser CSP checks |
| Cache behavior | Static resources retain 300 seconds; nonce-bearing HTML is private/no-store | HTTP tests |

`web/next/app` and configs are the maintained Next source. `scripts/build-web.mjs`
generates independent per-site `app/`, `public/`, package/config files, `.next/`
and `.open-next/` output (all ignored). Only explicitly named HTML sources enter
the discovery output; build files and deployment configuration are never copied
to public assets. HTML inputs are repository-owned, never supplied by a request.
App Router supplies charset and viewport once; the source copies are omitted
when rendering the head to prevent duplicate metadata. These are React elements
rendered by Next.js, not raw HTML responses passed through by a route handler.
Keeping the content inputs unchanged avoids duplicating or rewriting Connect,
trial and delivery guidance. Edit those HTML inputs for content changes.

Pages render per request so Next can nonce its runtime scripts. The Worker
replaces incoming CSP/nonce headers, adds security headers to Next/asset/error
responses, and disables shared HTML caching. No R2, ISR, self-service binding,
Images, queues or provisioning are required. Existing links are native anchors,
so `connect-src 'none'` remains compatible with the pages. Adding client-side
Next navigation, server actions or fetches later requires a deliberate CSP review.

## Local validation

Use Node 22+ (CI uses Node 22), from the repository root:

```sh
npm ci
npm run test:web
npm run test:web-next
npm run build:web
npm run test:web-local
npx playwright install chromium
npm run test:web-browser
npm run preview:web -- landing
# In another terminal, if desired:
npm run preview:web -- docs
```

`build:web` runs the actual Next production build and OpenNext adapter separately
for each app; it never deploys. Preview uses local workerd on loopback ports
4173/4174. Browser QA uses production Workers on 14183/14184, aborts external
requests, and saves screenshots to ignored `build/web-qa/`. Local HTTP QA uses
14173–14175. `test:web-next` prepares inputs but does not compile; run build before
runtime checks. No live API, MCP, OAuth connection or task creation is exercised.
There is no separate TypeScript/lint project for these JavaScript web sources;
Next's build and Node syntax checks cover compilation, with behavior covered by
the tests. Keep the lockfile synchronized after dependency changes.

## Reviewed rollout only — no deployment performed by this change

1. Review/merge after independent QA and CI. Rebase onto current main first;
   retain unrelated OAuth fixes such as PR81. Record the exact merge SHA.
2. In the authorized deployment environment, record each existing web Worker's
   current version ID for rollback. Confirm existing custom domains are still
   attached to the same Worker names; do not change DNS or routes.
3. Run the local validation above and dry-run bundles:
   `npx wrangler deploy --dry-run --config web/landing/wrangler.jsonc` and
   `npx wrangler deploy --dry-run --config web/docs/wrangler.jsonc`.
   Check compressed bundle size and account CPU allowance. SSR replaces the old
   landing-only 10ms CPU cap; the configs use the account's default CPU limit.
4. Only with deployment authorization, deploy each existing Worker with
   `npx wrangler deploy --config web/landing/wrangler.jsonc` and the corresponding
   docs config. Deploying these configs changes only those web Worker versions;
   no new bindings or custom routes are declared. Never run the auto-migration
   CLI, resource-creation commands, or API/MCP deployment as part of this rollout.
5. Smoke-test both public domains, www redirects with encoded queries, HEAD,
   discovery/Markdown MIME and hashes, missing URLs, CSP and clipboard behavior.
   Compare public release guidance and canonical/OG metadata. Monitor web errors.

Rollback: use `wrangler rollback <recorded-version-id> --config <site-config>`
for each affected web Worker, then repeat the smoke checks. Rollback both if the
paired content release needs to remain synchronized. No API/data rollback or
schema migration is involved. Source rollback is a revert followed by a build
of the previous static web release; `build:discovery` still produces that output.
The older `web/landing/worker.mjs` is retained as the tested static-release
rollback reference and is not the new deployment entrypoint.
