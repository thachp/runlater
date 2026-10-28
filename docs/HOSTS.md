# RunLater host ownership and static publication

| Host | Role | Worker / source | State |
| --- | --- | --- | --- |
| runlater.io | Landing + discovery | runlater-web-landing / web/landing + generated discovery | Prepared for reviewed publication |
| docs.runlater.io | Documentation + contracts/client | runlater-web-docs / web/docs + generated discovery | Prepared for reviewed publication |
| api.runlater.io | Retained restricted-alpha Rust API | runlater-alpha-api / production profile | Deployed operator-only alpha |
| receiver-alpha.runlater.io/callback | Exact owned synthetic receiver | runlater-alpha-receiver / alpha/receiver | Deployed; not a customer receiver |
| www.runlater.io | HTTPS308 redirect to apex | runlater-web-www / web/redirect | Prepared for reviewed publication |

## Build and review

`npm run build:web` deterministically assembles `build/discovery/landing` and `build/discovery/docs`. Use these roots, not the raw web folders: they include versioned descriptors, schemas, shared styling, llms.txt, Markdown quickstart, downloadable client, local OpenAPI, defensive `_headers` and404 pages. The output ownership marker prevents deleting an unrelated directory; rebuilt owned subtrees remove stale assets. No build command deploys or contacts a host.

`npm run test:web` checks schema/link consistency, custom authority states, exact signed client wires/proofs, unsafe resource inputs, private file handling, response bounds and308 preservation. `npm run test:web-local` runs actual local Wrangler static-asset servers and checks MIME, headers and missing-path404 behavior; remote bindings are disabled and disposable local state is separate from saved development data. `npm run preview:web -- landing` and `npm run preview:web -- docs` provide loopback-only visual previews. Desktop1440px, mobile390px and narrow320px were inspected with the real browser; copy feedback and keyboard skip navigation were verified. Browser screenshots are review evidence, not runtime guarantees.

Three independent Wrangler configs live under web/landing, web/docs and web/redirect. Static workers use the native Assets service with no main script, DO/Queue/service bindings, secrets or credentials. Workers.dev, version previews and paid logs/traces are disabled. Static responses use a short300-second cache lifetime; no API proxy or client-side API fetch is embedded. The small www Worker has10ms CPU and no bindings. No analytics/font/third-party runtime requests are introduced.

## Reviewed publication procedure

1. Select the authorized Cloudflare account and inspect Workers, custom domains, exact DNS names and zone routes. Refuse preexisting `runlater-web-*` or runlater.io/docs/www ownership collisions unless explicitly reviewed. Capture the returned IDs/tags and baseline in a private publication ledger. Preserve api.runlater.io, receiver-alpha.runlater.io and their Workers, namespace, Queue, secrets and policies exactly.
2. Pin the independently reviewed source SHA, require a clean tree, run build/tests and Wrangler dry-run for each config. Use the existing authenticated network context; do not create a provider token or expand grants.
3. Upload only the two generated static trees and redirect module to their three dedicated Workers. No API profile build/deploy is part of this operation. Verify workers.dev/previews disabled and record returned Worker identities before the next mutation.
4. Attach exact custom domains runlater.io → runlater-web-landing, docs.runlater.io → runlater-web-docs, www.runlater.io → runlater-web-www using the supported provider API. No wildcard routes. Cloudflare manages the associated DNS/TLS records; capture those returned IDs and verify host ownership. Do not overwrite an unrelated preexisting record. Do not broaden HSTS to include subdomains.
5. Verify HTTPS200 for the two homepages, stylesheet, favicon, llms.txt, descriptor, pricing status, contracts/schemas and Markdown/client links. Check content types/nosniff/CSP, direct anchor navigation and a missing-path404. A www URL such as `/guide/deep?q=a%20b&next=2` must return308 with exactly `https://runlater.io/guide/deep?q=a%20b&next=2`; do not follow it for the assertion. Confirm API health and its Worker tags unchanged using bounded read-only checks. No new task, identity or callback is needed.
6. Record exact deployed SHA, URLs, IDs and verification evidence. Only then treat hosted-link acceptance in issues13/26 as satisfied. Source presence alone is not publication.

## Rollback and cost boundary

On initial publication failure, remove only newly created static custom domains/associated records and Workers after ID/tag/baseline checks; preserve the retained API. Domain removal may automatically remove its DNS record: reconcile missing records through complete inventory rather than blind deletion. Never force-delete or relax an ownership check. On later content updates, roll back only the static/redirect Worker to its recorded previous version; no database rollback, grant reset or key rotation belongs here.

These static surfaces share the existing total US$20/month RunLater budget. Native Assets caching avoids application/API invocation for static files, but public traffic and the www Worker are not an account-wide hard spending cap. Do not upgrade the plan, enable paid logging or add a service as part of publication. No API credentials, operator public identity, grant IDs, private keys or provider account IDs belong in published assets.

## Product boundary

The API supports approved Ed25519 operators and only the owned side-effect-free synthetic receiver. Its current finite identity/grant is not public signup or a commercial trial. Self-service enrollment, customer destination verification and paid credit purchases are later increments. See the public agent quickstart for actual signing and lifecycle semantics. The local OpenAPI remains a loopback bearer/fixture contract, separately labelled from the hosted alpha contract subset.
