# RunLater host ownership and web publication

The current source migration uses **Next.js + OpenNext** for the existing landing
and docs Workers. It has not been deployed. Follow [WEB-NEXTJS.md](WEB-NEXTJS.md)
for current build, local QA, deployment and rollback instructions. The static
publication/consolidation notes below are historical release evidence and are not
the procedure for deploying the Next.js bundles. No routes or resources should be
created or changed for this migration.

| Host | Role | Worker / source | State |
| --- | --- | --- | --- |
| runlater.io | Landing + discovery | runlater-web-landing / web/landing + generated discovery | Published; shared-host patch pending reviewed rollout |
| docs.runlater.io | Documentation + contracts/client | runlater-web-docs / web/docs + generated discovery | Published |
| api.runlater.io | Retained restricted-alpha Rust API | runlater-alpha-api / production profile | Deployed operator-only alpha |
| receiver-alpha.runlater.io/callback | Exact owned synthetic receiver | runlater-alpha-receiver / alpha/receiver | Deployed; not a customer receiver |
| www.runlater.io | HTTPS308 redirect to apex | runlater-web-landing / web/landing/worker.mjs | Move from legacy redirect Worker only after review |

## Build and review

`npm run build:discovery` deterministically assembles `build/discovery/landing` and `build/discovery/docs`. Use these roots, not the raw web folders: they include versioned descriptors, schemas, shared styling, llms.txt, Markdown quickstart, downloadable client, local OpenAPI, defensive `_headers` and404 pages. The output ownership marker prevents deleting an unrelated directory; rebuilt owned subtrees remove stale assets. No build command deploys or contacts a host.

`npm run test:web` checks schema/link consistency, custom authority states, exact signed client wires/proofs, unsafe resource inputs, private file handling, response bounds and308 preservation. `npm run test:web-local` runs actual local Wrangler static-asset servers and checks MIME, headers and missing-path404 behavior; remote bindings are disabled and disposable local state is separate from saved development data. `npm run preview:web -- landing` and `npm run preview:web -- docs` provide loopback-only visual previews. Desktop1440px, mobile390px and narrow320px were inspected with the real browser; copy feedback and keyboard skip navigation were verified. Browser screenshots are review evidence, not runtime guarantees.

Active Wrangler configs live under web/landing and web/docs; web/redirect is retained only as a legacy rollback reference. Docs use the native Assets service without a main script. The landing Worker has only an ASSETS binding and a hostname handler, with assets.run_worker_first=true so every www request (including existing files and HEAD) redirects before static serving. Apex responses pass through unchanged from ASSETS, including CSP and404. Neither static surface has DO/Queue/service bindings, secrets or credentials. Workers.dev, version previews and paid logs/traces are disabled. Static responses use a short300-second cache lifetime; no API proxy or client-side API fetch is embedded. The shared landing Worker has10ms CPU and no API/storage bindings. web/redirect remains a legacy rollback reference; do not deploy it as an additional public service after consolidation. No analytics/font/third-party runtime requests are introduced.

## Reviewed publication procedure

1. Select the authorized Cloudflare account and inspect Workers, custom domains, exact DNS names and zone routes. Refuse preexisting `runlater-web-*` or runlater.io/docs/www ownership collisions unless explicitly reviewed. Capture the returned IDs/tags and baseline in a private publication ledger. Preserve api.runlater.io, receiver-alpha.runlater.io and their Workers, namespace, Queue, secrets and policies exactly.
2. Pin the independently reviewed source SHA, require a clean tree, run build/tests and Wrangler dry-run for each config. Use the existing authenticated network context; do not create a provider token or expand grants.
3. For this consolidation, deploy only the shared landing module and its generated static tree to the existing landing Worker; leave docs unchanged. Future static releases upload only the appropriate generated trees to the two active web Workers. No API profile build/deploy is part of this operation. Verify workers.dev/previews disabled and record returned Worker identities before the next mutation.
4. The final exact domain ownership is runlater.io and www.runlater.io → runlater-web-landing, docs.runlater.io → runlater-web-docs. For consolidation, upsert only the existing www custom-domain mapping after the shared landing deployment is verified; leave apex/docs domain IDs unchanged. No wildcard routes. Cloudflare manages the associated DNS/TLS records; capture those returned IDs and verify host ownership. Do not overwrite an unrelated preexisting record. Do not broaden HSTS to include subdomains.
5. Verify HTTPS200 for the two homepages, stylesheet, favicon, llms.txt, descriptor, pricing status, contracts/schemas and Markdown/client links. Check content types/nosniff/CSP, direct anchor navigation and a missing-path404. A www URL such as `/guide/deep?q=a%20b&next=2` must return308 with exactly `https://runlater.io/guide/deep?q=a%20b&next=2`; do not follow it for the assertion. Confirm API health and its Worker tags unchanged using bounded read-only checks. No new task, identity or callback is needed.
6. Record exact deployed SHA, URLs, IDs and verification evidence. Issues13/26 were closed after the original actual publication; later hosting changes must preserve those verified links and semantics. Source presence alone is not publication.

## Rollback and cost boundary

On initial publication failure, remove only newly created static custom domains/associated records and Workers after ID/tag/baseline checks; preserve the retained API. Domain removal may automatically remove its DNS record: reconcile missing records through complete inventory rather than blind deletion. Never force-delete or relax an ownership check. On later content updates, roll back only the static/redirect Worker to its recorded previous version; no database rollback, grant reset or key rotation belongs here.

These static surfaces share the existing total US$20/month RunLater budget. The shared landing hostname handler runs for each landing/www request before native Assets; its10ms CPU limit is not a traffic or account-wide spending cap. Docs remain assets-only. Consolidating removes a separately managed redirect Worker but does not promise a billing reduction. Do not upgrade the plan, enable paid logging or add a service as part of publication. No API credentials, operator public identity, grant IDs, private keys or provider account IDs belong in published assets.

## Product boundary

The API supports approved Ed25519 operators and only the owned side-effect-free synthetic receiver. Its current finite identity/grant is not public signup or a commercial trial. Self-service enrollment, customer destination verification and paid credit purchases are later increments. See the public agent quickstart for actual signing and lifecycle semantics. The local OpenAPI remains a loopback bearer/fixture contract, separately labelled from the hosted alpha contract subset.

## Shared apex/www rollout and rollback

The original PR37 publication passed28 live checks and left www on the separate runlater-web-www Worker. This follow-up changes only landing hosting. Capture the existing landing and legacy-www tags/versions plus exact custom-domain ID/service and DNS ID. Deploy the reviewed shared landing build before touching the www mapping. Verify apex assets/CSP/404 and API/docs unchanged. Repoint the existing www custom domain to runlater-web-landing with the supported custom-domain upsert; do not delete the domain or its DNS record first. Verify TLS, GET/HEAD, root/existing assets, encoded path/query and duplicate query values return the canonical308 without an asset body. Confirm the custom-domain inventory now maps BOTH apex/www to landing. Only then delete runlater-web-www with its captured unchanged tag, after verifying no domains/routes remain attached. Preserve DNS and all API/receiver resources.

If mapping or redirect verification fails, retain the old redirect Worker, restore the www mapping to its captured service, and roll the landing deployment back to its captured previous version if needed. No grant, key, database or task state changes belong here. If the old Worker tag changed or another binding/domain references it, stop cleanup and report it rather than force deletion.
