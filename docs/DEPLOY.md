# Deploying RunLater

Three Workers, each with `staging` and `production` environments in its `wrangler.jsonc`:

| Worker | Staging | Production | Public? |
| --- | --- | --- | --- |
| `apps/api` | `runlater-api-staging` | `runlater-api-production` | No — service binding only |
| `apps/gateway` | `runlater-gateway-staging` | `runlater-gateway-production` | Yes |
| `apps/web` | `runlater-web-staging` | `runlater-web-production` | Yes |

[`deploy.yml`](../.github/workflows/deploy.yml) runs after CI passes on `main`. It deploys staging, then
production once the `production` environment's reviewer approves. Each environment deploys
**api → gateway → web** ([`deploy-env.yml`](../.github/workflows/deploy-env.yml)); the gateway's service
binding fails if the API Worker doesn't exist yet.

Always pass `--env`. A bare `wrangler deploy` creates un-suffixed `runlater-api` / `runlater-gateway` /
`runlater-web` Workers from the top-level config.

## One-time setup

Nothing deploys until `DEPLOY_ENABLED` is set, so the workflow can merge before these steps are done.

1. **Cloudflare API token** — one per environment, scoped to the RunLater account only (the account
   also holds unrelated Workers). Permissions:
   - Account · Workers Scripts · Edit
   - Account · D1 · Edit (from phase 4)
   - Account · Queues · Edit (from phase 3)
   - Zone `runlater.io` · Workers Routes · Edit (only once custom domains are added to config)

   Give it an expiry and record the rotation date.
2. **GitHub environments** `staging` and `production` (Settings → Environments):
   - Both: restrict deployment branches to `main`.
   - `production`: add a required reviewer; disable admin bypass.
   - Secrets in each: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.
   - Variable in each (once the gateway has a hostname): `GATEWAY_URL`, e.g. `https://gateway-staging.runlater.io`. The smoke check is skipped while it's unset.
3. **Repository variable** `DEPLOY_ENABLED=true`.
4. **First run** — trigger *Deploy* manually (`workflow_dispatch`) and watch it. Confirm in the dashboard
   that exactly the six expected Workers exist and no legacy Worker changed.

## Adding resources per phase

Wrangler doesn't inherit bindings into environments: every binding below goes in **both** `env.staging`
and `env.production`, with that environment's resource name.

### Phase 3 — API

- `compatibility_flags: ["global_fetch_strictly_public"]` on the API Worker.
- `durable_objects.bindings` for `TaskLedger`, plus `migrations: [{ "tag": "v1", "new_sqlite_classes": ["TaskLedger"] }]`.
- Create each queue **before** the first deploy that references it:

  ```bash
  npx wrangler queues create runlater-ready-staging
  ```

  ```bash
  npx wrangler queues create runlater-ready-production
  ```

  Then add `queues.producers` and `queues.consumers` to the API config.
- Ed25519 assertion public key as a `vars` entry on the API (it's not secret).

### Phase 4 — Gateway

- Create the databases and commit the returned ids into `d1_databases` (binding `DB`, `migrations_dir: "migrations"`):

  ```bash
  npx wrangler d1 create runlater-gateway-staging
  ```

  ```bash
  npx wrangler d1 create runlater-gateway-production
  ```
- Uncomment the D1 migrations step in `deploy-env.yml` so migrations apply before the gateway deploys.
- Secrets, set once per environment and never committed:

  ```bash
  npx wrangler secret put ASSERTION_PRIVATE_KEY --env staging
  ```

  ```bash
  npx wrangler secret put BETTER_AUTH_SECRET --env staging
  ```
  `ASSERTION_PRIVATE_KEY` is a hex 32-byte Ed25519 seed (`openssl rand -hex 32`); `BETTER_AUTH_SECRET` is
  any 32+ random bytes. The API needs the matching public key as `GATEWAY_PUBLIC_KEY` (a `vars` entry or a
  secret; it isn't sensitive). Derive it from the seed:

  ```bash
  node -e 'const c=require("crypto");const k=c.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),Buffer.from(process.argv[1],"hex")]),format:"der",type:"pkcs8"});console.log(c.createPublicKey(k).export({format:"der",type:"spki"}).subarray(-32).toString("hex"))' "$SEED"
  ```
- Done in source: D1 migrations (`apps/gateway/migrations`, applied by `deploy-env.yml`), `ratelimits`,
  the `AuthStore` Durable Object, and `PUBLIC_URL` per environment (`https://gateway-staging.runlater.io`,
  `https://gateway.runlater.io`). Agent Auth checks JWT audiences against `PUBLIC_URL`, so it must be the
  hostname agents actually use.
- Still to do before the first deploy: replace the placeholder `database_id`s, set the secrets above, and
  route the hostnames to the gateway (`"routes": [{ "pattern": "gateway-staging.runlater.io", "custom_domain": true }]`
  per environment; needs the Workers Routes permission on the token). Then set `GATEWAY_URL` for the smoke check.

### Phase 6 — E2E

Add the e2e script as a step in `deploy-env.yml` after the smoke check, run only when
`inputs.environment == 'staging'`, so a failure blocks production.

## Domains and cutover (phase 7)

These hostnames are owned by legacy Workers today:

| Hostname | Today | Target |
| --- | --- | --- |
| `runlater.io`, `www.runlater.io` | `runlater-web-landing` | `runlater-web-production` |
| `docs.runlater.io` | `runlater-web-docs` | Redirect to `runlater.io/docs` (served by `runlater-web-production`) |
| `api.runlater.io` | `runlater-alpha-api` | `runlater-gateway-production` (or a new hostname) |

Until cutover, give production temporary hostnames. At cutover, move each custom domain with an
upsert to the new Worker. Don't delete the old domain or its DNS record first. Verify the new
hostname serves before deleting the legacy Worker, and check for live tasks or grants on the old
API before moving `api.runlater.io`.

## Rollback

```bash
npx wrangler rollback --env production
```

Run it in the affected app's directory. Roll back the gateway before the API if the internal contract
changed. Durable Object migrations and D1 migrations are forward-only, so ship schema changes that the
previous Worker version can still read.

## Cost

Durable Objects, Queues and D1 together likely require the Workers Paid plan. Confirm against the
monthly budget before phase 3 adds them.
