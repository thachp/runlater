# RunLater

Let an AI agent make an HTTP request later, and check whether it happened.

> **Rebuild in progress.** The product spec is [docs/spec/PRODUCT.md](docs/spec/PRODUCT.md) and the
> target design and migration phases are in [docs/spec/ARCHITECTURE.md](docs/spec/ARCHITECTURE.md).
> The previous implementation lives under [`legacy/`](legacy/) until cutover.

## Layout

| Path | What | Stack |
| --- | --- | --- |
| `apps/api` | Private task API: ledger, scheduling, delivery | Rust · workers-rs |
| `apps/gateway` | Public entry for agents: Agent Auth, capabilities, MCP | TypeScript Worker |
| `apps/web` | runlater.io landing and docs | Next.js · OpenNext |
| `crates/core` | Task domain, no Cloudflare deps | Rust |
| `crates/egress` | Destination policy and request signing | Rust |
| `packages/contracts` | OpenAPI contract between gateway and API | OpenAPI 3.1 |
| `packages/tsconfig` | Shared TypeScript config | |

Everything deploys to Cloudflare Workers, with `staging` and `production` environments in each app's `wrangler.jsonc`.

## Develop

Requires Rust (pinned in `rust-toolchain.toml`), Node 22+, and `cargo install worker-build --version 0.8.7 --locked`.

```bash
npm install
```

```bash
cargo test && npm run typecheck && npm test
```

```bash
npm run dev -w @runlater/gateway
```

```bash
npm run dev -w @runlater/web
```
