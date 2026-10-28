# Pending sandbox decision bundle

Proposal only, prepared 2026-10-28. No key, profile, webhook, Cloudflare resource or payment is created by this document. The offline codec remains disabled and unlinked from the Worker. A handler skeleton is omitted until provider verification and durable fulfillment can be reviewed together.

## Account and eligibility

Use only **RunLater Development**, sandbox `acct_1UVU4BJmFZFo8ppd`, under OM.Network. The connected Stripe plugin currently exposes the live parent account, so it must not perform sandbox mutations through that context. The [sandbox profile page](https://dashboard.stripe.com/acct_1UVU4BJmFZFo8ppd/test/profiles) currently offers initial profile creation; no `profile_test_` identity exists. Profile creation and [Agentic Commerce seller preview terms](https://stripe.com/legal/ssa-service-terms#stripe-agentic-commerce-seller-services-preview) acceptance remain pending explicit approval. The [seller SPT guide](https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens?agent-seller=seller) describes country restrictions; this account's merchant eligibility and preview access have not been established. No commercial currency, pricing or trial terms are selected.

## Exact proposed isolation and storage

| Item | Proposed target |
| --- | --- |
| Worker | `runlater-payments-sandbox` |
| HTTPS webhook | `https://payments-sandbox.runlater.io/v1/stripe/webhook` |
| Dedicated SQLite Durable Object class / binding | `SandboxPaymentLedger` / `SANDBOX_PAYMENT_LEDGER` |
| Namespace | New namespace belonging only to that Worker/class; record returned ID after authorized provisioning |
| Secrets on this Worker only | `STRIPE_SANDBOX_RESTRICTED_KEY`, `STRIPE_SANDBOX_WEBHOOK_SECRET` |

These exact candidate names/URL require fresh ownership and collision checks before provisioning; no DNS change or endpoint reservation has occurred. Do not reuse live alpha bindings, routes, funding state, Queues or customer traffic. No queue, cron, KV, R2, receiver Worker, plan upgrade or new account is proposed. Disable preview/alternative public hosts and request-body logging in a reviewed deployment. Secrets belong in [encrypted Worker secret bindings](https://developers.cloudflare.com/workers/configuration/secrets/), entered through a secure operator flow without model/transcript exposure; do not store them in Git, vars or command arguments.

## Minimum proposed permissions

One new sandbox restricted key: **Payment Intents → Write**, which includes read; all other resources **None**. Stripe documents this resource scope for the underlying SPT PaymentIntent call. No publishable key is needed for this server-only slice. Do not add Shared Payment Tokens read/write, SPT test helpers, Profiles, Customers, Checkout, Charges/Refunds or webhook-management permissions speculatively. A future optional SPT lookup or refund reconciliation would need its exact API call and separate permission review. A permission failure must be reported, not solved by broadening access silently. [Restricted-key guidance](https://docs.stripe.com/keys/restricted-api-keys).

Separately create one **sandbox snapshot webhook** at the exact URL above only after reviewed code exists. Its endpoint-specific signing secret is distinct from the API key and does not require runtime webhook-management permission. Initially proposed events are `payment_intent.succeeded`, `payment_intent.payment_failed`, `payment_intent.canceled`; event/API version must match a reviewed documented contract. Refund/reversal and SPT deactivation handling need a completed reconciliation design before enabling any fulfillment. No webhook subscription is created now.

## Required source before any fulfillment

Persist purchase/cap reservation and challenge/token identity before an authenticated provider request. Reconcile uncertain provider outcomes using the same logical idempotency key. Check verified sandbox account/mode, successful provider status, amount/currency and purchase/recipient binding; atomically deduplicate provider payment/event IDs with the entitlement commit. Verify raw webhook bytes, bounded signature fields and timestamp tolerance; tolerate duplicate/out-of-order delivery and interruption. A token-deactivated event or supplied success receipt is not settlement. Complete refund/reversal reconciliation while preserving accepted-task funding. The existing `DisabledVerifier` stays in place until those checks are reviewed. [Stripe webhooks](https://docs.stripe.com/webhooks).

## Cost and release decision

No new resources means **$0 incremental provider usage from this PR**. For a future single 15-minute synthetic campaign, planning limits are 500 Worker requests at 50ms CPU each, 2,000 DO requests, one active 128MB DO for 900s (about 116 GB-s), 10,000 SQL reads/writes and under 1 MB stored. These are estimates, not implemented caps or a bill ceiling. Assuming existing Paid service and exhausted included allocations, a conservative full-unit reserve is **$14.171**: Worker requests/CPU $0.30+$0.02; DO request/duration $0.15+$12.50; SQL read/write/storage $0.001+$1+$0.20. DO overage rounds upward to billable units. Existing account usage can cross those boundaries. No additional $5 plan subscription is authorized. [Workers rates](https://developers.cloudflare.com/workers/platform/pricing/), [DO/SQL rates and rounding](https://developers.cloudflare.com/durable-objects/platform/pricing/), retrieved 2026-10-28.

The existing RunLater $20 risk envelope is shared, not a fresh allocation for payments. Remaining headroom and billing visibility are unknown. Anonymous ingress and retained storage can exceed campaign estimates. Parent approval must name the reviewed SHA, exact resource/secret/profile actions, event/version choices, available budget and cleanup owner; existing [staging release controls](../../staging/README.md) are not bypassed. Actual testing, secure credential entry, terms acceptance and activation remain pending, and no request for approval is sent while the user sleeps.
