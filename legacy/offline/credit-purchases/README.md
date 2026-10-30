# Offline credit purchase and spending-cap contract

Source-only slice for [#40](https://github.com/thachp/runlater/issues/40), below [#29](https://github.com/thachp/runlater/issues/29) and [#30](https://github.com/thachp/runlater/issues/30). Based on `d078768ed6b122619de380a0fccf4d2790485b6c`. This standalone crate is **not a dependency of the Worker**. It has no routes, environment reads, HTTP client, payment capability, credentials, commercial defaults, live trial policy, or live activation function. The only shipped verifier rejects every claim. The optional disconnected [entitlement aggregate](ENTITLEMENTS.md) now composes configurable fictional trial terms with task funding; it is not live trial activation. Numeric terms and `xxx` in the tests are explicitly fictional.

## Commands and trust boundary

`OfflineLedger::new(project, None)` disables intent creation. An explicit immutable `Policy` supplies the synthetic offer, amount in integer minor units, three-letter currency label, attempt units, quote/admission durations, fixed spending window, project cap and separately authorized purchasers. The model does not infer currency exponents or perform currency conversion. A future owner-authorized policy change/window rollover needs a reviewed migration; there is no auto-top-up or reset.

`create_intent(expected_revision, Authority::Purchase { ... }, key, packs, now)` reserves monetary cap headroom. `Authority` is trusted application context, not JSON. A future application must authenticate it through an explicit purchase authorizer; existing scheduling/configuration/read permissions confer no purchase capability. This crate adds no identity permission and changes no signed bytes. The standalone purchase ledger intentionally has no trial activation policy. A separate, disconnected [entitlement aggregate](ENTITLEMENTS.md) composes optional fictional trial terms with this ledger and the existing task/funding engine; it does not activate Worker routes or real payments.

An intent fixes the project, purchaser, offer and policy version, amount/currency, credit grant identity/amount/expiry and purchase idempotency key. The digest covers that complete snapshot. Repeating the same principal/key/packs returns the original intent after expiry or settlement; changed packs conflict. Another purchaser has a separate idempotency namespace but shares the project cap. Checked arithmetic bounds money, counters, project lifetime attempt units and timestamps to JavaScript-safe integers.

`reconcile(..., opaque_evidence, trusted_verifier, now)` can only consume **offline** facts. `VerifiedEvent` is not deserializable. Its public trait is an injection boundary for trusted server code, not proof that any arbitrary implementation is secure. The library ships `DisabledVerifier`; the allowlisted synthetic implementation exists only in the integration tests. Neither a client `paid=true`, a receipt-shaped JSON object, an MPP credential, nor an HTTP success page can authorize entitlement here. Nonfixture facts are refused, so installing a future real verifier still cannot activate this model.

A future adapter must authenticate authoritative settlement and bind its provider payment identity to this exact project, quote digest, amount and currency. It must reject a payment already associated with another purchase/project, authenticate webhook/reconciliation results, enforce provider-level idempotency, and exclude client-selected verifier/account/mode/routing data. The local payment registry is project-scoped; cross-project uniqueness must come from that verified immutable provider binding or an atomic global payment registry. No such provider adapter is claimed by this change.

## Spending and reconciliation semantics

The project and purchaser caps count **pending reservations + gross committed purchases** in one immutable window. A quote timeout does not prove that payment failed: its reservation remains until a trusted `NoPaymentFinal` result. Cap holds are created before any future payment operation. A late settlement is accepted when the verified payment occurred inside the quote lifetime; it never extends credit admission expiry. A definitive no-payment result is final; contradictory later payment facts conflict and require reconciliation outside this model.

Events and payment identities cannot be reused for another quote. Exact event replay returns current reconciliation state without writing; a new delivery of the same settlement does not issue a second grant. Event-ID conflicts reject atomically. Refunds and reversals keep gross cap consumption, preventing repeated buy/refund from replenishing delegated authority.

Only full refunds/full reversals are modeled. They permanently revoke unused admission credits while preserving existing task reservations. A reversal arriving before settlement suppresses issuance permanently. Partial amounts fail binding validation and leave the ledger unchanged: partial-refund conversion/quarantine is **not implemented** and must be reviewed before any real integration. These internal credit dispositions make no commercial refund promise.

## Existing finite-grant model remains authoritative

The crate imports the existing `runlater::funding::State` and `GrantSpec`; it does not implement a second attempt reservation/spending engine. `funding_updates(cursor)` emits an ordered policy journal. Apply **every** missing directive with `sync_funding`, then persist the returned cursor, funding state, purchase ledger and any accepted task/idempotency record in the same authoritative transaction. Persisted cursors are trusted internal data. Replaying old directives against a newer state fails closed; applying the current cursor cannot refill a grant. Do not mix these synthetic directives with a live operator project's funding revisions.

Multiple settlements can arrive before a consumer restarts: the journal recreates each immutable grant before selecting the latest unrevoked grant, so earlier purchased balances are retained. The existing core selects one grant for fresh admission and does not pool grants. `Balance.available` sums all grants; `selected_grant` and `admission_available` identify the amount available under the current selection. The standalone purchase ledger adds no automatic grant selection after depletion. The optional [entitlement aggregate](ENTITLEMENTS.md) owns a separate revision sequence and explicitly selects eligible trial/purchased grants atomically with task reservation; do not mix that aggregate with standalone `sync_funding` cursors. Queries clone funding state, report their sampled time/revision and `activation_enabled=false`, and cannot authorize spending or reserve a task.

Existing funded task replay/cancellation/attempt settlement stays in the signed project aggregate. Tests use the actual task ledger and funding state to prove that an accepted task survives admission expiry and reversal, spends once per committed fence, and retires unused units without reopening the source grant.

## Persistence, concurrency and bounds

All purchase commands check an expected revision, validate a clone and replace state only on success. A future host must provide real durable compare-and-swap or a serialized project transaction; the 16-thread fixture proves the command contract under a mutex, not multi-process storage atomicity. A stale sampled balance/revision cannot bypass a fresh cap check. Verification is side-effect-free: network/charge work belongs outside the atomic command, with durable provider idempotency and reconciliation before passing normalized facts.

Snapshots validate on every deserialization and command commit. Storage is trusted; snapshots are not public request formats or signed proof. There are 32 lifetime intent/grant identities and 256 event tombstones, bounded evidence (8 KiB) and snapshot input (256 KiB). Unpaid, reversed and duplicate identities are never pruned or recycled. Exhaustion fails closed and requires an explicitly reviewed migration. This is a bounded offline model, not a production database, webhook handler or distributed transaction proof.

## Read-only quote lookup for offline MPP journaling

`intent(project, id)` returns the immutable cap-reserved quote from this ledger, including after restore, expiry or settlement. It performs the same project check as `receipt` and cannot create a purchase or confer purchase authority. The sibling `offline/mpp-http` journal uses it instead of accepting arbitrary quote terms. Its snapshot/restart fixtures pin challenge and first-credential/provider identity, but do not replace this ledger's verifier, cap holds or funding journal. A host must atomically validate **both** current ledger and challenge-journal revisions; neither a stale ledger clone nor journal-only CAS proves current purchase state.

## MPP adapter follow-up and primary references

The intended future adapter is narrow Rust HTTP protocol handling, since prior compatibility findings rule out assuming full native MPP SDK Wasm support. This crate uses no MPP SDK and claims no MPP wire interoperability. Its fixture identifiers are not `WWW-Authenticate`, credentials, receipts, provider signatures or actual settlement. The sibling offline MPP crate supplies a narrow wire codec and snapshot fixture journal, not a live adapter. Provider verification, durable storage integration, reconciliation transport, merchant eligibility and live configuration remain in #29; entitlement/action routes remain in #30.

References reviewed on 2026-10-28:

- [Stripe MPP integration](https://docs.stripe.com/payments/machine/mpp): the HTTP challenge/credential exchange includes provider verification before access. No instructions that create accounts, tokens, wallets or charges were executed.
- [Payment authentication draft 01](https://paymentauth.org/draft-httpauth-payment-01.html), especially §§5 and 11: a future implementation must use the actual challenge/credential/receipt formats, bind the echoed fields, and consume a proof atomically across concurrent requests. This is a work-in-progress draft.
- [Stripe charge intent draft 00](https://paymentauth.org/draft-stripe-charge-00.html), §§8–10: future verification must establish the exact challenge, amount, currency, recipient and single-use payment identity. This is a work-in-progress draft.
- [Stripe webhooks](https://docs.stripe.com/webhooks): authenticate signatures and handle duplicate/out-of-order delivery. An unverified event is not entitlement.
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests): provider retry handling is distinct from this ledger's immutable purchase and settlement identities.

Stripe documentation search through the installed connector returned `Unknown tool`, and the Stripe CLI was absent. The official public documentation above was read as fallback. No Stripe account tools were called.

## Local verification

Use the pinned Rust 1.92 toolchain (a Homebrew `rustc` earlier on PATH must not override it):

```sh
cargo fmt --manifest-path offline/credit-purchases/Cargo.toml -- --check
cargo test --locked --manifest-path offline/credit-purchases/Cargo.toml
cargo check --locked --manifest-path offline/credit-purchases/Cargo.toml --target wasm32-unknown-unknown
cargo test --locked
cargo check --locked --target wasm32-unknown-unknown --features production
```

The dedicated `offline-credit-purchases.yml` workflow checks the standalone crate. Existing Worker source, root manifest/lockfile, signed envelopes, onboarding and live resources are unchanged. The model fixtures cover duplicate/concurrent settlement, concurrent last-cap intent creation, all quote bindings, foreign tenants, fabricated claims, overflow, restart/journal recovery, expiry, no-payment finality, full refund/reversal, partial rejection and accepted-task preservation.

## Atomic fixture trial/task aggregate

The optional `entitlements::Entitlements` module is a source-only #28 increment. See [ENTITLEMENTS.md](ENTITLEMENTS.md) for once-only configurable trial allowances, exact `payment_required` decisions, atomic task/reservation/purchase-journal composition, validation evidence and remaining Worker/payment integration gates. Its task allowance is never replenished by cancellation, and its purchase intents reserve capacity before any future fixture settlement. No Worker dependency or live activation path is added.
