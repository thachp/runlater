# Offline MPP HTTP draft-profile codec

A minimal source-only slice of [#29](https://github.com/thachp/runlater/issues/29), based on combined main `934eb9b09caa856e0f8b684c55fa1fcbd79c014a`. This standalone crate is not linked into the Worker. It provides no HTTP client, routes, environment reads, clock access, account calls, credentials, wallet operations, payment execution or activation path. It does not implement `SettlementVerifier`. The existing `DisabledVerifier` is unchanged.

## Exact draft profile

The official [specification index](https://paymentauth.org/) was retrieved on 2026-10-28 and linked to:

- [Payment HTTP authentication draft 01](https://paymentauth.org/draft-httpauth-payment-01.html), published 2026-10-26, expiring 2027-04-29. This crate covers a single challenge field, echoed credential parameters, the selected credential field, SHA-256 body digests and receipt syntax. The optional alternate field is included in the challenge binding input.
- [Stripe charge draft 00](https://paymentauth.org/draft-stripe-charge-00.html), with the same publication/expiry dates. The local issuance profile uses string minor-unit amounts, currency labels, `methodDetails.networkId`, `paymentMethodTypes`, and flat correlation metadata. The unexecuted request body follows the documented PaymentIntent fields and derives an idempotency key from challenge, quote and credential identity.

Both are **work-in-progress Internet-Drafts**, not finalized standards. These references pin the compatibility target; later draft changes require review. [Stripe's MPP guide](https://docs.stripe.com/payments/machine/mpp) was also consulted. No registration, validator, wallet, account, token or payment commands from that guide were run.

This is a deliberately limited profile, not general MPP interoperability certification or a claim that a merchant/account/currency is eligible. Currency exponents, supported commercial currencies, prices, trials and business terms remain unset. Fictional fixture amounts and `xxx` do not select commercial terms.

## Boundaries and API

`Challenge::parse` / `to_header` handle one `WWW-Authenticate` field containing one `Payment` challenge. Auth scheme and HTTP parameter names are case-insensitive; method/intent values remain case-sensitive. Quoted commas, escaped quotes/backslashes and optional whitespace are handled. Unknown string parameters are preserved/ignored for authorization. Duplicate parameter names, control characters and malformed or ambiguous challenge lists fail closed. A future HTTP host must separate challenge lists; negotiation and other payment intents are out of scope.

`IssuedChallenge::offline` requires an explicit trusted quote, merchant-shaped context, an `offline_` fixture challenge ID, request bytes, and credential-field selection. It records the full quote snapshot. It emits the actual documented header/JSON encodings, not custom 402 JSON. It does not authenticate the caller, reserve a spending cap, prove a profile exists, allocate durable challenge IDs, or generate a secret. Its inputs must come from trusted application context, not an HTTP body. It is an in-memory issuance snapshot, not a challenge store or persistence contract.

`prepare` checks the current quote/project, quote lifetime, body digest, selected header, and every echoed bound challenge parameter before interpreting the Stripe payload. The description, payer `source` and client `externalId` cannot alter amount, currency, recipient context or authoritative correlation. The request has no client-selected Connect routing, fees, API account or HTTP authorization fields. Task/onboarding authority is not purchase authority.

The returned `UnexecutedStripeRequest` is a descriptive operation/body and hashed idempotency key. It has **no execution method**, always reports activation disabled, and cannot convert into `VerifiedEvent`. `body_for_inspection` deliberately exposes untrusted credential material for explicit inspection; callers must not log or persist that body casually. Debug output is redacted. The operation uses automatic payment methods and does not set the provider's `payment_method_types` parameter; `methodDetails.paymentMethodTypes` is a distinct MPP challenge field.

`UntrustedReceipt::parse` accepts success-shaped Stripe receipt syntax only alongside a supplied 2xx status. `to_fixture_header` supports fixture round trips. Neither a receipt, HTTP 200 nor JSON `status=succeeded` authenticates a provider or establishes settlement. There is no provider-response-to-credit conversion. The fabricated-success test passes both a syntactically valid receipt and fabricated PaymentIntent JSON to the unchanged `DisabledVerifier`; both reject without minting entitlement.

No payment proof is consumed here. Repeating the same valid credential produces the same unexecuted plan. Durable single-use challenge/SPT handling, cross-project payment uniqueness, cap reservation before payment, authenticated provider transport, verification of amounts/recipient/status, provider-level idempotency/replay detection, refund reconciliation and an atomic entitlement commit remain follow-up work. A future provider-backed adapter must address them before any real payment execution or credit issuance. This crate is not authorization to implement or activate that transport.

## Encoding restrictions and limits

- Inputs are bounded to 8 KiB per field/document, 2 KiB request bodies, 32 HTTP fields, 24 challenge parameters, 32 JSON object entries/array elements and eight JSON nesting levels. JSON parsing also retains serde_json's recursion guard.
- This narrow JSON profile contains strings, arrays and objects only. It rejects duplicate JSON keys, JSON numbers/booleans/null and unsupported method-specific data. No general-purpose numeric JCS implementation is claimed. Object keys sort by UTF-16 code units; strings use JSON escaping. Request and opaque encodings must already match JCS within this profile.
- Base64url must be unpadded with canonical trailing bits. Opaque values must be a flat string map. SHA-256 content digests use the standard padded base64 representation inside the RFC 9530 syntax.
- Headers use a strict ASCII profile. Non-ASCII/obsolete folding and arbitrary credential-header names are unsupported. Header parameter extension keys are normalized on parse. Local Stripe issuance supports explicit `card`/`link` lists only; no wallet/network integration is inferred.
- Timestamps use RFC3339 with millisecond comparisons and JavaScript-safe positive integer bounds. No clock is sampled. The host supplies trusted time and must persist its own monotonic expiry and replay decisions.
- `hmac_binding_input` produces only the draft's delimited input. It creates no MAC, authenticates no challenge, accepts no secret and rejects delimiter-containing bound fields. Production HMAC issuance/verification is not implemented.

## Source fixtures and checks

`fixtures/drafts-and-vectors.json` records pinned URLs/dates and the draft's three published HMAC input/output vectors. The literal `test-vector-secret` is public specification test material used only by the native test's HMAC calculation; it is not a provider key or newly generated credential. The method in those generic binding vectors is Tempo; this does not add a Tempo payment adapter.

`fixtures/stripe-charge-fiction.json` contains independent Python-generated golden challenge headers, credentials, quote digest, receipt and unexecuted request/idempotency expectations. All identifiers are explicitly fictional. The fixtures are embedded into the Rust tests, contain no real/test-provider credential, and cause no network calls.

```sh
cargo fmt --manifest-path offline/mpp-http/Cargo.toml -- --check
cargo test --locked --manifest-path offline/mpp-http/Cargo.toml
cargo check --locked --manifest-path offline/mpp-http/Cargo.toml --target wasm32-unknown-unknown
cargo test --locked --manifest-path offline/mpp-http/Cargo.toml --target wasm32-unknown-unknown --no-run
```

Use pinned Rust 1.92. Native tests execute the fixtures; Wasm checks compile the same fixture tests but do not execute them. A Wasm test runner is not installed locally, so this change does not claim Wasm runtime or live provider interoperability. The dedicated CI workflow repeats native execution and Wasm compilation. Neither `mppx validate` nor provider sandbox tests are part of this suite because they can initiate payments.
