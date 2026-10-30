# Public self-service beta: source client handoff

The public client follows [the actual public-beta contract](../contracts/public-beta-v1.json), with a separate [quickstart](PUBLIC-BETA-QUICKSTART-v1.md) and [Workers receiver](../examples/public-beta-receiver/README.md). It reconstructs public Ed25519 proof bytes, checks full release-derived identity and fixed terms, recovers the original receipt, retrieves only the scoped tenant callback key and signs destination/task management. Alpha and invitation protocols remain separate.

The source cohort is ten lifetime public projects, seven days/100 attempt credits, five reserved credits per fresh task/redrive, 16 lifetime admissions and 128 lifetime publications. These application limits are not a provider billing cap, paid plan or availability statement. Payments and automatic recharge remain absent. Accepted funded work can continue after admission expiry under existing limits.

Two required nonsecret release inputs are not exposed by current DTOs: the release ID deriving the registration ticket, and callback key validity/history metadata required by the receiver. The activation owner must publish the exact reviewed immutable values before claiming a complete self-service live guide. The client requires them explicitly; it does not invent fields, infer validity times or return master material. The compiled local journey uses its real explicit release profile.

The ownership proof window is five minutes, with three lifetime issuances per endpoint version. Prepare the receiver/private owner channel first, privately install the nonce-bearing static response, then verify. The example never reflects incoming data or exposes public setup/reset routes. Its exact Workers.dev URL remains subject to separate strictly-public Fetch admission; ownership proves no arbitrary DNS/SSRF safety.

Remaining release work is reviewed policy publication, practical owner secret-installation timing, controlled provider/runtime proof and separately authorized activation. Keep local mock/native/workerd evidence distinct from live DNS/TLS/availability. No live resources or published assets are changed by this client.
