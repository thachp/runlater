# Local verification checkpoint — 2026-10-27

Passed on this Mac with Rust 1.92.0, released worker/worker-build 0.8.7 and Wrangler 4.154.0:

- `scripts/check.sh`: 11 meaningful native Rust tests, doc-test compilation, Wasm target check, rustfmt, 2 Node redirect tests.
- `scripts/build.sh`: release Wasm build, wasm-bindgen and wasm-opt bundle completed.
- `npm run test:local` against `wrangler dev --local`: real local SQLite DO + alarm + Queue producer/consumer + signed in-process fixture + committed result; create idempotency with omitted schedule, conflict detection, tenant denial, all real destinations rejected, retry, linked redrive retaining operation key, cancellation, task list, future schedule, unauthorized access. Passed.
- Manual persisted-state process restart: created a task scheduled 15 seconds ahead, stopped the emulator process, restarted with the same `.wrangler` state, observed exactly one recorded successful attempt through Queue; repeated create with the original key returned the original task. Passed.

Integration initially exposed the released alarm API's relative-offset semantics, starvation from postponing alarms during polling, and immediate scheduling's delivery-age baseline. All were corrected; the final integration suite passed with continuous polling.

No production deployment, live Cloudflare binding, DNS change, credential provisioning, live callback, production capacity benchmark, or SLA validation was performed. This does not close the full backlog. Remaining launch gates are listed in LOCAL.md.
