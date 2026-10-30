// The docs' code samples are run, not just shown. The vector is the one pinned in
// crates/egress/src/signing.rs (matches_a_fixed_vector).

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { LIMITS } from "../lib/site";
import { verifyNode, verifyPython } from "../lib/snippets";

const SIG = "78034213583182231b9638987a3393e0a8a1a8ba1fa5810e5822c53d835a2eb2";
const headers = (signature: string, ts = "1767225600") => ({
  "runlater-task-id": "task_1",
  "runlater-attempt": "1",
  "runlater-timestamp": ts,
  "runlater-signature": signature,
});

describe("Node verification sample", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "runlater-docs-")), "verify.mjs");
  writeFileSync(file, verifyNode);
  const { verifyRunLater } = (await import(pathToFileURL(file).href)) as {
    verifyRunLater: (h: Record<string, string>, body: string | Buffer, secret: string, tol?: number) => boolean;
  };

  it("accepts a genuine signature", () => {
    expect(verifyRunLater(headers(`v1=${SIG}`), "{}", "secret", Infinity)).toBe(true);
    expect(verifyRunLater(headers(`v1=${SIG}`), Buffer.from("{}"), "secret", Infinity)).toBe(true);
  });

  it("accepts any entry during rotation", () => {
    expect(verifyRunLater(headers(`v1=${"0".repeat(64)}, v1=${SIG}`), "{}", "secret", Infinity)).toBe(true);
  });

  it("rejects tampering, wrong secrets, other schemes and stale timestamps", () => {
    expect(verifyRunLater(headers(`v1=${SIG}`), "{ }", "secret", Infinity)).toBe(false);
    expect(verifyRunLater(headers(`v1=${SIG}`), "{}", "other", Infinity)).toBe(false);
    expect(verifyRunLater(headers(`v0=${SIG}`), "{}", "secret", Infinity)).toBe(false);
    expect(verifyRunLater(headers("v1=abc"), "{}", "secret", Infinity)).toBe(false);
    expect(verifyRunLater(headers(`v1=${SIG}`), "{}", "secret")).toBe(false);
  });
});

describe("Python verification sample", () => {
  it("agrees with the same vector", () => {
    const script = `${verifyPython}

h = {"runlater-task-id": "task_1", "runlater-attempt": "1", "runlater-timestamp": "1767225600",
     "runlater-signature": "v1=${SIG}"}
inf = float("inf")
assert verify_runlater(h, b"{}", "secret", inf)
assert not verify_runlater(h, b"{ }", "secret", inf)
assert not verify_runlater(h, b"{}", "other", inf)
assert not verify_runlater(h, b"{}", "secret")
h["runlater-signature"] = "v1=" + "0" * 64 + ", v1=${SIG}"
assert verify_runlater(h, b"{}", "secret", inf)
print("ok")
`;
    expect(execFileSync("python3", ["-I", "-c", script], { encoding: "utf8" }).trim()).toBe("ok");
  });
});

describe("stated limits", () => {
  const limitsRs = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "../../../crates/core/src/limits.rs"),
    "utf8",
  );
  const stated = Object.fromEntries(LIMITS);
  const constant = (name: string) => limitsRs.match(new RegExp(`pub const ${name}: \\w+ = ([^;]+);`))?.[1];

  it("match crates/core", () => {
    expect(constant("MAX_BODY_BYTES")).toBe("64 * 1024");
    expect(stated["Request body"]).toBe("64 KiB");
    expect(constant("MAX_HEADERS")).toBe("32");
    expect(constant("MAX_HEADER_BYTES")).toBe("8 * 1024");
    expect(stated["Headers"]).toBe("32 headers, 8 KiB in total");
    expect(constant("TRIAL_ATTEMPTS")).toBe("100");
    expect(constant("TRIAL_DURATION_MS")).toBe("7 * DAY_MS");
    expect(stated["Free trial"]).toContain("100 delivery attempts over 7 days");
    expect(constant("MAX_ATTEMPTS")).toBe("5");
    expect(constant("DEFAULT_MAX_ATTEMPTS")).toBe("5");
    expect(stated["Attempts per task"]).toBe("1–5 (default 5)");
    expect(constant("ATTEMPT_TIMEOUT_MS")).toBe("10 * SECOND_MS");
    expect(constant("MAX_RETAINED_TASKS")).toBe("1_000");
    expect(constant("RETENTION_MS")).toBe("30 * DAY_MS");
    expect(constant("MAX_SCHEDULE_AHEAD_MS")).toBe("7 * DAY_MS");
  });
});
