// Facts the site states. Keep in step with docs/spec/PRODUCT.md and crates/core/src/limits.rs.

/** Where agents connect once the gateway is deployed (docs/DEPLOY.md, phase 4). */
export const GATEWAY_URL = "https://gateway.runlater.io";
export const REPO_URL = "https://github.com/thachp/runlater";

export const LIMITS: [string, string][] = [
  ["Free trial", "100 delivery attempts over 7 days, per project"],
  ["Projects", "One per agent host"],
  ["Schedule ahead", "Up to 7 days, and before the trial ends"],
  ["Request body", "64 KiB"],
  ["Headers", "32 headers, 8 KiB in total"],
  ["Attempts per task", "1–5 (default 5)"],
  ["Attempt timeout", "10 seconds; redirects are not followed"],
  ["Tasks held", "1,000 per project, finished ones included until purged"],
  ["Retention", "Tasks and attempts are kept 30 days after they finish"],
];
