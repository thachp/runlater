import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "cloudflare:workers": new URL("./test/stubs/cloudflare-workers.ts", import.meta.url).pathname } },
  test: {
    include: ["test/**/*.test.ts"],
    // Bundle the OAuth provider so its `cloudflare:workers` import reaches the alias above.
    server: { deps: { inline: ["@cloudflare/workers-oauth-provider"] } },
  },
});
