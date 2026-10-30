// Reproducible hosted bundle. Strip dependency console calls before publication:
// even with observability disabled a dependency must not log URLs/token material.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
const root = fileURLToPath(new URL('../', import.meta.url));
export async function bundleMcp() {
  const result = await build({absWorkingDir: root, entryPoints: ['mcp/worker.mjs'], bundle: true,
    loader: {'.md': 'text'}, platform: 'neutral', mainFields: ['module', 'main'], format: 'esm',
    external: ['cloudflare:*', 'node:*'], drop: ['console'], legalComments: 'none', minifyWhitespace: true, write: false});
  const code = result.outputFiles[0].text;
  if (/\bconsole\s*\./.test(code)) throw new Error('Unsafe hosted bundle runtime');
  return code;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = path.join(root, 'build/mcp'); await fs.mkdir(directory, {recursive: true});
  await fs.writeFile(path.join(directory, 'worker.mjs'), await bundleMcp());
  console.log('Built disabled-profile MCP bundle; no deployment, credentials or network requests.');
}
