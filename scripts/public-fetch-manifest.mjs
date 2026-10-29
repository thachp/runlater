// Deterministic source-review identity, NOT deployment/provider proof or an approval grant.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const digest=value=>createHash('sha256').update(value).digest('hex');
const paths=['egress/controller/dispatch.mjs','egress/controller/envelope.mjs','egress/public-fetch/transport.mjs','egress/public-fetch/worker.mjs','egress/public-fetch/wrangler.example.jsonc'];
const files=[];for(const path of paths)files.push({path,sha256:digest(await readFile(new URL('../'+path,import.meta.url)))});
const manifest={version:1,transport:'worker-public-fetch-v1',files};
console.log(JSON.stringify({...manifest,revision:digest(JSON.stringify(manifest))},null,2));
