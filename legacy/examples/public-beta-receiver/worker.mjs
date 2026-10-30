// Source-only customer receiver example. No outbound fetch, public setup route or secret logging.
import {DurableObject} from 'cloudflare:workers';
import {createHash, timingSafeEqual} from 'node:crypto';
import {validatePolicy, verifyV2WithMaterial, advancePolicy} from '../rotating-receiver.mjs';

const MAX_OPERATIONS = 128;
const PROOF_PREFIX = 'RunLater destination proof v1\n';
const VERIFY_PREFIX = 'RunLater destination verification v1\n';
const hex64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const reply = (status, code) => Response.json({code}, {status, headers: {'Cache-Control': 'no-store'}});
function base(env) {
  if (env.RECEIVER_ENABLED !== 'owner-configured' || !id(env.RECEIVER_PROJECT_ID)) throw Error();
  const url = new URL(env.RECEIVER_URL);
  if (url.href !== env.RECEIVER_URL || url.protocol !== 'https:' || url.username || url.password
    || url.port || url.pathname !== '/callback' || url.search || url.hash
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/.test(url.hostname)) throw Error();
  return {url: url.href, project: env.RECEIVER_PROJECT_ID};
}
function callbackConfig(env) {
  const context = base(env);
  if (typeof env.CALLBACK_POLICY !== 'string' || env.CALLBACK_POLICY.length > 16384
    || typeof env.CALLBACK_KEYS !== 'string' || env.CALLBACK_KEYS.length > 4096) throw Error();
  const policy = JSON.parse(env.CALLBACK_POLICY), raw = JSON.parse(env.CALLBACK_KEYS);
  if (!validatePolicy(policy) || policy.tenant !== context.project || !raw || Array.isArray(raw)
    || typeof raw !== 'object' || Object.keys(raw).length > 16) throw Error();
  const material = new Map();
  for (const [key, value] of Object.entries(raw)) {
    if (!Object.hasOwn(policy.keys, key) || key.startsWith('fixture') || !hex64(value)
      || /^(..)(?:\1){31}$/.test(value)) throw Error();
    material.set(key, Buffer.from(value, 'hex'));
  }
  if (Object.entries(policy.keys).some(([key, value]) => value.revoked_at_sec === null && !material.has(key))) throw Error();
  return {context, policy, material};
}
async function boundedBody(request) {
  const reader = request.body?.getReader(); if (!reader) throw Error();
  let timer, size = 0, chunks = 0;
  try {
    return await Promise.race([(async () => {
      const parts = [];
      for (;;) {
        const {done, value} = await reader.read(); if (done) break;
        size += value.byteLength; chunks++;
        if (size > 1024 || chunks > 32) throw Error(); parts.push(Buffer.from(value));
      }
      return Buffer.concat(parts);
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(Error()), 3000); })]);
  } finally {
    clearTimeout(timer); void reader.cancel().catch(() => {});
    try { reader.releaseLock(); } catch { /* timed-out pending read */ }
  }
}
function proofResponse(env, context, body, now) {
  // This value is privately installed by the owner. Never derive it from request bytes.
  if (typeof env.OWNERSHIP_PROOF !== 'string' || env.OWNERSHIP_PROOF.length > 2048) throw Error();
  const p = JSON.parse(env.OWNERSHIP_PROOF);
  if (!p || Object.keys(p).sort().join(',') !== 'expires_at_ms,id,response' || !hex64(p.id)
    || typeof p.response !== 'string' || Buffer.byteLength(p.response) > 1024
    || !p.response.startsWith(PROOF_PREFIX) || digest(p.response) !== p.id) throw Error();
  const t = JSON.parse(p.response.slice(PROOF_PREFIX.length));
  if (!Array.isArray(t) || t.length !== 8 || t[0] !== 1 || t[1] !== context.project || !id(t[2])
    || !Number.isInteger(t[3]) || t[3] < 1 || t[3] > 0xffffffff || t[4] !== context.url
    || !Number.isInteger(t[5]) || t[5] < 1 || t[5] > 3 || !Number.isSafeInteger(t[6])
    || t[6] !== p.expires_at_ms || t[6] <= now || t[6] - now > 300000 || !hex64(t[7])
    || p.response !== PROOF_PREFIX + JSON.stringify(t)) throw Error();
  const expected = Buffer.from(VERIFY_PREFIX + JSON.stringify([t[1], t[2], t[3], p.id, t[6]]));
  if (body.length !== expected.length || !timingSafeEqual(body, expected)) return reply(403, 'proof_forbidden');
  return new Response(p.response, {status: 200, headers: {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store'}});
}
export default {async fetch(request, env) {
  let context; try { context = base(env); } catch { return reply(503, 'receiver_unconfigured'); }
  if (request.url !== context.url || request.method !== 'POST') return reply(404, 'route_unavailable');
  let headerBytes = 0; for (const [k, v] of request.headers) headerBytes += Buffer.byteLength(k, 'utf8') + Buffer.byteLength(v, 'utf8');
  if (headerBytes > 2048) return reply(431, 'headers_too_large');
  const type = request.headers.get('Content-Type');
  if (!['text/plain; charset=utf-8', 'application/json'].includes(type)) return reply(415, 'unsupported_media');
  let body; try { body = await boundedBody(request); } catch { return reply(413, 'body_limit'); }
  if (type === 'text/plain; charset=utf-8') {
    try { return proofResponse(env, context, body, Date.now()); }
    catch { return reply(503, 'proof_unavailable'); }
  }
  let c; try { c = callbackConfig(env); } catch { return reply(503, 'receiver_unconfigured'); }
  if (!verifyV2WithMaterial(c.policy, request.headers, body, Math.floor(Date.now() / 1000), key => c.material.get(key))) return reply(403, 'callback_forbidden');
  if (!env.INBOX) return reply(503, 'receiver_unconfigured');
  try {
    // Object naming comes only from owner config after authentication, never an untrusted header.
    const inbox = env.INBOX.getByName(c.context.project);
    const status = await inbox.accept(Object.fromEntries(request.headers), new Uint8Array(body));
    return status === 204 ? new Response(null, {status: 204, headers: {'Cache-Control': 'no-store'}})
      : reply(status, status === 409 ? 'operation_conflict' : 'receiver_unavailable');
  } catch { return reply(503, 'receiver_unavailable'); }
}};

export class ReceiverInbox extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_policy(id INTEGER PRIMARY KEY CHECK(id=1),policy TEXT NOT NULL,material_hashes TEXT NOT NULL)');
      this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_operations(operation_key TEXT PRIMARY KEY,body_sha256 TEXT NOT NULL,first_task TEXT NOT NULL)');
      this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_effect(id INTEGER PRIMARY KEY CHECK(id=1),accepted_operations INTEGER NOT NULL)');
      this.sql.exec('INSERT OR IGNORE INTO receiver_effect VALUES(1,0)');
    });
  }
  accept(headers, body) {
    try {
      const c = callbackConfig(this.env), h = new Headers(headers);
      if (!(body instanceof Uint8Array) || body.length > 1024
        || !verifyV2WithMaterial(c.policy, h, body, Math.floor(Date.now() / 1000), key => c.material.get(key))) return 403;
      return this.ctx.storage.transactionSync(() => {
        const old = this.sql.exec('SELECT policy,material_hashes FROM receiver_policy WHERE id=1').toArray()[0];
        const policy = old ? advancePolicy(JSON.parse(old.policy), c.policy) : c.policy;
        const fingerprints = new Map(old ? Object.entries(JSON.parse(old.material_hashes)) : []);
        for (const [key, bytes] of c.material) {
          const hash = digest(bytes);
          if (fingerprints.has(key) && fingerprints.get(key) !== hash) throw Error();
          fingerprints.set(key, hash);
        }
        this.sql.exec('INSERT INTO receiver_policy VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,material_hashes=excluded.material_hashes', JSON.stringify(policy), JSON.stringify(Object.fromEntries(fingerprints)));
        const operation = h.get('RunLater-Operation-Key'), hash = digest(body);
        const found = this.sql.exec('SELECT body_sha256 FROM receiver_operations WHERE operation_key=?', operation).toArray()[0];
        if (found) return found.body_sha256 === hash ? 204 : 409;
        if (this.sql.exec('SELECT count(*) AS n FROM receiver_operations').one().n >= MAX_OPERATIONS) return 429;
        // The example's entire effect is this local counter, atomic with deduplication.
        this.sql.exec('INSERT INTO receiver_operations VALUES(?,?,?)', operation, hash, h.get('RunLater-Task-Id'));
        this.sql.exec('UPDATE receiver_effect SET accepted_operations=accepted_operations+1 WHERE id=1');
        return 204;
      });
    } catch { return 503; }
  }
}
