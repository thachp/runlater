// Source-only, privately configured single-project receiver. No public bootstrap or secret output.
import {DurableObject} from 'cloudflare:workers';
import {randomBytes} from 'node:crypto';
import {API, PULL, ACK, manifest, privateKey, probeResponse, signedRequest, installation,
  destinationProof, callbackValid, exact, hex, sha} from './protocol.mjs';
const CADENCE = 30000, MAX_CYCLES = 10, MAX_OPERATIONS = 128;
const reply = (status, code) => Response.json({code}, {status, headers: {'Cache-Control': 'no-store, private'}});
function config(env) {
  if (env.RECEIVER_ENABLED !== 'pairing-configured' || typeof env.RECEIVER_MANIFEST !== 'string'
    || env.RECEIVER_MANIFEST.length > 2048) throw Error();
  return manifest(JSON.parse(env.RECEIVER_MANIFEST));
}
async function readBody(body, limit, timeout = 3000) {
  const reader = body?.getReader(); if (!reader) throw Error();
  let timer, size = 0, chunks = 0;
  try {
    return await Promise.race([(async () => {
      const parts = [];
      for (;;) {
        const {done, value} = await reader.read(); if (done) break;
        if ((size += value.byteLength) > limit || ++chunks > 64) throw Error();
        parts.push(Buffer.from(value));
      }
      return Buffer.concat(parts);
    })(), new Promise((_, reject) => {timer = setTimeout(() => reject(Error()), timeout);})]);
  } finally {
    clearTimeout(timer); void reader.cancel().catch(() => {});
    try {reader.releaseLock();} catch { /* timed-out pending read */ }
  }
}
async function apiRequest(m, key, path, body) {
  const controller = new AbortController(); let timer, response;
  try {
    return await Promise.race([(async () => {
      response = await fetch(API + path, {...signedRequest(m, key, path, body, Date.now(), randomBytes(32).toString('hex')),
        signal: controller.signal});
      let headerBytes = 0; for (const [k, v] of response.headers) headerBytes += Buffer.byteLength(k) + Buffer.byteLength(v);
      if (headerBytes > 4096 || response.status !== 200 || response.headers.get('Location') !== null
        || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') || '')) throw Error();
      const bytes = await readBody(response.body, 16384);
      return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    })(), new Promise((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error());}, 5000);})]);
  } finally {
    clearTimeout(timer); controller.abort();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}
export default {async fetch(request, env) {
  let m; try {m = config(env);} catch {return reply(503, 'receiver_unconfigured');}
  let headerBytes = 0; for (const [k, v] of request.headers) headerBytes += Buffer.byteLength(k) + Buffer.byteLength(v);
  if (headerBytes > 2048) return reply(431, 'headers_too_large');
  const metadata = new URL('/.well-known/runlater-receiver', m.url).href;
  const isMetadata = request.url === metadata && request.method === 'GET';
  if (!isMetadata && (request.url !== m.url || request.method !== 'POST')) return reply(404, 'route_unavailable');
  if (!env.INBOX) return reply(503, 'receiver_unconfigured');
  try {
    // A constant name in this receiver's private namespace prevents config edits selecting a fresh inbox.
    const inbox = env.INBOX.getByName('bound-receiver-v1');
    if (isMetadata) {
      const value = await inbox.describe();
      return Response.json(value, {headers: {'Cache-Control': 'no-store, private'}});
    }
    const type = request.headers.get('Content-Type');
    if (!['text/plain; charset=utf-8', 'application/json'].includes(type)) return reply(415, 'unsupported_media');
    let bytes; try {bytes = await readBody(request.body, type === 'application/json' ? 1024 : 2048);}
    catch {return reply(413, 'body_limit');}
    const r = await inbox.receive(Object.fromEntries(request.headers), new Uint8Array(bytes));
    if (r.probe) return Response.json(r.probe, {headers: {'Cache-Control': 'no-store, private'}});
    if (r.proof) return new Response(r.proof, {headers: {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, private'}});
    return r.status === 204 ? new Response(null, {status: 204, headers: {'Cache-Control': 'no-store, private'}}) : reply(r.status, r.code);
  } catch {return reply(503, 'receiver_unavailable');}
}};
export class TrialReceiverInbox extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env); this.sql = ctx.storage.sql;
    this.ctx.blockConcurrencyWhile(async () => {
      const m = config(this.env), now = Date.now();
      this.ctx.storage.transactionSync(() => {
        this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_setup(id INTEGER PRIMARY KEY CHECK(id=1),manifest TEXT NOT NULL,installation TEXT,digest TEXT,ready INTEGER NOT NULL,cycles INTEGER NOT NULL,next_at INTEGER NOT NULL)');
        this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_operations(operation_key TEXT PRIMARY KEY,body_sha256 TEXT NOT NULL,first_task TEXT NOT NULL,body BLOB NOT NULL)');
        this.sql.exec('CREATE TABLE IF NOT EXISTS receiver_effect(id INTEGER PRIMARY KEY CHECK(id=1),accepted_operations INTEGER NOT NULL)');
        this.sql.exec('INSERT OR IGNORE INTO receiver_effect VALUES(1,0)');
        const next = Math.max(m.issued_at_ms, now) + CADENCE;
        this.sql.exec('INSERT OR IGNORE INTO receiver_setup VALUES(1,?,NULL,NULL,0,0,?)', JSON.stringify(m), next);
        this.state(m); // Existing configuration cannot be rebound or replaced.
      });
      const s = this.state(m);
      if (!s.ready && s.cycles < MAX_CYCLES && now < m.expires_at_ms && s.next_at < m.expires_at_ms
        && await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Math.max(now + 1, s.next_at));
    });
  }
  state(m = config(this.env)) {
    const s = this.sql.exec('SELECT * FROM receiver_setup WHERE id=1').one();
    if (s.manifest !== JSON.stringify(m) || ![0, 1].includes(s.ready) || !Number.isSafeInteger(s.cycles)
      || s.cycles < 0 || s.cycles > MAX_CYCLES || !Number.isSafeInteger(s.next_at) || s.next_at < 0) throw Error();
    if (s.installation !== null) {
      if (typeof s.installation !== 'string' || Buffer.byteLength(s.installation) > 16384 || !hex(s.digest)) throw Error();
      installation({installation: JSON.parse(s.installation), installation_sha256: s.digest}, m, Date.now(), {persisted: true});
    } else if (s.digest !== null || s.ready !== 0) throw Error();
    return s;
  }
  describe() {const m = config(this.env); this.state(m); return m;}
  async alarm() {
    const m = config(this.env), now = Date.now(), s = this.state(m);
    if (s.ready || s.cycles >= MAX_CYCLES || now >= m.expires_at_ms) {await this.ctx.storage.deleteAlarm(); return;}
    if (now < s.next_at) {await this.ctx.storage.setAlarm(s.next_at); return;}
    const next = now + CADENCE;
    this.sql.exec('UPDATE receiver_setup SET cycles=cycles+1,next_at=? WHERE id=1', next);
    // Persist and pre-arm before network I/O. Public calls cannot reset or accelerate this cadence.
    if (s.cycles + 1 < MAX_CYCLES && next < m.expires_at_ms) await this.ctx.storage.setAlarm(next);
    try {
      const key = privateKey(this.env.RECEIVER_SETUP_PRIVATE_KEY, m);
      let current = this.state(m);
      if (!current.installation) {
        const response = await apiRequest(m, key, PULL, {}), payload = installation(response, m, Date.now());
        this.ctx.storage.transactionSync(() => {
          current = this.state(m);
          if (current.installation && (current.digest !== response.installation_sha256 || current.installation !== JSON.stringify(payload))) throw Error();
          if (!current.installation) this.sql.exec('UPDATE receiver_setup SET installation=?,digest=? WHERE id=1', JSON.stringify(payload), response.installation_sha256);
        });
      }
      current = this.state(m);
      // No lock/transaction spans this await: API calls /callback with the preinstalled hidden proof.
      const ack = await apiRequest(m, key, ACK, {installation_sha256: current.digest});
      if (!exact(ack, ['state', 'project_id', 'receiver_ready', 'endpoint_id']) || ack.state !== 'ready'
        || ack.project_id !== m.project_id || ack.receiver_ready !== true || ack.endpoint_id !== 'receiver') throw Error();
      this.sql.exec('UPDATE receiver_setup SET ready=1 WHERE id=1');
      await this.ctx.storage.deleteAlarm();
    } catch { /* Bounded next alarm reconciles the same tuple; no logging of transport or payload. */ }
  }
  receive(headers, bytes) {
    const m = config(this.env), s = this.state(m), now = Date.now();
    if (!(bytes instanceof Uint8Array) || bytes.length > 2048) return {status: 413, code: 'body_limit'};
    const type = new Headers(headers).get('Content-Type');
    if (type === 'text/plain; charset=utf-8') {
      if (Buffer.from(bytes).subarray(0, 27).equals(Buffer.from('RunLater receiver probe v1\n'))) {
        try {return {probe: probeResponse(m, privateKey(this.env.RECEIVER_SETUP_PRIVATE_KEY, m), bytes, now)};}
        catch {return {status: 403, code: 'probe_forbidden'};}
      }
      if (!s.installation) return {status: 503, code: 'receiver_unconfigured'};
      try {return {proof: destinationProof(JSON.parse(s.installation), bytes, now)};}
      catch {return {status: 403, code: 'proof_forbidden'};}
    }
    if (type !== 'application/json' || bytes.length > 1024) return {status: 415, code: 'unsupported_media'};
    if (!s.installation) return {status: 503, code: 'receiver_unconfigured'};
    const p = JSON.parse(s.installation);
    if (!callbackValid(p, headers, bytes, now)) return {status: 403, code: 'callback_forbidden'};
    return this.ctx.storage.transactionSync(() => {
      const h = new Headers(headers), operation = h.get('RunLater-Operation-Key'), hash = sha(bytes);
      const old = this.sql.exec('SELECT body_sha256 FROM receiver_operations WHERE operation_key=?', operation).toArray()[0];
      if (old) return old.body_sha256 === hash ? {status: 204} : {status: 409, code: 'operation_conflict'};
      if (this.sql.exec('SELECT count(*) AS n FROM receiver_operations').one().n >= MAX_OPERATIONS) return {status: 429, code: 'receiver_full'};
      this.sql.exec('INSERT INTO receiver_operations VALUES(?,?,?,?)', operation, hash, h.get('RunLater-Task-Id'), bytes);
      this.sql.exec('UPDATE receiver_effect SET accepted_operations=accepted_operations+1 WHERE id=1');
      return {status: 204};
    });
  }
}
