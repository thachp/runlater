// Dedicated anonymous-trial authority; OAuth bearer tokens are never forwarded.
import {createHash, createPrivateKey, randomBytes, sign} from 'node:crypto';
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
import {API_ORIGIN, delegationPublicKey} from './delegation.mjs';
import {TRIAL_SCOPES} from './oauth-consent.mjs';
import {receiverManifest} from './receiver-manifest.mjs';
import {httpTaskInput} from './http-task.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join() === [...fields].sort().join();
const key = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const check = (ok, code = 'invalid_trial_context') => {if (!ok) throw new PublicBetaClientError(code);};
export function canonicalTrialDescriptor(value) {
  check(exact(value, ['version', 'release_id', 'bootstrap_id', 'capability_hash', 'revocation_hash', 'issued_at_ms', 'expires_at_ms', 'permissions'])
    && value.version === 1 && typeof value.release_id === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(value.release_id)
    && hex(value.bootstrap_id) && hex(value.capability_hash) && hex(value.revocation_hash)
    && integer(value.issued_at_ms) && integer(value.expires_at_ms) && value.expires_at_ms - value.issued_at_ms === 604800000
    && Array.isArray(value.permissions) && value.permissions.length > 0
    && value.permissions.every(scope => TRIAL_SCOPES.includes(scope))
    && JSON.stringify(value.permissions) === JSON.stringify([...new Set(value.permissions)].sort()));
  // This order is part of the signed cross-language wire contract.
  return {version: 1, release_id: value.release_id, bootstrap_id: value.bootstrap_id,
    capability_hash: value.capability_hash, revocation_hash: value.revocation_hash,
    issued_at_ms: value.issued_at_ms, expires_at_ms: value.expires_at_ms, permissions: [...value.permissions]};
}
export function trialProjectId(descriptor) {
  const d = canonicalTrialDescriptor(descriptor);
  return 'p_' + hash('RunLater anonymous trial project v1\n' + JSON.stringify([1, d.release_id, d.bootstrap_id])).slice(0, 60);
}
export class AnonymousTrialClientV1 {
  #key; #descriptor; #secret; #revocation; #fetch; #clock; #nonce; #timeout;
  constructor({privateKey, descriptor, capability, revocationSecret, releaseId, fetchImpl,
    clock = Date.now, nonce = () => randomBytes(32).toString('hex'), timeoutMs = 5000} = {}) {
    check(typeof fetchImpl === 'function', 'explicit_transport_required');
    check(typeof clock === 'function' && typeof nonce === 'function' && Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000);
    const d = canonicalTrialDescriptor(descriptor);
    check(d.release_id === releaseId && d.issued_at_ms <= clock() && d.expires_at_ms > clock(), 'identity_expired');
    check((capability === undefined) !== (revocationSecret === undefined));
    const purpose = capability === undefined ? 'revocation' : 'capability', secret = capability ?? revocationSecret;
    check(hex(secret) && d[purpose + '_hash'] === hash(`RunLater anonymous trial ${purpose} v1\n`
      + JSON.stringify([1, d.release_id, d.bootstrap_id, secret])));
    this.#key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
    delegationPublicKey(this.#key); // Reject non-Ed25519 input before any network request.
    this.#descriptor = d; this.#secret = secret; this.#revocation = purpose === 'revocation';
    this.#fetch = fetchImpl; this.#clock = clock; this.#nonce = nonce; this.#timeout = timeoutMs;
  }
  get project() {return trialProjectId(this.#descriptor);}
  async #request(path, {method = 'POST', body, idempotencyKey = '', permission = null} = {}) {
    const d = this.#descriptor, now = this.#clock();
    check(integer(now) && now >= d.issued_at_ms && now < d.expires_at_ms, 'identity_expired');
    check(this.#revocation === (path === '/v1/mcp/trials/revoke'), 'insufficient_scope');
    if (permission !== null) check(d.permissions.includes(permission), 'insufficient_scope');
    const nonce = this.#nonce(); check(hex(nonce));
    const bytes = body === undefined ? '' : JSON.stringify(body); check(Buffer.byteLength(bytes) <= (path === '/v1/http/tasks' ? 4096 : 2048), 'request_too_large');
    const expires = Math.min(now + 60000, d.expires_at_ms), descriptor = JSON.stringify(d);
    const wire = 'RunLater anonymous trial request v1\n' + JSON.stringify([1, API_ORIGIN, d.release_id, this.project,
      d.bootstrap_id, d.capability_hash, hash(descriptor), method, path, '', hash(bytes), idempotencyKey, now, expires, nonce]);
    const headers = {'RunLater-Project-Id': this.project, 'RunLater-Nonce': nonce,
      'RunLater-Issued-At': String(now), 'RunLater-Expires-At': String(expires),
      'RunLater-Request-Signature': sign(null, Buffer.from(wire), this.#key).toString('hex'),
      'RunLater-Trial-Bootstrap': Buffer.from(descriptor).toString('base64url'),
      [this.#revocation ? 'RunLater-Trial-Revocation' : 'RunLater-Trial-Capability']: this.#secret};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    const controller = new AbortController(); let reader, timer;
    const deadline = new Promise((_, reject) => {timer = setTimeout(() => {
      controller.abort(); reject(new PublicBetaClientError('transport_uncertain'));
    }, this.#timeout);});
    try {return await Promise.race([deadline, (async () => {
      const response = await this.#fetch(API_ORIGIN + path, {method, headers, body: bytes || undefined, redirect: 'manual', signal: controller.signal});
      check(!(response.status >= 300 && response.status < 400), 'redirect_rejected');
      if (!response.ok) {
        if (path === '/v1/http/tasks' && response.status === 503) {
          reader = response.body?.getReader(); let size = 0, chunks = 0; const parts = [];
          if (reader) for (;;) {const {done, value} = await reader.read(); if (done) break;
            check((size += value.byteLength) <= 1024 && ++chunks <= 16, 'invalid_response'); parts.push(Buffer.from(value));}
          let error; try {error = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts)));} catch {}
          if (exact(error, ['error', 'task_accepted']) && error.task_accepted === false
            && exact(error.error, ['code']) && error.error.code === 'general_https_unavailable')
            throw new PublicBetaClientError('general_https_unavailable', 503);
        }
        throw new PublicBetaClientError('http_error', response.status);
      }
      reader = response.body?.getReader(); let size = 0, chunks = 0; const parts = [];
      if (reader) for (;;) {const {done, value} = await reader.read(); if (done) break;
        check((size += value.byteLength) <= 32768 && ++chunks <= 32, 'response_too_large'); parts.push(Buffer.from(value));}
      try {return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts)));}
      catch {throw new PublicBetaClientError('invalid_response');}
    })()]);} catch (error) {throw error instanceof PublicBetaClientError ? error : new PublicBetaClientError('transport_uncertain');}
    finally {clearTimeout(timer); controller.abort(); if (reader) {void reader.cancel().catch(() => {}); try {reader.releaseLock();} catch {}}}
  }
  #lifecycle(value) {
    const d = this.#descriptor;
    check(exact(value, ['state', 'project_id', 'expires_at_ms', 'permissions', 'receiver_ready', 'attempt_units', 'client_operations_limit',
      ...(value?.receiver_ready === true ? ['endpoint_id'] : [])])
      && ['unprovisioned', 'active'].includes(value.state) && value.project_id === this.project
      && value.expires_at_ms === d.expires_at_ms && JSON.stringify(value.permissions) === JSON.stringify(d.permissions)
      && (value.receiver_ready === false || (value.receiver_ready === true && value.state === 'active' && value.endpoint_id === 'receiver'))
      && value.attempt_units === (value.state === 'active' ? 100 : 0)
      && value.client_operations_limit === 1000, 'invalid_trial_response');
    return value;
  }
  async provision() {return this.#lifecycle(await this.#request('/v1/mcp/trials/provision', {body: {}, idempotencyKey: this.#descriptor.bootstrap_id}));}
  async status() {return this.#lifecycle(await this.#request('/v1/mcp/trials/status', {method: 'GET'}));}
  async validate() {return this.#lifecycle(await this.#request('/v1/mcp/trials/validate', {body: {}}));}
  async pairReceiver(manifest) {
    check(!this.#revocation && this.#descriptor.permissions.includes('receiver_setup'), 'insufficient_scope');
    const d = this.#descriptor, body = receiverManifest(manifest, {project: this.project,
      releaseId: d.release_id, now: this.#clock(), trialExpiresAt: d.expires_at_ms});
    const value = await this.#request('/v1/mcp/trials/receiver', {body, idempotencyKey: body.pairing_id, permission: 'receiver_setup'});
    check(exact(value, ['state', 'project_id', 'receiver_ready', 'endpoint_id']) && value.project_id === this.project
      && ((value.state === 'awaiting_receiver' && value.receiver_ready === false && value.endpoint_id === null)
        || (value.state === 'ready' && value.receiver_ready === true && value.endpoint_id === 'receiver')), 'invalid_trial_response');
    return value;
  }
  async revoke() {
    const value = await this.#request('/v1/mcp/trials/revoke', {body: {}, idempotencyKey: this.#descriptor.bootstrap_id});
    check(exact(value, ['revoked', 'provisioned']) && value.revoked === true && typeof value.provisioned === 'boolean', 'invalid_trial_response');
    return value;
  }
  scheduleHttp(input, idempotencyKey) {
    check(key(idempotencyKey), 'idempotency_key_required');
    const body = httpTaskInput(input, {expiresAt: this.#descriptor.expires_at_ms});
    return this.#request('/v1/http/tasks', {body, idempotencyKey, permission: 'http_schedule'});
  }
  enqueue(input, idempotencyKey) {
    check(exact(input, ['endpoint_id', 'body', 'operation_key', 'run_at_ms'])
      && typeof input.endpoint_id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(input.endpoint_id)
      && typeof input.body === 'string' && Buffer.byteLength(input.body) <= 1024 && key(input.operation_key)
      && integer(input.run_at_ms) && input.run_at_ms <= this.#descriptor.expires_at_ms, 'invalid_task');
    check(key(idempotencyKey), 'idempotency_key_required');
    return this.#request('/v1/tasks', {body: {destination: 'registered:' + input.endpoint_id, body: input.body,
      operation_key: input.operation_key, run_at_ms: input.run_at_ms}, idempotencyKey, permission: 'enqueue'});
  }
  task(id) {check(typeof id === 'string' && /^task_[a-f0-9]{16}$/.test(id), 'invalid_task');
    return this.#request('/v1/tasks/' + id, {method: 'GET', permission: 'read'});}
  cancel(id) {check(typeof id === 'string' && /^task_[a-f0-9]{16}$/.test(id), 'invalid_task');
    return this.#request('/v1/tasks/' + id + '/cancel', {body: {}, permission: 'cancel'});}
}
