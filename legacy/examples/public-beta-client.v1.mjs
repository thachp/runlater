// Source-only public-beta v1. Explicit transport; no default network, retries or payments.
import {createHash, createPrivateKey, createPublicKey, randomBytes, sign} from 'node:crypto';
import {validatePolicy} from './rotating-receiver.mjs';
export {readOwnerText, loadOwnerKey, writeOwnerJson} from './invitation-client.v1.mjs';

export const ORIGIN = 'https://api.runlater.io';
const PERMISSIONS = Object.freeze(['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations']);
export const PUBLIC_BETA_TERMS = Object.freeze({attempt_units: 100, identity_ms: 604800000, permissions: PERMISSIONS});
const hash = value => createHash('sha256').update(value).digest('hex');
const hex64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const stable = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const same = (a, b) => stable(a) === stable(b);
const exact = (v, fields) => v && typeof v === 'object' && !Array.isArray(v)
  && same(Object.keys(v).sort(), [...fields].sort());
const commandKey = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const version = value => Number.isInteger(value) && value > 0 && value <= 0xffffffff;
export class PublicBetaClientError extends Error {
  constructor(code, status = null) {
    super(`RunLater public-beta client: ${code}${status === null ? '' : ` (HTTP ${status})`}`);
    this.name = 'PublicBetaClientError'; this.code = code; this.status = status;
  }
}
function requireValue(ok, code = 'invalid_context') { if (!ok) throw new PublicBetaClientError(code); }
function terms(value) {
  requireValue(exact(value, ['attempt_units', 'identity_ms', 'permissions'])
    && value.attempt_units === 100 && value.identity_ms === 604800000 && same(value.permissions, PERMISSIONS), 'unexpected_terms');
  return {attempt_units: 100, identity_ms: 604800000, permissions: [...PERMISSIONS]};
}
function endpointURL(value) {
  requireValue(typeof value === 'string' && Buffer.byteLength(value) <= 256, 'invalid_endpoint');
  let u; try { u = new URL(value); } catch { throw new PublicBetaClientError('invalid_endpoint'); }
  requireValue(u.href === value && u.protocol === 'https:' && !u.username && !u.password && !u.port && !u.search && !u.hash
    && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/.test(u.hostname), 'invalid_endpoint');
  return value; // The server's strict-public-host policy independently remains authoritative.
}
function endpointInput(id, revision) { requireValue(identifier(id) && version(revision), 'invalid_endpoint'); return {endpoint_id: id, version: revision}; }
function endpoint(value, expected) {
  requireValue(exact(value, ['endpoint_id', 'version', 'url', 'status', 'created_at_ms', 'verified_at_ms', 'revoked_at_ms'])
    && value.endpoint_id === expected.endpoint_id && value.version === expected.version && value.url === expected.url
    && ['pending', 'verified', 'revoked'].includes(value.status) && integer(value.created_at_ms)
    && (value.verified_at_ms === null || integer(value.verified_at_ms))
    && (value.revoked_at_ms === null || integer(value.revoked_at_ms)), 'invalid_endpoint_response');
  return value;
}
function taskId(id) { requireValue(typeof id === 'string' && /^task_[a-f0-9]{16}$/.test(id), 'invalid_task'); return id; }

export class PublicBetaClientV1 {
  #key; #fetch; #clock; #nonce; #timeout; #project = null; #release; #ticket; #receipt = null; #offerTicket = null;
  constructor({privateKey, fetchImpl, releaseId, receipt = null, clock = Date.now,
    nonce = () => randomBytes(32).toString('hex'), timeoutMs = 5000} = {}) {
    requireValue(typeof fetchImpl === 'function', 'explicit_transport_required');
    requireValue(identifier(releaseId) && releaseId.length <= 32, 'reviewed_release_id_required');
    requireValue(typeof clock === 'function' && typeof nonce === 'function' && Number.isInteger(timeoutMs)
      && timeoutMs > 0 && timeoutMs <= 5000, 'invalid_client_options');
    try { this.#key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey); }
    catch { throw new PublicBetaClientError('ed25519_private_key_required'); }
    requireValue(this.#key.type === 'private' && this.#key.asymmetricKeyType === 'ed25519', 'ed25519_private_key_required');
    this.#fetch = fetchImpl; this.#clock = clock; this.#nonce = nonce; this.#timeout = timeoutMs; this.#release = releaseId;
    this.publicKey = createPublicKey(this.#key).export({type: 'spki', format: 'der'}).subarray(-32).toString('hex');
    Object.defineProperty(this, 'publicKey', {writable: false, configurable: false});
    this.#ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, this.publicKey]));
    if (receipt !== null) this.#acceptReceipt(receipt);
  }
  get expectedProject() { return 'p_' + this.#ticket.slice(0, 60); }
  get project() { return this.#project; }
  get receipt() { return structuredClone(this.#receipt); }
  #now() { const at = this.#clock(); requireValue(integer(at) && at <= Number.MAX_SAFE_INTEGER - 300000, 'invalid_clock'); return at; }
  #random() { const n = this.#nonce(); requireValue(hex64(n), 'invalid_nonce'); return n; }
  async #request(path, {method = 'POST', body, idempotencyKey = '', signed = false} = {}) {
    const registration = /^\/v1\/registration\/(challenge|complete|recover)$/.test(path);
    const destination = /^\/v1\/destinations\/(create|prepare|verify|revoke)$/.test(path);
    const task = /^\/v1\/tasks(?:\/task_[a-f0-9]{16}(?:\/(?:cancel|redrive))?)?$/.test(path);
    requireValue(registration || destination || task || path === '/v1/callback-key' || path === '/v1/beta', 'unsupported_route');
    const bytes = body === undefined ? '' : JSON.stringify(body);
    requireValue(Buffer.byteLength(bytes) <= 2048, 'request_too_large');
    const headers = body === undefined ? {} : {'Content-Type': 'application/json'};
    if (signed) {
      requireValue(this.#receipt !== null && this.#project === this.expectedProject, 'enrollment_required');
      requireValue(this.#receipt.expires_at_ms > this.#now(), 'identity_expired');
      if (method === 'GET') requireValue(body === undefined && !idempotencyKey, 'invalid_read');
      else if (!path.endsWith('/cancel')) requireValue(commandKey(idempotencyKey), 'idempotency_key_required');
      const at = this.#now(), nonce = this.#random();
      const wire = 'RunLater signed request v1\n' + JSON.stringify([1, ORIGIN, this.#project, this.publicKey,
        method, path, '', hash(bytes), idempotencyKey, at, at + 60000, nonce]);
      Object.assign(headers, {'RunLater-Project-Id': this.#project, 'RunLater-Public-Key': this.publicKey,
        'RunLater-Nonce': nonce, 'RunLater-Issued-At': String(at), 'RunLater-Expires-At': String(at + 60000),
        'RunLater-Request-Signature': sign(null, Buffer.from(wire), this.#key).toString('hex')});
      if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    }
    const controller = new AbortController(); let reader, timer;
    const deadline = new Promise((_, reject) => { timer = setTimeout(() => {
      controller.abort(); reject(new PublicBetaClientError('transport_uncertain'));
    }, this.#timeout); });
    const action = async () => {
      const response = await this.#fetch(ORIGIN + path, {method, headers, body: bytes || undefined,
        redirect: 'manual', signal: controller.signal});
      requireValue(!(response.status >= 300 && response.status < 400), 'redirect_rejected');
      if (!response.ok) throw new PublicBetaClientError('http_error', response.status);
      let size = 0, chunks = 0; const parts = []; reader = response.body?.getReader();
      if (reader) for (;;) {
        const {done, value} = await reader.read(); if (done) break;
        size += value.byteLength; chunks++; requireValue(size <= 32768 && chunks <= 32, 'response_too_large'); parts.push(Buffer.from(value));
      }
      try { return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts))); }
      catch { throw new PublicBetaClientError('invalid_response'); }
    };
    try { return await Promise.race([action(), deadline]); }
    catch (e) { throw e instanceof PublicBetaClientError ? e : new PublicBetaClientError('transport_uncertain'); }
    finally { clearTimeout(timer); controller.abort(); if (reader) {
      void reader.cancel().catch(() => {}); try { reader.releaseLock(); } catch { /* timed-out pending read */ }
    } }
  }
  #offer(offer) {
    requireValue(exact(offer, ['challenge', 'challenge_id', 'canonical_utf8']));
    const c = offer.challenge, now = this.#now();
    requireValue(exact(c, ['version', 'origin', 'purpose', 'ticket', 'public_key', 'nonce', 'issued_at_ms', 'expires_at_ms']));
    const t = c.ticket;
    requireValue(exact(t, ['id', 'project_id', 'grant_id', 'terms', 'issued_at_ms', 'expires_at_ms', 'policy_revision', 'revoked']));
    const approved = terms(t.terms);
    requireValue(c.version === 1 && c.origin === ORIGIN && c.purpose === 'public_beta_registration'
      && c.public_key === this.publicKey && hex64(c.nonce) && t.id === this.#ticket
      && t.project_id === this.expectedProject && t.grant_id === 'g_' + this.#ticket.slice(0, 60)
      && t.policy_revision === 1 && t.revoked === false && integer(t.issued_at_ms) && t.issued_at_ms <= now
      && integer(t.expires_at_ms) && t.expires_at_ms > t.issued_at_ms && t.expires_at_ms - t.issued_at_ms <= 300000
      && now - t.issued_at_ms <= 604800000 + 300000 && integer(c.issued_at_ms) && c.issued_at_ms <= now
      && c.issued_at_ms >= t.issued_at_ms && integer(c.expires_at_ms) && c.expires_at_ms > now
      && c.expires_at_ms > c.issued_at_ms && c.expires_at_ms - c.issued_at_ms <= 300000);
    // An existing grant's immutable ticket can be older than this fresh recovery challenge.
    const ticket = {id: t.id, project_id: t.project_id, grant_id: t.grant_id, terms: approved,
      issued_at_ms: t.issued_at_ms, expires_at_ms: t.expires_at_ms, policy_revision: t.policy_revision, revoked: t.revoked};
    const wire = 'RunLater public registration proof v1\n' + JSON.stringify([1, ORIGIN, 'public_beta_registration',
      hash(JSON.stringify(ticket)), t.id, t.project_id, t.grant_id, this.publicKey, c.nonce, c.issued_at_ms, c.expires_at_ms]);
    requireValue(offer.canonical_utf8 === wire && offer.challenge_id === hash(wire));
    return {wire, ticket};
  }
  #acceptReceipt(value, ticket = this.#offerTicket) {
    const now = this.#now();
    requireValue(exact(value, ['ticket_id', 'project_id', 'public_key', 'grant_id', 'enrolled_at_ms', 'expires_at_ms', 'attempt_units', 'permissions'])
      && value.ticket_id === this.#ticket && value.project_id === this.expectedProject && value.public_key === this.publicKey
      && value.grant_id === 'g_' + this.#ticket.slice(0, 60) && integer(value.enrolled_at_ms) && value.enrolled_at_ms <= now
      && integer(value.expires_at_ms) && value.expires_at_ms > now && value.expires_at_ms - value.enrolled_at_ms === 604800000
      && value.attempt_units === 100 && same(value.permissions, PERMISSIONS));
    if (ticket) requireValue(value.enrolled_at_ms >= ticket.issued_at_ms && value.enrolled_at_ms < ticket.expires_at_ms);
    if (this.#receipt) requireValue(same(value, this.#receipt), 'receipt_changed');
    this.#receipt = structuredClone(value); this.#project = value.project_id; return structuredClone(value);
  }
  async challenge() {
    const offer = await this.#request('/v1/registration/challenge', {body: {public_key: this.publicKey}});
    const {ticket} = this.#offer(offer); this.#offerTicket = ticket; return offer;
  }
  async complete(offer, expectedTerms) {
    terms(expectedTerms); const {wire, ticket} = this.#offer(offer); this.#offerTicket = ticket;
    const receipt = await this.#request('/v1/registration/complete', {body: {challenge_id: offer.challenge_id,
      signature: sign(null, Buffer.from(wire), this.#key).toString('hex')}});
    return this.#acceptReceipt(receipt, ticket);
  }
  async recover() {
    const at = this.#now(), nonce = this.#random();
    // This prefix is intentionally shared by the actual public recovery DTO.
    const wire = 'RunLater invitation recovery v1\n' + JSON.stringify([1, ORIGIN, this.expectedProject, this.publicKey, nonce, at, at + 60000]);
    const receipt = await this.#request('/v1/registration/recover', {body: {project_id: this.expectedProject,
      public_key: this.publicKey, nonce, issued_at_ms: at, expires_at_ms: at + 60000,
      signature: sign(null, Buffer.from(wire), this.#key).toString('hex')}});
    return this.#acceptReceipt(receipt);
  }
  async callbackKey(idempotencyKey) {
    const result = await this.#request('/v1/callback-key', {body: {}, idempotencyKey, signed: true});
    requireValue(exact(result, ['version', 'project_id', 'policy_id', 'key_id', 'key_hex', 'signature_window_sec'])
      && result.version === 'v2' && result.project_id === this.expectedProject && result.policy_id === 'public_beta_' + this.#release
      && result.key_id === 'beta_v1' && hex64(result.key_hex) && !/^(..)(?:\1){31}$/.test(result.key_hex)
      && result.signature_window_sec === 300, 'invalid_callback_key');
    return result; // Secret owner-only output. Never automatically log, install or persist it.
  }
  async status() {
    const v = await this.#request('/v1/beta', {method: 'GET'});
    requireValue(exact(v, ['mode', 'registration_open', 'remaining_projects', 'trial', 'limits', 'payments'])
      && v.mode === 'public_free_beta' && typeof v.registration_open === 'boolean' && v.payments === false
      && integer(v.remaining_projects) && v.remaining_projects <= 10
      && same(v.trial, {attempt_units: 100, duration_ms: 604800000, units_reserved_per_task: 5})
      && same(v.limits, {client_operations_per_project: 1000, lifetime_projects: 10, lifetime_publications_per_project: 128,
        lifetime_tasks_per_project: 16, receiver: 'worker.account.workers.dev'}), 'invalid_beta_status');
    return v;
  }
  async createDestination(id, revision, url, idempotencyKey) {
    const input = {...endpointInput(id, revision), url: endpointURL(url)};
    return endpoint(await this.#request('/v1/destinations/create', {body: input, idempotencyKey, signed: true}), input);
  }
  async prepareDestination(value, idempotencyKey) {
    const input = endpointInput(value.endpoint_id, value.version), url = endpointURL(value.url);
    const proof = await this.#request('/v1/destinations/prepare', {body: input, idempotencyKey, signed: true});
    const prefix = 'RunLater destination proof v1\n';
    requireValue(exact(proof, ['id', 'response', 'expires_at_ms']) && hex64(proof.id)
      && typeof proof.response === 'string' && Buffer.byteLength(proof.response) <= 1024 && proof.response.startsWith(prefix));
    let tuple; try { tuple = JSON.parse(proof.response.slice(prefix.length)); } catch { throw new PublicBetaClientError('invalid_context'); }
    const now = this.#now();
    requireValue(Array.isArray(tuple) && tuple.length === 8 && same(tuple.slice(0, 5), [1, this.#project, input.endpoint_id, input.version, url])
      && Number.isInteger(tuple[5]) && tuple[5] >= 1 && tuple[5] <= 3 && integer(tuple[6]) && tuple[6] === proof.expires_at_ms
      && tuple[6] > now && tuple[6] - now <= 300000 && hex64(tuple[7]) && hash(proof.response) === proof.id
      && proof.response === prefix + JSON.stringify(tuple));
    return proof;
  }
  async verifyDestination(value, idempotencyKey) {
    const input = endpointInput(value.endpoint_id, value.version); endpointURL(value.url);
    const result = endpoint(await this.#request('/v1/destinations/verify', {body: input, idempotencyKey, signed: true}), value);
    requireValue(result.status === 'verified'); return result;
  }
  async revokeDestination(id, revision, idempotencyKey) {
    const result = await this.#request('/v1/destinations/revoke', {body: endpointInput(id, revision), idempotencyKey, signed: true});
    requireValue(exact(result, ['revoked']) && result.revoked === true); return result;
  }
  enqueue(input, idempotencyKey) {
    requireValue(exact(input, ['endpoint_id', 'body', 'operation_key', 'run_at_ms']) && identifier(input.endpoint_id)
      && typeof input.body === 'string' && Buffer.byteLength(input.body) <= 1024 && commandKey(input.operation_key)
      && integer(input.run_at_ms) && this.#receipt && input.run_at_ms <= this.#receipt.expires_at_ms, 'invalid_task');
    return this.#request('/v1/tasks', {body: {destination: 'registered:' + input.endpoint_id, body: input.body,
      operation_key: input.operation_key, run_at_ms: input.run_at_ms}, idempotencyKey, signed: true});
  }
  task(id) { return this.#request('/v1/tasks/' + taskId(id), {method: 'GET', signed: true}); }
  cancel(id) { return this.#request('/v1/tasks/' + taskId(id) + '/cancel', {body: {}, signed: true}); }
  redrive(id, idempotencyKey) { return this.#request('/v1/tasks/' + taskId(id) + '/redrive', {body: {}, idempotencyKey, signed: true}); }
}

/** Explicit owner setup. The key DTO does not carry release validity times; never infer them. */
export function receiverSetup({receipt, callbackKey, callbackPolicy, url}) {
  endpointURL(url);
  requireValue(new URL(url).pathname === '/callback' && validatePolicy(callbackPolicy)
    && identifier(receipt?.project_id) && exact(callbackKey, ['version', 'project_id', 'policy_id', 'key_id', 'key_hex', 'signature_window_sec'])
    && receipt.project_id === callbackKey.project_id && callbackPolicy.tenant === receipt.project_id
    && callbackKey.version === 'v2' && callbackPolicy.policy_id === callbackKey.policy_id
    && callbackKey.key_id === 'beta_v1' && callbackKey.signature_window_sec === 300 && hex64(callbackKey.key_hex)
    && !/^(..)(?:\1){31}$/.test(callbackKey.key_hex)
    && callbackPolicy.revision === 1 && Object.keys(callbackPolicy.keys).join(',') === 'beta_v1'
    && callbackPolicy.keys.beta_v1.revoked_at_sec === null, 'reviewed_receiver_policy_required');
  return {RECEIVER_ENABLED: 'owner-configured', RECEIVER_URL: url, RECEIVER_PROJECT_ID: receipt.project_id,
    CALLBACK_POLICY: JSON.stringify(callbackPolicy), CALLBACK_KEYS: JSON.stringify({beta_v1: callbackKey.key_hex})};
}
