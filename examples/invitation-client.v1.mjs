// Source-only invitation contract v1. Transport is injected explicitly; no default network calls.
import {createHash, createPrivateKey, createPublicKey, randomBytes, sign} from 'node:crypto';
import fs from 'node:fs';

export const ORIGIN = 'https://api.runlater.io';
const PERMISSIONS = ['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations'];
const sha = value => createHash('sha256').update(value).digest('hex');
const hex64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...fields].sort());
const key = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const version = value => Number.isInteger(value) && value > 0 && value <= 0xffffffff;

export class InvitationClientError extends Error {
  constructor(code, status = null) {
    super(`RunLater invitation client: ${code}${status === null ? '' : ` (HTTP ${status})`}`);
    this.name = 'InvitationClientError'; this.code = code; this.status = status;
  }
}
function requireValue(ok, code = 'invalid_context') { if (!ok) throw new InvitationClientError(code); }
function terms(value) {
  requireValue(exact(value, ['attempt_units', 'identity_ms', 'permissions']));
  requireValue(integer(value.attempt_units) && value.attempt_units >= 5 && value.attempt_units <= 1000000
    && integer(value.identity_ms) && value.identity_ms > 0 && value.identity_ms <= 30 * 86400000);
  const p = value.permissions;
  // Rust BTreeSet follows Permission enum order, not alphabetical order.
  requireValue(Array.isArray(p) && p.length > 0 && same(p, PERMISSIONS.filter(item => p.includes(item))));
  return {attempt_units: value.attempt_units, identity_ms: value.identity_ms, permissions: [...p]};
}
function endpointURL(value) {
  requireValue(typeof value === 'string' && Buffer.byteLength(value) <= 256, 'invalid_endpoint');
  let u; try { u = new URL(value); } catch { throw new InvitationClientError('invalid_endpoint'); }
  requireValue(u.protocol === 'https:' && u.href === value && !u.username && !u.password
    && !u.port && !u.search && !u.hash && u.hostname.includes('.')
    && u.hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    && !/^\d+(?:\.\d+){3}$/.test(u.hostname), 'invalid_endpoint');
  return value; // Syntax only. The server's independent operator allowlist remains authoritative.
}
function endpointInput(id, revision) { requireValue(identifier(id) && version(revision), 'invalid_endpoint'); return {endpoint_id: id, version: revision}; }
function taskId(id) { requireValue(typeof id === 'string' && /^task_[a-f0-9]{16}$/.test(id), 'invalid_task'); return id; }

/** Owner-only bounded text input; refuses symlinks and files readable by another account. */
export function readOwnerText(file, limit = 4096) {
  let fd;
  try {
    requireValue(typeof fs.constants.O_NOFOLLOW === 'number' && typeof process.getuid === 'function'
      && Number.isSafeInteger(limit) && limit > 0 && limit <= 65536, 'posix_owner_files_required');
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const s = fs.fstatSync(fd);
    requireValue(s.isFile() && s.size <= limit && (s.mode & 0o077) === 0
      && (!process.getuid || s.uid === process.getuid()), 'owner_file_required');
    // Bound the read even if the file grows after fstat.
    const bytes = Buffer.alloc(limit + 1), size = fs.readSync(fd, bytes, 0, bytes.length, 0);
    requireValue(size <= limit, 'owner_file_required');
    return new TextDecoder('utf-8', {fatal: true}).decode(bytes.subarray(0, size));
  } catch { throw new InvitationClientError('owner_file_required'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
export function loadOwnerKey(file) {
  try { return createPrivateKey(readOwnerText(file)); }
  catch { throw new InvitationClientError('owner_private_key_required'); }
}
export function loadInvitationToken(file) {
  const value = readOwnerText(file, 128).trim(); requireValue(hex64(value), 'invalid_invitation'); return value;
}
/** Exclusive creation: never overwrite a proof/receipt or follow an existing symlink. */
export function writeOwnerJson(file, value) {
  requireValue(typeof process.getuid === 'function', 'posix_owner_files_required');
  try { fs.writeFileSync(file, JSON.stringify(value) + '\n', {flag: 'wx', mode: 0o600}); }
  catch { throw new InvitationClientError('owner_output_exists_or_unavailable'); }
}

export class InvitationClientV1 {
  #key; #fetch; #clock; #nonce; #timeout; #project; #ticketId;
  constructor({privateKey, fetchImpl, project = null, ticketId = null, clock = Date.now,
    nonce = () => randomBytes(32).toString('hex'), timeoutMs = 5000} = {}) {
    requireValue(typeof fetchImpl === 'function', 'explicit_transport_required');
    requireValue(typeof clock === 'function' && typeof nonce === 'function'
      && Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000, 'invalid_client_options');
    try { this.#key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey); }
    catch { throw new InvitationClientError('ed25519_private_key_required'); }
    requireValue(this.#key.type === 'private' && this.#key.asymmetricKeyType === 'ed25519', 'ed25519_private_key_required');
    requireValue(project === null || identifier(project), 'invalid_project');
    requireValue(ticketId === null || hex64(ticketId)
      && (project === null || project === 'p_' + ticketId.slice(0, 60)), 'invalid_ticket');
    this.#ticketId = ticketId;
    this.#project = project; this.#fetch = fetchImpl; this.#clock = clock; this.#nonce = nonce; this.#timeout = timeoutMs;
    this.publicKey = createPublicKey(this.#key).export({type: 'spki', format: 'der'}).subarray(-32).toString('hex');
    Object.defineProperty(this, 'publicKey', {writable: false, configurable: false});
  }
  get project() { return this.#project; }
  #now() { const at = this.#clock(); requireValue(integer(at) && at <= Number.MAX_SAFE_INTEGER - 60000, 'invalid_clock'); return at; }
  #random() { const n = this.#nonce(); requireValue(hex64(n), 'invalid_nonce'); return n; }
  async #request(path, {method = 'POST', body, idempotencyKey = '', signed = false} = {}) {
    const registration = /^\/registration\/(challenge|complete|recover)$/.test(path);
    const destination = /^\/v1\/destinations\/(create|prepare|verify|revoke)$/.test(path);
    const task = /^\/v1\/tasks(?:\/task_[a-f0-9]{16}(?:\/(?:cancel|redrive))?)?$/.test(path);
    requireValue(registration || destination || task, 'unsupported_route');
    const bytes = body === undefined ? '' : JSON.stringify(body);
    requireValue(Buffer.byteLength(bytes) <= 2048, 'request_too_large');
    const headers = body === undefined ? {} : {'Content-Type': 'application/json'};
    if (signed) {
      requireValue(identifier(this.#project), 'enrollment_or_project_required');
      if (method === 'GET') requireValue(!body && !idempotencyKey, 'invalid_read');
      else if (!path.endsWith('/cancel')) requireValue(key(idempotencyKey), 'idempotency_key_required');
      const at = this.#now(), nonce = this.#random();
      const canonical = 'RunLater signed request v1\n' + JSON.stringify([1, ORIGIN, this.#project,
        this.publicKey, method, path, '', sha(bytes), idempotencyKey, at, at + 60000, nonce]);
      Object.assign(headers, {'RunLater-Project-Id': this.#project, 'RunLater-Public-Key': this.publicKey,
        'RunLater-Nonce': nonce, 'RunLater-Issued-At': String(at), 'RunLater-Expires-At': String(at + 60000),
        'RunLater-Request-Signature': sign(null, Buffer.from(canonical), this.#key).toString('hex')});
      if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    }
    const controller = new AbortController(); let reader, timer;
    const deadline = new Promise((_, reject) => { timer = setTimeout(() => {
      controller.abort(); reject(new InvitationClientError('transport_uncertain'));
    }, this.#timeout); });
    const action = async () => {
      const response = await this.#fetch(ORIGIN + path, {method, headers, body: bytes || undefined,
        redirect: 'manual', signal: controller.signal});
      requireValue(!(response.status >= 300 && response.status < 400), 'redirect_rejected');
      if (!response.ok) throw new InvitationClientError('http_error', response.status);
      let size = 0, chunks = 0; const parts = [];
      reader = response.body?.getReader();
      if (reader) for (;;) {
        const {done, value} = await reader.read(); if (done) break;
        size += value.byteLength; chunks++;
        requireValue(size <= 32768 && chunks <= 32, 'response_too_large'); parts.push(Buffer.from(value));
      }
      try { return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts))); }
      catch { throw new InvitationClientError('invalid_response'); }
    };
    try { return await Promise.race([action(), deadline]); }
    catch (e) { throw e instanceof InvitationClientError ? e : new InvitationClientError('transport_uncertain'); }
    finally { clearTimeout(timer); controller.abort(); if (reader) {
      void reader.cancel().catch(() => {}); try { reader.releaseLock(); } catch { /* pending timed-out read */ }
    } }
  }
  #offer(token, offer) {
    requireValue(hex64(token) && exact(offer, ['challenge', 'challenge_id', 'canonical_utf8']), 'invalid_invitation');
    const c = offer.challenge, now = this.#now();
    requireValue(exact(c, ['version', 'origin', 'purpose', 'ticket', 'public_key', 'nonce', 'issued_at_ms', 'expires_at_ms']));
    const t = c.ticket;
    requireValue(exact(t, ['id', 'project_id', 'grant_id', 'terms', 'issued_at_ms', 'expires_at_ms', 'policy_revision', 'revoked']));
    const approved = terms(t.terms), id = sha(token);
    requireValue(c.version === 1 && c.origin === ORIGIN && c.purpose === 'invitation_enrollment'
      && c.public_key === this.publicKey && hex64(c.nonce) && t.id === id
      && t.project_id === 'p_' + id.slice(0, 60) && t.grant_id === 'g_' + id.slice(0, 60)
      && (!this.#project || this.#project === t.project_id)
      && (!this.#ticketId || this.#ticketId === id) && t.revoked === false
      && integer(t.policy_revision) && t.policy_revision > 0 && integer(t.issued_at_ms)
      && integer(t.expires_at_ms) && t.issued_at_ms <= now && t.expires_at_ms > now
      && t.expires_at_ms - t.issued_at_ms <= 86400000
      && integer(c.issued_at_ms) && integer(c.expires_at_ms) && c.issued_at_ms <= now
      && c.issued_at_ms >= t.issued_at_ms && c.expires_at_ms > now
      && c.expires_at_ms <= t.expires_at_ms && c.expires_at_ms - c.issued_at_ms <= 300000);
    // Reconstruct Rust struct field order before hashing; JSON response map order is irrelevant.
    const ticket = {id: t.id, project_id: t.project_id, grant_id: t.grant_id, terms: approved,
      issued_at_ms: t.issued_at_ms, expires_at_ms: t.expires_at_ms, policy_revision: t.policy_revision, revoked: t.revoked};
    const wire = 'RunLater invitation proof v1\n' + JSON.stringify([1, ORIGIN, 'invitation_enrollment',
      sha(JSON.stringify(ticket)), id, t.project_id, t.grant_id, this.publicKey, c.nonce, c.issued_at_ms, c.expires_at_ms]);
    requireValue(offer.canonical_utf8 === wire && offer.challenge_id === sha(wire));
    return {wire, ticket};
  }
  async challenge(token) {
    requireValue(hex64(token), 'invalid_invitation');
    const offer = await this.#request('/registration/challenge', {body: {token, public_key: this.publicKey}});
    const {ticket} = this.#offer(token, offer); this.#ticketId = ticket.id; return offer;
  }
  #receipt(receipt, project, expectedTerms = null, expectedTicketId = this.#ticketId) {
    requireValue(exact(receipt, ['ticket_id', 'project_id', 'public_key', 'grant_id', 'enrolled_at_ms', 'expires_at_ms', 'attempt_units', 'permissions']));
    requireValue(hex64(receipt.ticket_id) && (!expectedTicketId || receipt.ticket_id === expectedTicketId)
      && receipt.project_id === project && receipt.public_key === this.publicKey
      && project === 'p_' + receipt.ticket_id.slice(0, 60) && receipt.grant_id === 'g_' + receipt.ticket_id.slice(0, 60)
      && integer(receipt.enrolled_at_ms) && receipt.enrolled_at_ms <= this.#now()
      && integer(receipt.expires_at_ms) && receipt.expires_at_ms > this.#now()
      && receipt.expires_at_ms > receipt.enrolled_at_ms && integer(receipt.attempt_units)
      && receipt.attempt_units >= 5 && receipt.attempt_units <= 1000000);
    const actual = terms({attempt_units: receipt.attempt_units,
      identity_ms: receipt.expires_at_ms - receipt.enrolled_at_ms, permissions: receipt.permissions});
    if (expectedTerms) requireValue(same(actual, expectedTerms), 'unexpected_terms');
    this.#ticketId = receipt.ticket_id; this.#project = project; return receipt;
  }
  async complete(token, offer, expectedTerms) {
    const {wire, ticket} = this.#offer(token, offer), approved = terms(expectedTerms);
    requireValue(same(ticket.terms, approved), 'unexpected_terms');
    // Retain the complete signed identity even if the completion response is lost.
    this.#ticketId = ticket.id;
    const receipt = await this.#request('/registration/complete', {body: {token,
      challenge_id: offer.challenge_id, signature: sign(null, Buffer.from(wire), this.#key).toString('hex')}});
    return this.#receipt(receipt, ticket.project_id, approved, ticket.id);
  }
  async recover(project) {
    requireValue(identifier(project) && (!this.#project || project === this.#project)
      && (!this.#ticketId || project === 'p_' + this.#ticketId.slice(0, 60)), 'invalid_project');
    const at = this.#now(), nonce = this.#random();
    const wire = 'RunLater invitation recovery v1\n' + JSON.stringify([1, ORIGIN, project, this.publicKey, nonce, at, at + 60000]);
    const receipt = await this.#request('/registration/recover', {body: {project_id: project,
      public_key: this.publicKey, nonce, issued_at_ms: at, expires_at_ms: at + 60000,
      signature: sign(null, Buffer.from(wire), this.#key).toString('hex')}});
    return this.#receipt(receipt, project);
  }
  async createDestination(id, revision, url, idempotencyKey) {
    const body = {...endpointInput(id, revision), url: endpointURL(url)};
    const endpoint = await this.#request('/v1/destinations/create', {body, idempotencyKey, signed: true});
    requireValue(endpoint.endpoint_id === id && endpoint.version === revision && endpoint.url === url
      && ['pending', 'verified', 'revoked'].includes(endpoint.status)); return endpoint;
  }
  async prepareDestination(endpoint, idempotencyKey) {
    const body = endpointInput(endpoint.endpoint_id, endpoint.version), url = endpointURL(endpoint.url);
    const proof = await this.#request('/v1/destinations/prepare', {body, idempotencyKey, signed: true});
    requireValue(exact(proof, ['id', 'response', 'expires_at_ms']) && hex64(proof.id)
      && typeof proof.response === 'string' && Buffer.byteLength(proof.response) <= 1024
      && proof.response.startsWith('RunLater destination proof v1\n'));
    let tuple; try { tuple = JSON.parse(proof.response.slice('RunLater destination proof v1\n'.length)); }
    catch { throw new InvitationClientError('invalid_context'); }
    const now = this.#now();
    requireValue(Array.isArray(tuple) && tuple.length === 8 && same(tuple.slice(0, 5),
      [1, this.#project, body.endpoint_id, body.version, url]) && Number.isInteger(tuple[5])
      && tuple[5] >= 1 && tuple[5] <= 3 && integer(tuple[6]) && tuple[6] === proof.expires_at_ms
      && tuple[6] > now && tuple[6] - now <= 60000 && hex64(tuple[7]) && sha(proof.response) === proof.id);
    return proof; // Owner-only output. Never automatically echoed, uploaded or logged.
  }
  async verifyDestination(id, revision, idempotencyKey) {
    const result = await this.#request('/v1/destinations/verify', {body: endpointInput(id, revision), idempotencyKey, signed: true});
    requireValue(result.endpoint_id === id && result.version === revision && result.status === 'verified'); return result;
  }
  async revokeDestination(id, revision, idempotencyKey) {
    const result = await this.#request('/v1/destinations/revoke', {body: endpointInput(id, revision), idempotencyKey, signed: true});
    requireValue(result.revoked === true); return result;
  }
  enqueue(input, idempotencyKey) {
    requireValue(exact(input, ['endpoint_id', 'body', 'operation_key', 'run_at_ms']) && identifier(input.endpoint_id)
      && typeof input.body === 'string' && Buffer.byteLength(input.body) <= 1024
      && key(input.operation_key) && integer(input.run_at_ms), 'invalid_task');
    return this.#request('/v1/tasks', {body: {destination: 'registered:' + input.endpoint_id, body: input.body,
      operation_key: input.operation_key, run_at_ms: input.run_at_ms}, idempotencyKey, signed: true});
  }
  task(id) { return this.#request('/v1/tasks/' + taskId(id), {method: 'GET', signed: true}); }
  cancel(id) { return this.#request('/v1/tasks/' + taskId(id) + '/cancel', {body: {}, signed: true}); }
  redrive(id, idempotencyKey) { return this.#request('/v1/tasks/' + taskId(id) + '/redrive', {body: {}, idempotencyKey, signed: true}); }
}
