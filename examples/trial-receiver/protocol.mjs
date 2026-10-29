// Pure, bounded receiver-pairing validation. No fetch, configuration mutation or logging.
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {validatePolicy, verifyV2WithMaterial} from '../rotating-receiver.mjs';
export const API = 'https://api.runlater.io';
export const PULL = '/v1/mcp/receiver/pull', ACK = '/v1/mcp/receiver/ack';
export const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const signature = value => typeof value === 'string' && /^[a-f0-9]{128}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
export const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const check = value => {if (!value) throw Error('receiver_invalid');};
const pubKey = raw => createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw, 'hex')]), format: 'der', type: 'spki'});
export function manifestBytes(m) {
  return 'RunLater receiver manifest v1\n' + JSON.stringify([1, m.release_id, m.project_id, m.url,
    m.receiver_public_key, m.pairing_id, m.issued_at_ms, m.expires_at_ms]);
}
export function manifest(value) {
  check(exact(value, ['version', 'release_id', 'project_id', 'url', 'receiver_public_key', 'pairing_id', 'issued_at_ms', 'expires_at_ms', 'signature'])
    && value.version === 1 && typeof value.release_id === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(value.release_id)
    && typeof value.project_id === 'string' && /^p_[a-f0-9]{60}$/.test(value.project_id) && hex(value.receiver_public_key) && hex(value.pairing_id)
    && integer(value.issued_at_ms) && integer(value.expires_at_ms)
    && value.expires_at_ms > value.issued_at_ms && value.expires_at_ms - value.issued_at_ms <= 300000 && signature(value.signature));
  const url = new URL(value.url);
  check(url.href === value.url && url.protocol === 'https:' && !url.username && !url.password && !url.port
    && url.pathname === '/callback' && !url.search && !url.hash
    && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/.test(url.hostname));
  const m = {version: 1, release_id: value.release_id, project_id: value.project_id, url: value.url,
    receiver_public_key: value.receiver_public_key, pairing_id: value.pairing_id, issued_at_ms: value.issued_at_ms,
    expires_at_ms: value.expires_at_ms, signature: value.signature};
  check(verify(null, Buffer.from(manifestBytes(m)), pubKey(m.receiver_public_key), Buffer.from(m.signature, 'hex')));
  return m;
}
export function privateKey(value, m) {
  check(typeof value === 'string' && value.length <= 4096);
  const key = createPrivateKey(value); check(key.type === 'private' && key.asymmetricKeyType === 'ed25519');
  const pub = createPublicKey(key).export({format: 'der', type: 'spki'});
  check(pub.length === 44 && pub.subarray(12).toString('hex') === m.receiver_public_key); return key;
}
export function active(m, now) {check(integer(now) && now >= m.issued_at_ms && now < m.expires_at_ms);}
export function probeResponse(m, key, bytes, now) {
  active(m, now); check(bytes.length <= 2048);
  const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes), prefix = 'RunLater receiver probe v1\n';
  check(text.startsWith(prefix)); const t = JSON.parse(text.slice(prefix.length));
  check(Array.isArray(t) && t.length === 9 && hex(t[7]));
  const expected = prefix + JSON.stringify([1, m.release_id, m.project_id, m.url, m.receiver_public_key,
    m.pairing_id, sha(JSON.stringify(m)), t[7], m.expires_at_ms]);
  check(text === expected); return {signature: sign(null, bytes, key).toString('hex')};
}
export function signedRequest(m, key, path, body, now, nonce) {
  active(m, now); check([PULL, ACK].includes(path) && hex(nonce));
  const expires = Math.min(now + 60000, m.expires_at_ms), bytes = JSON.stringify(body);
  const wire = 'RunLater receiver setup request v1\n' + JSON.stringify([1, API, m.release_id, m.project_id,
    m.pairing_id, sha(JSON.stringify(m)), 'POST', path, sha(bytes), now, expires, nonce]);
  return {method: 'POST', redirect: 'manual', headers: {'Content-Type': 'application/json',
    'RunLater-Project-Id': m.project_id, 'RunLater-Public-Key': m.receiver_public_key, 'RunLater-Pairing-Id': m.pairing_id,
    'RunLater-Issued-At': String(now), 'RunLater-Expires-At': String(expires), 'RunLater-Nonce': nonce,
    'RunLater-Request-Signature': sign(null, Buffer.from(wire), key).toString('hex')}, body: bytes};
}
export function installation(response, m, now, {persisted = false} = {}) {
  if (!persisted) active(m, now); check(exact(response, ['installation', 'installation_sha256']) && hex(response.installation_sha256));
  const p = response.installation, mh = sha(JSON.stringify(m));
  check(exact(p, ['version', 'project_id', 'pairing_id', 'manifest_sha256', 'installation_id', 'expires_at_ms',
    'callback_url', 'callback_policy', 'callback_keys', 'destination_proof', 'endpoint_id', 'endpoint_version'])
    && p.version === 1 && p.project_id === m.project_id && p.pairing_id === m.pairing_id
    && p.manifest_sha256 === mh && p.installation_id === mh && p.expires_at_ms === m.expires_at_ms
    && p.callback_url === m.url && p.endpoint_id === 'receiver' && p.endpoint_version === 1
    && sha(JSON.stringify(p)) === response.installation_sha256);
  check(validatePolicy(p.callback_policy) && p.callback_policy.tenant === m.project_id
    && exact(p.callback_keys, ['beta_v1']) && hex(p.callback_keys.beta_v1)
    && !/^(..)(?:\1){31}$/.test(p.callback_keys.beta_v1)
    && Object.keys(p.callback_policy.keys).length === 1 && Object.hasOwn(p.callback_policy.keys, 'beta_v1')
    && p.callback_policy.keys.beta_v1.revoked_at_sec === null);
  const proof = p.destination_proof;
  check(exact(proof, ['id', 'response', 'expires_at_ms']) && hex(proof.id) && proof.expires_at_ms === m.expires_at_ms
    && typeof proof.response === 'string' && Buffer.byteLength(proof.response) <= 1024 && sha(proof.response) === proof.id);
  const prefix = 'RunLater destination proof v1\n'; check(proof.response.startsWith(prefix));
  const t = JSON.parse(proof.response.slice(prefix.length));
  check(Array.isArray(t) && t.length === 8 && t[0] === 1 && t[1] === m.project_id && t[2] === 'receiver'
    && t[3] === 1 && t[4] === m.url && Number.isInteger(t[5]) && t[5] >= 1 && t[5] <= 3
    && t[6] === m.expires_at_ms && hex(t[7]) && proof.response === prefix + JSON.stringify(t));
  return p;
}
export function destinationProof(p, bytes, now) {
  check(integer(now) && now < p.destination_proof.expires_at_ms);
  const expected = 'RunLater destination verification v1\n' + JSON.stringify([p.project_id, p.endpoint_id,
    p.endpoint_version, p.destination_proof.id, p.destination_proof.expires_at_ms]);
  check(Buffer.from(expected).equals(Buffer.from(bytes))); return p.destination_proof.response;
}
export function callbackValid(p, headers, body, now) {
  return verifyV2WithMaterial(p.callback_policy, headers, body, Math.floor(now / 1000),
    key => Object.hasOwn(p.callback_keys, key) ? Buffer.from(p.callback_keys[key], 'hex') : null);
}
