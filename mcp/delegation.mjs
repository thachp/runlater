// Owner-side consent proof. No credential creation, enrollment, persistence or network I/O.
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {PublicBetaClientError, PUBLIC_BETA_TERMS} from '../examples/public-beta-client.v1.mjs';
export const API_ORIGIN = 'https://api.runlater.io';
export const MCP_RESOURCE = 'https://mcp.runlater.io';
export const DELEGATION_MAX_MS = 3600000;
export const DELEGATION_PREFIX = 'RunLater MCP task delegation v1\n';
const fields = ['version','audience','resource','release_id','project_id','owner_public_key','gateway_public_key','delegation_id','permissions','issued_at_ms','expires_at_ms','signature'];
const receiptFields = ['ticket_id','project_id','public_key','grant_id','enrolled_at_ms','expires_at_ms','attempt_units','permissions'];
const hex = (v,n) => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const integer = n => Number.isSafeInteger(n) && n >= 0;
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === [...keys].sort().join();
const hash = s => createHash('sha256').update(s).digest('hex');
function requireValue(ok, code = 'invalid_delegation') {if (!ok) throw new PublicBetaClientError(code);}
export function delegationPublicKey(key) {
  try {const k = key?.type === 'private' ? key : createPrivateKey(key); requireValue(k.asymmetricKeyType === 'ed25519'); return createPublicKey(k).export({format:'der',type:'spki'}).subarray(-32).toString('hex');}
  catch {throw new PublicBetaClientError('ed25519_private_key_required');}
}
function publicObject(raw) {return createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(raw,'hex')]),format:'der',type:'spki'});}
export function delegationBytes(c) {
  return Buffer.from(DELEGATION_PREFIX + JSON.stringify([c.version,c.audience,c.resource,c.release_id,c.project_id,c.owner_public_key,c.gateway_public_key,c.delegation_id,c.permissions,c.issued_at_ms,c.expires_at_ms]));
}
function shape(c) {
  requireValue(exact(c, fields) && c.version === 1 && c.audience === API_ORIGIN && c.resource === MCP_RESOURCE
    && typeof c.release_id === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(c.release_id)
    && hex(c.owner_public_key,64) && hex(c.gateway_public_key,64) && hex(c.delegation_id,64) && hex(c.signature,128)
    && Array.isArray(c.permissions) && c.permissions.length > 0 && c.permissions.length <= 3
    && c.permissions.every(p => ['cancel','enqueue','read'].includes(p))
    && c.permissions.join() === [...new Set(c.permissions)].sort().join()
    && integer(c.issued_at_ms) && integer(c.expires_at_ms) && c.expires_at_ms > c.issued_at_ms
    && c.expires_at_ms - c.issued_at_ms <= DELEGATION_MAX_MS);
  const ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1',c.release_id,c.owner_public_key]));
  requireValue(c.project_id === 'p_' + ticket.slice(0,60));
  return ticket;
}
function validateReceipt(r,c,ticket,now) {
  requireValue(exact(r,receiptFields) && r.ticket_id === ticket && r.project_id === c.project_id
    && r.public_key === c.owner_public_key && r.grant_id === 'g_'+ticket.slice(0,60)
    && integer(r.enrolled_at_ms) && r.enrolled_at_ms <= c.issued_at_ms && r.enrolled_at_ms <= now
    && integer(r.expires_at_ms) && r.expires_at_ms - r.enrolled_at_ms === PUBLIC_BETA_TERMS.identity_ms
    && c.expires_at_ms <= r.expires_at_ms && r.expires_at_ms > now && r.attempt_units === 100
    && Array.isArray(r.permissions) && [...r.permissions].sort().join() === [...PUBLIC_BETA_TERMS.permissions].sort().join()
    && r.permissions.length === PUBLIC_BETA_TERMS.permissions.length, 'invalid_enrollment_receipt');
}
export function verifyDelegation(c, {gatewayPublicKey,releaseId,now=Date.now(),receipt} = {}) {
  const ticket = shape(c);
  requireValue(integer(now) && c.issued_at_ms <= now && now < c.expires_at_ms, 'identity_expired');
  requireValue(hex(gatewayPublicKey,64) && c.gateway_public_key === gatewayPublicKey && c.release_id === releaseId);
  if (receipt !== undefined) validateReceipt(receipt,c,ticket,now);
  let valid = false;
  try {valid = verify(null,delegationBytes(c),publicObject(c.owner_public_key),Buffer.from(c.signature,'hex'));} catch {}
  requireValue(valid);
  return structuredClone(c);
}
export function signDelegation({privateKey,receipt,releaseId,gatewayPublicKey,permissions,delegationId,issuedAtMs,expiresAtMs}) {
  const owner = delegationPublicKey(privateKey);
  const c = {version:1,audience:API_ORIGIN,resource:MCP_RESOURCE,release_id:releaseId,project_id:receipt?.project_id,
    owner_public_key:owner,gateway_public_key:gatewayPublicKey,delegation_id:delegationId,permissions:Array.isArray(permissions)?[...permissions]:permissions,
    issued_at_ms:issuedAtMs,expires_at_ms:expiresAtMs,signature:'0'.repeat(128)};
  const ticket = shape(c); validateReceipt(receipt,c,ticket,issuedAtMs);
  const key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
  c.signature = sign(null,delegationBytes(c),key).toString('hex');
  return verifyDelegation(c,{gatewayPublicKey,releaseId,now:issuedAtMs,receipt});
}
export function encodeDelegation(c) {shape(c); return Buffer.from(JSON.stringify(Object.fromEntries(fields.map(k=>[k,c[k]])))).toString('base64url');}
export function decodeDelegation(encoded) {
  requireValue(typeof encoded === 'string' && encoded.length <= 4096 && /^[A-Za-z0-9_-]+$/.test(encoded));
  try {
    const bytes=Buffer.from(encoded,'base64url'); requireValue(bytes.toString('base64url') === encoded && bytes.length <= 3072);
    const c=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); shape(c); requireValue(encodeDelegation(c)===encoded); return c;
  } catch {throw new PublicBetaClientError('invalid_delegation');}
}
