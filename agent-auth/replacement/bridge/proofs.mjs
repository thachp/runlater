import {createHash,createPublicKey,verify} from 'node:crypto';
import {verifyDelegation} from '../../../mcp/delegation.mjs';
export const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
export const digest=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export const linkBytes=challenge=>Buffer.from('RunLater explicit Agent Auth project link v1\n'+JSON.stringify(canonical(challenge)));
export function verifySignature(key,signature,challenge){
 if(typeof signature!=='string'||!/^[a-f0-9]{128}$/.test(signature))throw Error('link_signature_rejected');
 const publicKey=createPublicKey({key,format:'jwk'});
 if(publicKey.asymmetricKeyType!=='ed25519'||!verify(null,linkBytes(challenge),publicKey,Buffer.from(signature,'hex')))throw Error('link_signature_rejected');
}
// This verifies owner key control using the current delegation verifier. It does
// not assert source-family activity or authorize linking: the old controller must
// separately check its authoritative family state and API validateDelegation().
export function verifyOwnerLinkControl({delegation,receipt,owner_signature},challenge,{gatewayPublicKey,releaseId,now=Date.now()}){
 if(!receipt)throw Error('enrollment_receipt_required');
 if(challenge.version!==1||challenge.origin!=='https://mcp.runlater.io'||!Number.isSafeInteger(challenge.issued_at_ms)||!Number.isSafeInteger(challenge.expires_at_ms)||challenge.issued_at_ms>now||challenge.expires_at_ms<=now||challenge.expires_at_ms-challenge.issued_at_ms>300000)throw Error('link_challenge_expired');
 const existing=verifyDelegation(delegation,{gatewayPublicKey,releaseId,receipt,now});
 if(challenge.project_id!==existing.project_id||challenge.release_id!==existing.release_id||challenge.source_kind!=='owner'||challenge.permissions.some(p=>!existing.permissions.includes(p))||challenge.expires_at_ms>existing.expires_at_ms)throw Error('owner_link_scope_rejected');
 const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(existing.owner_public_key,'hex')]),format:'der',type:'spki'}).export({format:'jwk'});
 verifySignature(key,owner_signature,challenge);
 return {project_id:existing.project_id,permissions:[...existing.permissions],expires_at_ms:existing.expires_at_ms,delegation_sha256:digest(existing)};
}
