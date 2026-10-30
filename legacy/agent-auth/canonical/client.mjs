import {createHash} from 'node:crypto';
import {SignJWT,importJWK} from 'jose';
import {ORIGIN,BASE} from '../replacement/config.mjs';
export const executeURL=ORIGIN+BASE+'/capability/execute';
// @auth/agent 0.6.2's executeCapability omits request binding. Keep keys in
// SDK storage and use its public signJwt API without relaxing server policy.
export async function executeBound(client,{agentId,capability,args={}},{fetchImpl}={}){
 if(typeof fetchImpl!=='function')throw Error('explicit_transport_required');
 const body=JSON.stringify({capability,arguments:args});
 const {token}=await client.signJwt({agentId,capabilities:[capability],audience:executeURL,htm:'POST',htu:executeURL,
  ath:createHash('sha256').update(body).digest('base64url')});
 return fetchImpl(executeURL,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body,redirect:'manual'});
}
export async function revokeHostBound(storage,hostId,{fetchImpl}={}){
 if(typeof fetchImpl!=='function')throw Error('explicit_transport_required');
 const host=await storage.getHostIdentity();if(!host)throw Error('host_identity_required');
 const target=ORIGIN+BASE+'/host/revoke',body=JSON.stringify({host_id:hostId});
 // SDK 0.6.2 has no bound host-signing convenience API. Consume its explicit
 // Storage interface internally; users never copy, paste or expose a key.
 const token=await new SignJWT({htm:'POST',htu:target,ath:createHash('sha256').update(body).digest('base64url')})
  .setProtectedHeader({alg:'EdDSA',typ:'host+jwt'}).setIssuer(hostId).setSubject(hostId).setAudience(ORIGIN+BASE)
  .setIssuedAt().setExpirationTime('45s').setJti(crypto.randomUUID()).sign(await importJWK(host.keypair.privateKey,'EdDSA'));
 return fetchImpl(target,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body,redirect:'manual'});
}
