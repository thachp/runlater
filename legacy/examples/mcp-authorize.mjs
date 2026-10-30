// Offline owner approval. Does not create keys, enroll, send HTTP, or schedule tasks.
import {randomBytes,sign} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {readOwnerText,loadOwnerKey,writeOwnerJson} from './invitation-client.v1.mjs';
import {signDelegation,DELEGATION_MAX_MS,MCP_RESOURCE} from '../mcp/delegation.mjs';
import {normalizedAuthRequest,oauthConsentBytes,verifyOwnerApproval} from '../mcp/oauth-consent.mjs';
const allowed=new Set(['--challenge','--key','--receipt','--out','--release-id','--gateway-public-key','--approve']);
function fail(){throw new Error('invalid_owner_approval_input');}
export function parseApprovalArgs(argv){
 const options={};
 for(let i=0;i<argv.length;i++){
  const name=argv[i];if(!allowed.has(name)||Object.hasOwn(options,name))fail();
  if(name==='--approve'){options[name]=true;continue;}
  const value=argv[++i];if(!value||value.startsWith('--'))fail();options[name]=value;
 }
 for(const name of ['--challenge','--release-id','--gateway-public-key'])if(!options[name])fail();
 if(!/^[A-Za-z0-9_-]{1,32}$/.test(options['--release-id'])||!/^[a-f0-9]{64}$/.test(options['--gateway-public-key']))fail();
 if(options['--approve']&&!['--key','--receipt','--out'].every(name=>options[name]))fail();
 return options;
}
export function reviewChallenge(challenge,{releaseId,gatewayPublicKey}){
 if(!challenge||challenge.version!==1||challenge.origin!==MCP_RESOURCE||challenge.release_id!==releaseId
   ||challenge.gateway_public_key!==gatewayPublicKey||!/^[A-Za-z0-9_-]{16,256}$/.test(challenge.handle??''))fail();
 if(Object.keys(challenge).sort().join()!==['version','origin','handle','request','release_id','gateway_public_key'].sort().join())fail();
 const request=normalizedAuthRequest(challenge.request);
 return {resource:MCP_RESOURCE,client_id:request.clientId,redirect_uri:request.redirectUri,permissions:request.scope,
  release_id:releaseId,gateway_public_key:gatewayPublicKey,maximum_delegation_ms:DELEGATION_MAX_MS,
  note:'Review this exact client, redirect and requested task authority. Approval does not schedule a task. Private keys stay on this device. Accepted tasks may execute after token/delegation expiry within existing project policy; expiry does not cancel them.'};
}
export function createOwnerApproval({challenge,privateKey,receipt,releaseId,gatewayPublicKey,now=Date.now(),delegationId=randomBytes(32).toString('hex')}){
 const review=reviewChallenge(challenge,{releaseId,gatewayPublicKey});
 const delegation=signDelegation({privateKey,receipt,releaseId,gatewayPublicKey,permissions:review.permissions,delegationId,
   issuedAtMs:now,expiresAtMs:Math.min(now+DELEGATION_MAX_MS,receipt?.expires_at_ms)});
 const approval={delegation,consent_signature:sign(null,oauthConsentBytes(challenge,delegation),privateKey).toString('hex')};
 verifyOwnerApproval(approval,challenge,{gatewayPublicKey,releaseId,now,receipt});return approval;
}
export function runOwnerApproval(argv,{print=message=>console.log(message)}={}){
 if(argv.length===1&&argv[0]==='--help'){
  print('Review: node examples/mcp-authorize.mjs --challenge FILE --release-id REVIEWED_ID --gateway-public-key REVIEWED_HEX_KEY');
  print('Approve after review: add --approve --key EXISTING_OWNER_KEY_FILE --receipt EXISTING_RECEIPT_FILE --out NEW_APPROVAL_FILE');
  print('Files must be owner-only regular files (0600), no symlinks. The output must not already exist. This helper never sends HTTP, creates credentials or schedules a task.');
  return;
 }
 const options=parseApprovalArgs(argv),challenge=JSON.parse(readOwnerText(options['--challenge'],16384));
 const pins={releaseId:options['--release-id'],gatewayPublicKey:options['--gateway-public-key']};
 const review=reviewChallenge(challenge,pins);print(JSON.stringify(review));
 if(!options['--approve']){print('Review only. To sign this exact request, rerun with --approve --key OWNER_KEY_FILE --receipt OWNER_RECEIPT_FILE --out NEW_APPROVAL_FILE.');return;}
 const privateKey=loadOwnerKey(options['--key']),receipt=JSON.parse(readOwnerText(options['--receipt']));
 const approval=createOwnerApproval({challenge,privateKey,receipt,...pins});
 writeOwnerJson(options['--out'],approval);
 print('Approval saved in the owner-only output file. Paste that JSON into the original authorization page before its ten-minute expiry. No key was uploaded or task created.');
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 try{runOwnerApproval(process.argv.slice(2));}catch{
  console.error('RunLater MCP approval failed. Check the exact reviewed release/gateway pins, challenge, owner-only existing key/receipt, identity expiry and new output path. No key or approval is printed.');process.exitCode=1;
 }
}
