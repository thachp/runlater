import {createHash} from 'node:crypto';
// Pinned provider 1.2.4 contract: the refresh grant KV read occurs only after
// parseTokenEndpointRequest authenticates the effective client. Do not upgrade
// without the invalid-client and old-token replay workerd regression tests.
export async function strictRefreshFetch(provider,request,env,ctx,clientId) {
  const form=new URLSearchParams(await request.clone().text());
  if(form.get('grant_type')!=='refresh_token') return provider.fetch(request,env,ctx);
  const token=form.get('refresh_token');
  if(typeof token!=='string'||token.length>2048||token.split(':').length!==3) return provider.fetch(request,env,ctx);
  const [userId,grantId]=token.split(':'), key=`family:${userId}:${grantId}`, grantKey=`grant:${userId}:${grantId}`;
  const family=await env.OAUTH_KV.get(key,{type:'json'});
  if(!family) return provider.fetch(request,env,ctx);
  const hash=createHash('sha256').update(token).digest('hex');
  let authenticatedRead=false, currentAccepted=false;
  const wrapped={...env.OAUTH_KV,async get(name,options){
    const value=await env.OAUTH_KV.get(name,options);
    if(name!==grantKey)return value;
    authenticatedRead=true;
    if(family.clientId!==clientId||family.revoked||family.expiresAt<=Date.now())return null;
    if(family.consumed.includes(hash)||(value?.refreshTokenId===hash&&family.consumed.length>=192)){
      family.revoked=true;
      await env.OAUTH_KV.put(key,JSON.stringify(family),{expiration:Math.ceil(family.expiresAt/1000)});
      return null;
    }
    currentAccepted=value?.refreshTokenId===hash;return currentAccepted?value:null;
  },async put(name,value,options){
    if(currentAccepted&&name.startsWith(`token:${userId}:${grantId}:`)) {
      // Strict trial rotation keeps one live access token. Delete old token rows
      // in the same staged transaction BEFORE capacity-checking the replacement.
      const old=await env.OAUTH_KV.list({prefix:`token:${userId}:${grantId}:`,limit:32});
      for(const row of old.keys)if(row.name!==name)await env.OAUTH_KV.delete(row.name);
    }
    return env.OAUTH_KV.put(name,value,options);
  }};
  const response=await provider.fetch(request,{...env,OAUTH_KV:wrapped},ctx);
  if(response.ok&&authenticatedRead){
    const updated=await env.OAUTH_KV.get(grantKey,{type:'json'});
    delete updated.previousRefreshTokenId;delete updated.previousRefreshTokenWrappedKey;
    await env.OAUTH_KV.put(grantKey,JSON.stringify(updated),{expiration:Math.ceil(family.expiresAt/1000)});
    family.consumed.push(hash);
    await env.OAUTH_KV.put(key,JSON.stringify(family),{expiration:Math.ceil(family.expiresAt/1000)});
  }
  return response;
}
