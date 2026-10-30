// Shared boundary for both web Workers. No API/MCP bindings or outbound requests.
export const security = {
 'X-Content-Type-Options':'nosniff',
 'Referrer-Policy':'strict-origin-when-cross-origin',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()',
 'X-Frame-Options':'DENY',
 'Strict-Transport-Security':'max-age=31536000',
};
export const policy = nonce => `default-src 'none'; style-src 'self'; script-src 'self'${nonce ? ` 'nonce-${nonce}'` : ''}; img-src 'self'; font-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests`;
export function createWebHandler(role, next) {
 return {async fetch(request, env, ctx) {
  const url = new URL(request.url);
  const hosts = role === 'landing' ? ['runlater.io','www.runlater.io'] : ['docs.runlater.io'];
  if (!hosts.includes(url.hostname)) return new Response('Unknown host',{status:404,headers:security});
  if (url.hostname === 'www.runlater.io' || url.protocol !== 'https:') {
   url.protocol='https:';url.hostname=hosts[0];url.port='';
   return new Response(null,{status:308,headers:{...security,Location:url.toString(),'Cache-Control':'public, max-age=3600'}});
  }
  if(['/index.html','/index','/404.html','/404/'].includes(url.pathname)) {
   url.pathname=url.pathname.startsWith('/404')?'/404':'/';return new Response(null,{status:307,headers:{...security,Location:url.pathname+url.search}});
  }
  // Native assets preserve exact bytes/MIME; unknown paths continue into Next's 404.
  if(url.pathname !== '/') {
   const asset = await env.ASSETS.fetch(request);
   if(asset.status !== 404) return protect(asset);
  }
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(18))));
  const headers = new Headers(request.headers);
  headers.set('Content-Security-Policy',policy(nonce));
  headers.set('x-nonce',nonce);
  const response = await next.fetch(new Request(request,{headers}),env,ctx);
  // Next reserves /404 with status 404 even when explicitly routed.
  // Preserve the legacy directly addressable document's 200 status only here.
  return protect(url.pathname === '/404' && response.status === 404
   ? new Response(response.body,{status:200,headers:response.headers}) : response,nonce);
 }};
}
function protect(response, nonce) {
 const headers = new Headers(response.headers);
 for(const [key,value] of Object.entries(security)) headers.set(key,value);
 headers.set('Content-Security-Policy',policy(nonce));
 headers.set('Cache-Control',nonce ? 'private, no-store' : 'public, max-age=300');
 return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}
