// Both custom domains use this Worker. Run before EVERY asset lookup, including / and existing files.
// Only the native ASSETS binding is available; no API, secret, storage or network access.
export default {async fetch(request,env){
 const url=new URL(request.url);
 if(!['runlater.io','www.runlater.io'].includes(url.hostname))return new Response('Unknown host',{status:404});
 if(url.hostname==='www.runlater.io'||url.protocol!=='https:'){
  url.protocol='https:';url.hostname='runlater.io';url.port='';
  return new Response(null,{status:308,headers:{Location:url.toString(),'Cache-Control':'public, max-age=3600','Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff'}});
 }
 return env.ASSETS.fetch(request);
}};
