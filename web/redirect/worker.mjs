// Dedicated www.runlater.io canonical redirect; no API, secret or storage bindings.
export default { fetch(request) {
 const incoming = new URL(request.url);
 if (incoming.hostname !== 'www.runlater.io') return new Response('Unknown host', { status: 404 });
 incoming.protocol = 'https:'; incoming.hostname = 'runlater.io'; incoming.port = '';
 return new Response(null,{status:308,headers:{Location:incoming.toString(),'Cache-Control':'public, max-age=3600','Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff'}});
}};
