// Planned www.runlater.io route only. No DNS or route is provisioned by this file.
export default { fetch(request) {
 const incoming = new URL(request.url);
 if (incoming.hostname !== 'www.runlater.io') return new Response('Unknown host', { status: 404 });
 incoming.protocol = 'https:'; incoming.hostname = 'runlater.io'; incoming.port = '';
 return Response.redirect(incoming.toString(), 308);
}};
