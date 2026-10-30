// LOCAL TEST HELPER ONLY. Real loopback TLS/HTTP with disposable CA/key material.
// The synthetic public pin -> loopback rewrite is NOT provider/network-isolation proof.
// Never import this helper from a Worker, native service entrypoint or deployment bundle.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import https from 'node:https';
import tls from 'node:tls';
import {createNativeEgress} from '../egress/index.mjs';
import {createNativeTransport} from '../egress/native-transport.mjs';
import {createIngress} from '../egress/controller/listener.mjs';
export async function createOrdinaryHttpsFixture({revision = 'c'.repeat(64)} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-general-http-fixture-')); fs.chmodSync(directory, 0o700);
  const keyFile = path.join(directory, 'key.pem'), certFile = path.join(directory, 'cert.pem');
  const hostname = 'customer.example.com', selectedAddress = '1.1.1.1';
  let server, ingress, connections = 0, dnsQueries = 0, closed = false;
  const requests = [], failures = [];
  try {
    const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile,
      '-out', certFile, '-days', '1', '-subj', '/CN=' + hostname, '-addext', 'subjectAltName=DNS:' + hostname], {stdio: 'ignore'});
    assert.equal(generated.status, 0); fs.chmodSync(keyFile, 0o600); const ca = fs.readFileSync(certFile);
    server = https.createServer({key: fs.readFileSync(keyFile), cert: ca, maxHeaderSize: 8192, requestTimeout: 5000}, (request, response) => {
      if (requests.length >= 40) {failures.push('fixture_request_bound'); request.destroy(); return;}
      const chunks = []; let size = 0;
      request.on('data', chunk => {if ((size += chunk.length) > 1024) {failures.push('fixture_body_bound'); request.destroy();} else chunks.push(chunk);});
      request.on('end', () => {
        try {
          assert.equal(request.method, 'POST'); assert.equal(request.headers.host, hostname);
          assert.equal(request.headers['content-type'], 'application/json');
          assert.equal(request.headers.authorization, undefined); assert.equal(request.headers.cookie, undefined);
          assert.equal(request.headers['x-api-key'], undefined);
          assert.equal(Object.keys(request.headers).some(name => name.startsWith('runlater-')), false, 'ordinary endpoint unexpectedly required RunLater proof/HMAC');
          assert.match(request.headers['idempotency-key'], /^[A-Za-z0-9_-]{1,128}$/);
          const body = Buffer.concat(chunks).toString('utf8'); JSON.parse(body);
          requests.push({path: request.url, method: request.method, operation: request.headers['idempotency-key'], body});
          const route = new URL(request.url, 'https://' + hostname).pathname;
          if (route === '/drop') {request.socket.destroy(); return;}
          if (route === '/redirect') {response.writeHead(302, {Location: 'https://forbidden.example/follow'}); response.end('PRIVATE_RESPONSE_SENTINEL'); return;}
          if (route === '/failure') {response.writeHead(500); response.end('PRIVATE_RESPONSE_SENTINEL'); return;}
          response.writeHead(200, {'Content-Type': 'application/json', 'X-Private-Fixture': 'PRIVATE_HEADER_SENTINEL'});
          response.end('{"private_result":"PRIVATE_RESPONSE_SENTINEL"}');
        } catch {failures.push('ordinary_http_contract'); request.destroy();}
      });
    });
    server.on('tlsClientError', () => {});
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port;
    const transport = createNativeTransport({connect: options => {
      assert.ok(++connections <= 50, 'fixture_connection_bound'); assert.equal(options.host, selectedAddress);
      assert.equal(options.port, 443); assert.equal(options.servername, hostname); assert.equal(options.rejectUnauthorized, true);
      // Test-only network translation. Original hostname/SNI/trust-chain checks still run in native TLS.
      const socket = tls.connect({...options, host: '127.0.0.1', port, ca});
      Object.defineProperty(socket, 'remoteAddress', {get: () => selectedAddress});
      Object.defineProperty(socket, 'remotePort', {get: () => 443}); return socket;
    }});
    const resolverFactory = () => ({
      async resolveCname(name) {assert.equal(name, hostname); assert.ok(++dnsQueries <= 150); return [];},
      async resolve4(name) {assert.equal(name, hostname); assert.ok(++dnsQueries <= 150); return [selectedAddress];},
      async resolve6(name) {assert.equal(name, hostname); assert.ok(++dnsQueries <= 150); return [];}, cancel() {},
    });
    const adapter = createNativeEgress({enabled: true, transport, resolverFactory});
    ingress = createIngress({adapter, enabled: true, revision});
    await new Promise(resolve => ingress.listen(0, '127.0.0.1', resolve)); const ingressOrigin = 'http://127.0.0.1:' + ingress.address().port;
    return {url: pathname => 'https://' + hostname + pathname, requests, failures,
      // This is only the private native transport hop. It does not fabricate API/controller readiness or admission.
      async nativeRequest(route, init = {}) {
        assert.ok(['/ready', '/dispatch'].includes(route));
        return fetch(ingressOrigin + route, {...init, redirect: 'manual'});
      },
      report() {return {ordinary_https_requests: requests.length, native_tls_connections: connections,
        synthetic_public_ip_mapping: true, provider_network_proof: false, external_calls: 0};},
      async close() {
        if (closed) return; closed = true;
        for (const item of [ingress, server]) if (item) await new Promise(resolve => {item.closeAllConnections(); item.close(resolve);});
        fs.rmSync(directory, {recursive: true});
      }};
  } catch (error) {
    for (const item of [ingress, server]) if (item?.listening) await new Promise(resolve => {item.closeAllConnections(); item.close(resolve);});
    fs.rmSync(directory, {recursive: true}); throw error;
  }
}
