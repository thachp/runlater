import http from 'node:http';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {timingSafeEqual, createHash} from 'node:crypto';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {SSEServerTransport} from '@modelcontextprotocol/sdk/server/sse.js';
import {CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema, JSONRPCMessageSchema, McpError, ErrorCode} from '@modelcontextprotocol/sdk/types.js';
import {PublicBetaClientV1, readOwnerText, loadOwnerKey} from '../examples/public-beta-client.v1.mjs';
import {TOOLS, toolHandler} from './tools.mjs';

export const ENDPOINT = 'https://mcp.runlater.io/sse';
const SERVICE = {service: 'RunLater', intended_endpoint: ENDPOINT, hosted_verification: 'not_performed_by_this_source',
  transport: 'legacy_HTTP_SSE', API: 'https://api.runlater.io', supported_profile: 'public_free_beta',
  callbacks: 'ownership_verified_workers_dev_only', payments: false, local_fixtures: 'not_exposed_by_this_server',
  authorization: 'Dedicated single-project signing gateway; anonymous sessions are discovery-only. Every authenticated request uses an existing owner-configured token. API scopes, identity expiry, project isolation and finite budgets remain authoritative.',
  omissions: {list: 'The hosted signed task router has no list route.', redrive: 'Deliberately omitted: new funded execution and possibly repeated effects require separate explicit review.'},
  guarantees: 'No SLA, exactly-once, ordering or exact-time guarantee. Admission is not delivery. Cancellation cannot undo in-flight effects.'};
const setup = fs.readFileSync(new URL('../docs/MCP.md', import.meta.url), 'utf8');
const resources = [{uri: 'runlater://service', name: 'RunLater capabilities and limits', mimeType: 'application/json'},
  {uri: 'runlater://setup', name: 'MCP configuration and verification status', mimeType: 'text/markdown'}];
const digest = text => createHash('sha256').update(text).digest();
const validToken = value => typeof value === 'string' && /^[A-Za-z0-9_-]{32,256}$/.test(value);

export function loadConfig(file, fetchImpl = fetch) {
  if (!file) return {};
  try {
    const config = JSON.parse(readOwnerText(file));
    const fields = ['key_file', 'receipt_file', 'token_file', 'release_id', 'scopes'];
    if (!config || Array.isArray(config) || Object.keys(config).sort().join() !== fields.sort().join()
      || !Array.isArray(config.scopes) || config.scopes.some(scope => !['enqueue', 'read', 'cancel'].includes(scope))
      || new Set(config.scopes).size !== config.scopes.length) throw new Error();
    const token = readOwnerText(config.token_file, 512).trim();
    if (!validToken(token)) throw new Error();
    const client = new PublicBetaClientV1({privateKey: loadOwnerKey(config.key_file), receipt: JSON.parse(readOwnerText(config.receipt_file)), releaseId: config.release_id, fetchImpl});
    if (!client.project) throw new Error();
    return {token, client, allowedScopes: config.scopes};
  } catch {throw new Error('Invalid MCP configuration. Use owner-only existing key, receipt and access-token files with the reviewed release ID and scopes. No credentials were created.');}
}

export function createMcpHttpServer({token = null, client = null, allowedScopes = [], status, publicOrigin = 'http://127.0.0.1:8790', maxSessions = 32, sessionMs = 900000} = {}) {
  const origin = new URL(publicOrigin);
  if (origin.origin !== publicOrigin || (publicOrigin !== 'https://mcp.runlater.io' && !(origin.protocol === 'http:' && origin.hostname === '127.0.0.1'))
    || (token !== null && !validToken(token)) || (!!token !== !!client)) throw new Error('Invalid MCP server configuration');
  const sessions = new Map(), tokenHash = token && digest(token), call = toolHandler({client, allowedScopes, status});
  function authenticate(req) {
    const header = req.headers.authorization;
    if (header === undefined) return 'anonymous';
    if (!tokenHash || typeof header !== 'string' || !header.startsWith('Bearer ') || !validToken(header.slice(7))) return null;
    return timingSafeEqual(tokenHash, digest(header.slice(7))) ? 'owner' : null;
  }
  function reply(res, code, error) {res.writeHead(code, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}).end(JSON.stringify({error}));}
  const server = http.createServer({maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 10000}, async (req, res) => {
    try {
      // Never trust forwarding headers or an arbitrary Origin/Host. Proxy must preserve the configured Host.
      if (req.headers.host !== origin.host || (req.headers.origin && req.headers.origin !== publicOrigin)) return reply(res, 403, 'origin_or_host_rejected');
      const url = new URL(req.url, publicOrigin), principal = authenticate(req);
      if (principal === null) return reply(res, 401, 'credentials_rejected');
      if (req.method === 'GET' && url.pathname === '/sse' && !url.search) {
        if (sessions.size >= maxSessions) return reply(res, 429, 'session_capacity');
        res.setHeader('X-Accel-Buffering', 'no');
        const mcp = new Server({name: 'runlater', version: '0.1.0'}, {capabilities: {tools: {}, resources: {}}, instructions: SERVICE.guarantees});
        mcp.setRequestHandler(ListToolsRequestSchema, async () => ({tools: TOOLS}));
        mcp.setRequestHandler(CallToolRequestSchema, async request => {
          // This server does not advertise MCP async tasks. Reject task-augmented calls before any effect.
          if (request.params.task !== undefined) throw new McpError(ErrorCode.InvalidParams, 'Async tasks are unavailable');
          return call(request.params.name, request.params.arguments, principal === 'owner');
        });
        mcp.setRequestHandler(ListResourcesRequestSchema, async () => ({resources}));
        mcp.setRequestHandler(ReadResourceRequestSchema, async request => {
          const resource = resources.find(value => value.uri === request.params.uri);
          if (!resource) throw new McpError(ErrorCode.InvalidParams, 'Unknown resource');
          return {contents: [{...resource, text: resource.uri === 'runlater://service' ? JSON.stringify(SERVICE) : setup}]};
        });
        const transport = new SSEServerTransport('/messages', res);
        const originalSend = transport.send.bind(transport);
        transport.send = async message => {
          if (res.writableLength > 65536) {await mcp.close(); return;}
          // SDK validation errors can include caller-controlled values; never echo them.
          return originalSend(message.error ? {...message, error: {code: message.error.code, message: 'Invalid or unsupported MCP request'}} : message);
        };
        mcp.onerror = () => {}; // No protocol/request/payload logging.
        const lifetime = setTimeout(() => {void mcp.close();}, sessionMs);
        const heartbeat = setInterval(() => {if (res.writableLength > 65536) void mcp.close(); else res.write(': keepalive\n\n');}, 15000);
        lifetime.unref(); heartbeat.unref();
        sessions.set(transport.sessionId, {mcp, transport, principal, messages: 0});
        res.once('close', () => {clearTimeout(lifetime); clearInterval(heartbeat); sessions.delete(transport.sessionId);});
        await mcp.connect(transport); return;
      }
      if (req.method === 'POST' && url.pathname === '/messages' && [...url.searchParams.keys()].join() === 'sessionId') {
        const session = sessions.get(url.searchParams.get('sessionId'));
        // A session ID is routing metadata, never authorization; every POST rechecks the bearer.
        if (!session || session.principal !== principal) return reply(res, 403, 'session_not_authorized');
        if (++session.messages > 512) {await session.mcp.close(); return reply(res, 429, 'session_budget_exhausted');}
        if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) return reply(res, 415, 'json_required');
        let bytes = 0; const chunks = [];
        for await (const chunk of req) {if ((bytes += chunk.length) > 8192) return reply(res, 413, 'request_too_large'); chunks.push(chunk);}
        let message;
        try {message = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)));} catch {return reply(res, 400, 'invalid_message');}
        if (!JSONRPCMessageSchema.safeParse(message).success) return reply(res, 400, 'invalid_message');
        await session.transport.handlePostMessage(req, res, message); return;
      }
      return reply(res, 404, 'not_found');
    } catch {if (!res.headersSent) reply(res, 400, 'request_failed'); else res.end();}
  });
  return {server, async close() {await Promise.all([...sessions.values()].map(s => s.mcp.close())); await new Promise(resolve => server.close(resolve));}};
}

async function main() {
  const port = Number(process.env.RUNLATER_MCP_PORT || 8790);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid listen port');
  const app = createMcpHttpServer({...loadConfig(process.env.RUNLATER_MCP_CONFIG), publicOrigin: process.env.RUNLATER_MCP_ORIGIN || `http://127.0.0.1:${port}`});
  // Bind only loopback. Hosted publication needs a separately reviewed TLS reverse proxy.
  await new Promise((resolve, reject) => {app.server.once('error', reject); app.server.listen(port, '127.0.0.1', resolve);});
  console.error('RunLater MCP listening on loopback; no hosted deployment verified.');
  const stop = () => {void app.close();}; process.once('SIGINT', stop); process.once('SIGTERM', stop);
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main().catch(() => {
  console.error('RunLater MCP startup failed; check owner-only configuration and available loopback port. No credentials or payloads are logged.'); process.exitCode = 1;
});
