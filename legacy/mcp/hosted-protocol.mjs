// Runtime-neutral hosted MCP transport. Authorization is rechecked by the OAuth
// boundary before every call here; a session ID is never an access credential.
import {createHash} from 'node:crypto';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {WebStandardStreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import {CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema,
  JSONRPCMessageSchema, McpError, ErrorCode} from '@modelcontextprotocol/sdk/types.js';
import {TOOLS, toolHandler} from './tools.mjs';
import {TRIAL_TOOLS, RECEIVER_PAIRING_TOOL, trialToolHandler} from './trial-tools.mjs';
import {canonicalTrialDescriptor, trialProjectId} from './trial-client.mjs';
import {MCP_SCOPES, TRIAL_SCOPES} from './oauth-consent.mjs';
import {HTTP_SCHEDULE_TOOL, httpToolHandler} from './http-tools.mjs';

export const MCP_ORIGIN = 'https://mcp.runlater.io';
export const HOSTED_SERVICE = Object.freeze({service: 'RunLater', intended_endpoint: MCP_ORIGIN + '/sse',
  streamable_http_endpoint: MCP_ORIGIN + '/mcp', hosted_verification: 'not_performed_by_this_source',
  transports: {sse: 'legacy_HTTP_SSE', mcp: 'stateless_Streamable_HTTP'}, supported_profile: 'public_free_beta',
  authentication: 'OAuth 2.1 with locally owner-signed scoped delegation; owner private keys never enter the gateway.',
  authorization: 'Every request is token-checked; the API independently verifies delegation, project, scopes, expiry, revocation and finite budgets.',
  omissions: ['list', 'redrive', 'registration', 'destination_management', 'payments', 'automatic_retries'],
  guarantees: 'Admission is not delivery. Cancellation cannot undo in-flight effects. No SLA, exactly-once, ordering or exact-time guarantee.'});
const resources = [{uri: 'runlater://service', name: 'RunLater capabilities and limits', mimeType: 'application/json'},
  {uri: 'runlater://setup', name: 'MCP setup and publication status', mimeType: 'text/markdown'}];
const encoder = new TextEncoder();
const json = (status, error) => Response.json({error}, {status, headers: {'Cache-Control': 'no-store'}});
const trialPrincipal = p => p?.kind === 'trial';
const principalProject = p => trialPrincipal(p) ? trialProjectId(p.trial.descriptor) : p.delegation.project_id;
const principalId = p => trialPrincipal(p) ? p.trial.descriptor.bootstrap_id : p.delegation.delegation_id;
function validPrincipal(p) {
  if (!p || !/^[a-f0-9]{64}$/.test(p.tokenHash) || !Array.isArray(p.scopes) || !p.scopes.length
    || p.scopes.some(scope => !(trialPrincipal(p) ? TRIAL_SCOPES : MCP_SCOPES).includes(scope)) || !Number.isSafeInteger(p.expiresAt)) return false;
  if (!trialPrincipal(p)) return p.kind === undefined && /^p_[a-f0-9]{60}$/.test(p.delegation?.project_id)
    && typeof p.delegation.delegation_id === 'string';
  try {const d = canonicalTrialDescriptor(p.trial?.descriptor);
    return /^[a-f0-9]{64}$/.test(p.trial.capability) && p.scopes.every(scope => d.permissions.includes(scope)) && p.expiresAt <= d.expires_at_ms;
  } catch {return false;}
}
const principalBinding = p => createHash('sha256').update(JSON.stringify([trialPrincipal(p) ? p.trial.descriptor : p.delegation,
  [...p.scopes].sort(), p.expiresAt])).digest('hex');
const serviceFor = p => trialPrincipal(p) ? {...HOSTED_SERVICE,
  authentication: 'Standard OAuth anonymous trial; no mandatory human account or owner-key UI. Trial authority is token-bound encrypted gateway storage, not owner-local asymmetric custody.',
  authorization: 'Explicit provision_trial allocates once; connect, discovery and status do not. The API independently checks dedicated capability, gateway signature, fixed expiry, revocation and shared finite budgets.',
  onboarding: p.scopes.includes('http_schedule') ? 'Connected trial with explicit general HTTP authority. No special receiver is required; an independently reviewed authenticated secure transport must be available before task admission. Source presence or provisioning is not activation.' : 'Connected; receiver setup required until trial_status confirms readiness. Pairing requires separate explicit scope, operator activation, and a privately configured receiver runtime. No automatic infrastructure or recovery is provided; HTTP delivery does not imply an agent conversation wakes.',
  omissions: [...HOSTED_SERVICE.omissions.filter(value => value !== 'registration'), 'automatic_receiver_deployment', 'automatic_recovery', 'generic_agent_wakeup']} : HOSTED_SERVICE;
const safeMessage = message => message.error ? {...message, error: {code: message.error.code, message: 'Invalid or unsupported MCP request'}} : message;

async function readMessage(request) {
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || '')) throw 415;
  const reader = request.body?.getReader();
  if (!reader) throw 400;
  let timer, size = 0, count = 0; const parts = [];
  const timeout = new Promise((_, reject) => {timer = setTimeout(() => {void reader.cancel().catch(() => {}); reject(408);}, 5000);});
  try {
    const value = await Promise.race([timeout, (async () => {
      for (;;) {const {done, value} = await reader.read(); if (done) break;
        if ((size += value.byteLength) > 8192 || ++count > 32) throw 413; parts.push(value);}
      const bytes = new Uint8Array(size); let offset = 0;
      for (const part of parts) {bytes.set(part, offset); offset += part.byteLength;}
      try {return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));} catch {throw 400;}
    })()]);
    if (Array.isArray(value) || !JSONRPCMessageSchema.safeParse(value).success) throw 400;
    return value;
  } finally {clearTimeout(timer); void reader.cancel().catch(() => {});}
}

class LegacySseTransport {
  constructor({sessionId, onClosed, lifetimeMs}) {
    this.sessionId = sessionId; this.onClosed = onClosed; this.closed = false; this.pending = new Map();
    this.stream = new ReadableStream({start: controller => {this.controller = controller;}, cancel: () => this.close()}, {highWaterMark: 65536, size: chunk => chunk.byteLength});
    this.lifetime = setTimeout(() => {void this.close();}, lifetimeMs); this.lifetime.unref?.();
    this.heartbeat = setInterval(() => this.write(': keepalive\n\n'), 15000); this.heartbeat.unref?.();
  }
  write(text) {
    if (this.closed) return;
    // Byte-sized queue, not message count. Disconnect slow readers before growing it.
    const bytes = encoder.encode(text);
    if (this.controller.desiredSize === null || bytes.byteLength > this.controller.desiredSize) {void this.close(); return;}
    try {this.controller.enqueue(bytes);} catch {void this.close();}
  }
  async start() {this.write(`event: endpoint\ndata: /messages?sessionId=${this.sessionId}\n\n`);}
  async send(message) {
    this.write(`event: message\ndata: ${JSON.stringify(safeMessage(message))}\n\n`);
    if (!message.method && message.id !== undefined) this.pending.get(message.id)?.();
  }
  async receive(message) {
    if (message.id === undefined || !message.method) {this.onmessage?.(message); return;}
    if (this.pending.has(message.id) || this.pending.size >= 8) throw 400;
    let timer;
    try {
      await new Promise((resolve, reject) => {
        this.pending.set(message.id, resolve);
        timer = setTimeout(() => reject(408), 6500);
        this.onmessage?.(message);
      });
    } finally {clearTimeout(timer); this.pending.delete(message.id);}
  }
  async close() {
    if (this.closed) return; this.closed = true; clearTimeout(this.lifetime); clearInterval(this.heartbeat);
    try {this.controller.close();} catch { /* already cancelled */ }
    for (const resolve of this.pending.values()) resolve(); this.pending.clear();
    this.onClosed(); this.onclose?.();
  }
  response() {return new Response(this.stream, {headers: {'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store',
    'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff'}});}
}

function scopeChallenge(message, principal) {
  const required = message.method === 'tools/call' && {schedule_task: 'enqueue', schedule_http_request: 'http_schedule', task_status: 'read', cancel_task: 'cancel', pair_receiver: 'receiver_setup'}[message.params?.name];
  if (!required || principal.scopes.includes(required)) return null;
  return Response.json({error: 'insufficient_scope'}, {status: 403, headers: {'Cache-Control': 'no-store',
    'WWW-Authenticate': `Bearer error="insufficient_scope", resource_metadata="${MCP_ORIGIN}/.well-known/oauth-protected-resource", scope="${required}"`}});
}

export function createHostedProtocol({makeClient, setup, status, receiverPairingEnabled = false, generalHttpEnabled = false, clock = Date.now, maxSessions = 32, sessionMs = 900000} = {}) {
  if (typeof makeClient !== 'function' || typeof setup !== 'string') throw new Error('Invalid hosted protocol configuration');
  const sessions = new Map(); let active = 0, activeTrials = 0;
  function makeServer(principal) {
    const client = makeClient(principal), taskHandler = toolHandler({client, allowedScopes: principal.scopes, status});
    const lifecycle = trialPrincipal(principal) ? trialToolHandler({client, revokeTrial: principal.revokeTrial,
      markTrialProvisioned: principal.markTrialProvisioned, taskHandler, receiverPairingEnabled, allowedScopes: principal.scopes}) : taskHandler;
    const call = trialPrincipal(principal) ? httpToolHandler({client, allowedScopes: principal.scopes, enabled: generalHttpEnabled, next: lifecycle}) : lifecycle;
    const server = new Server({name: 'runlater', version: '0.2.0'}, {capabilities: {tools: {}, resources: {}}, instructions: HOSTED_SERVICE.guarantees,
      jsonSchemaValidator: {getValidator() {throw new Error('Dynamic schemas are not supported');}}});
    server.onerror = () => {};
    server.setRequestHandler(ListToolsRequestSchema, async () => ({tools: trialPrincipal(principal)
      ? [...TOOLS, ...TRIAL_TOOLS, ...(receiverPairingEnabled ? [RECEIVER_PAIRING_TOOL] : []), ...(generalHttpEnabled ? [HTTP_SCHEDULE_TOOL] : [])] : TOOLS}));
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({resources}));
    server.setRequestHandler(ReadResourceRequestSchema, async ({params}) => {
      const resource = resources.find(r => r.uri === params.uri);
      if (!resource) throw new McpError(ErrorCode.InvalidParams, 'Unknown resource');
      return {contents: [{...resource, text: resource.uri === 'runlater://service' ? JSON.stringify(serviceFor(principal)) : setup}]};
    });
    server.setRequestHandler(CallToolRequestSchema, async ({params}) => {
      if (params.task !== undefined) throw new McpError(ErrorCode.InvalidParams, 'Async tasks unavailable');
      if (clock() >= principal.expiresAt) throw new McpError(ErrorCode.InvalidRequest, 'Credentials expired');
      if (active >= 4 || (trialPrincipal(principal) && activeTrials >= 2)) return {isError: true, content: [{type: 'text', text: 'Server busy. No operation was attempted; do not change idempotency keys.'}]};
      active++; if (trialPrincipal(principal)) activeTrials++;
      try {return await call(params.name, params.arguments, true);} finally {active--; if (trialPrincipal(principal)) activeTrials--;}
    });
    return server;
  }
  async function handle(request, principal) {
    try {
      const url = new URL(request.url);
      if (url.origin !== MCP_ORIGIN || (request.headers.has('origin') && request.headers.get('origin') !== MCP_ORIGIN)) return json(403, 'origin_rejected');
      if (!validPrincipal(principal) || principal.expiresAt <= clock()) return json(401, 'credentials_rejected');
      if (url.pathname === '/sse' && request.method === 'GET' && !url.search) {
        const projectSessions = [...sessions.values()].filter(s => s.project === principalProject(principal)).length;
        if (sessions.size >= maxSessions || projectSessions >= (trialPrincipal(principal) ? 2 : 4)
          || (trialPrincipal(principal) && [...sessions.values()].filter(s => s.trial).length >= Math.min(8, maxSessions))) return json(429, 'session_capacity');
        const id = crypto.randomUUID(), server = makeServer(principal);
        const transport = new LegacySseTransport({sessionId: id, lifetimeMs: Math.min(sessionMs, principal.expiresAt - clock()),
          onClosed: () => sessions.delete(id)});
        sessions.set(id, {server, transport, tokenHash: principal.tokenHash, project: principalProject(principal), trial: trialPrincipal(principal),
          delegationId: principalId(principal), principalBinding: principalBinding(principal), messages: 0});
        try {await server.connect(transport);} catch {await transport.close(); throw 400;}
        return transport.response();
      }
      if (url.pathname === '/messages' && request.method === 'POST' && [...url.searchParams.keys()].join() === 'sessionId') {
        const session = sessions.get(url.searchParams.get('sessionId'));
        if (!session || session.tokenHash !== principal.tokenHash || session.project !== principalProject(principal)
          || session.delegationId !== principalId(principal) || session.principalBinding !== principalBinding(principal)) return json(403, 'session_not_authorized');
        if (++session.messages > 512) {await session.server.close(); return json(429, 'session_budget_exhausted');}
        const message = await readMessage(request);
        const insufficient = scopeChallenge(message, principal); if (insufficient) return insufficient;
        await session.transport.receive(message);
        return new Response(null, {status: 202, headers: {'Cache-Control': 'no-store'}});
      }
      if (url.pathname === '/mcp' && !url.search) {
        if (request.method !== 'POST') return new Response(null, {status: 405, headers: {Allow: 'POST', 'Cache-Control': 'no-store'}});
        const message = await readMessage(request);
        const insufficient = scopeChallenge(message, principal); if (insufficient) return insufficient;
        const server = makeServer(principal);
        const transport = new WebStandardStreamableHTTPServerTransport({sessionIdGenerator: undefined, enableJsonResponse: true,
          maxRequestBodySize: 8192, keepAliveMs: 0});
        const send = transport.send.bind(transport);
        transport.send = async (message, options) => send(safeMessage(message), options);
        const headers = new Headers();
        for (const name of ['accept', 'content-type', 'mcp-protocol-version']) if (request.headers.has(name)) headers.set(name, request.headers.get(name));
        const sanitized = new Request(MCP_ORIGIN + '/mcp', {method: 'POST', headers});
        try {await server.connect(transport); const response = await transport.handleRequest(sanitized, {parsedBody: message});
          const safeHeaders = new Headers(response.headers); safeHeaders.set('Cache-Control', 'no-store');
          return new Response(response.body, {status: response.status, headers: safeHeaders});
        } finally {await server.close();}
      }
      return json(404, 'not_found');
    } catch (code) {return json([400, 408, 413, 415].includes(code) ? code : 400, 'invalid_request');}
  }
  return {handle, async close() {await Promise.all([...sessions.values()].map(s => s.server.close()));}, get sessionCount() {return sessions.size;}};
}
