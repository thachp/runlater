import {createTrialAuthority} from './oauth-trial.mjs';
import {MCP_RESOURCE, MCP_SCOPES, normalizedAuthRequest, ownerChallenge, ownerTaskAuthorizationUrl, verifyOwnerApproval} from './oauth-consent.mjs';
const escape = value => String(value).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
export const privateHeaders = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"};
export function oauthFailure(status = 400) {
  return Response.json({error: status === 503 ? 'temporarily_unavailable' : 'invalid_request'}, {status, headers: privateHeaders});
}
export async function requireActiveDelegation(delegation, validateDelegation) {
  if (typeof validateDelegation !== 'function') throw new Error('delegation_validation_unavailable');
  const result = await validateDelegation(delegation);
  if (!result || Object.keys(result).sort().join() !== 'active,expires_at_ms,permissions,project_id'
    || result.active !== true || result.project_id !== delegation.project_id
    || !Number.isSafeInteger(result.expires_at_ms) || result.expires_at_ms <= Date.now()
    || result.expires_at_ms > delegation.expires_at_ms
    || JSON.stringify(result.permissions) !== JSON.stringify(delegation.permissions)) throw new Error('delegation_not_active');
  return result;
}
async function boundedForm(request) {
  if (!/^application\/x-www-form-urlencoded(?:;\s*charset=UTF-8)?$/i.test(request.headers.get('content-type') || '')) throw new Error();
  const reader = request.body?.getReader(); let bytes = 0; const chunks = [];
  if (reader) try {for (;;) {const {done, value} = await reader.read(); if (done) break;
    bytes += value.byteLength; if (bytes > 16384) {await reader.cancel(); throw new Error();} chunks.push(value);
  }} finally {reader.releaseLock();}
  const form = new URLSearchParams(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)));
  if ([...form.keys()].some((key, i, keys) => !['handle', 'decision', 'approval'].includes(key) || keys.indexOf(key) !== i)) throw new Error();
  return form;
}
export async function authorizeOwner(request, oauth, config) {
  if (new URL(request.url).origin !== MCP_RESOURCE || new URL(request.url).pathname !== '/authorize') return oauthFailure();
  // A browser opened the protocol endpoint without a client-started transaction.
  // Explain how to connect, without parsing metadata, creating consent or relaxing OAuth.
  const acceptsHtml = (request.headers.get('accept') || '').split(',').some(part => {
    const [type, ...parameters] = part.trim().split(';');
    return type.trim().toLowerCase() === 'text/html'
      && !parameters.some(value => /^q\s*=\s*0(?:\.0*)?$/i.test(value.trim()));
  });
  if (request.method === 'GET' && !new URL(request.url).search && acceptsHtml) {
    return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect RunLater from your agent app</title>
<h1>Start in your agent app</h1>
<p>This authorization page needs a connection request from a compatible OAuth MCP client. Opening this address alone cannot connect a project.</p>
<ol><li>Open your agent app’s MCP integration settings and add <code>https://mcp.runlater.io/mcp</code> (Streamable HTTP), or <code>https://mcp.runlater.io/sse</code> for legacy SSE.</li>
<li>Start the connection in that app. It supplies its client identity, return address and security checks.</li>
<li>Only on that client-started consent page, review the client, return destination and permissions before choosing <strong>Start free agent project</strong>.</li></ol>
<p>No RunLater account or private-key generation is needed for this trial path. Connecting does not allocate a project; provisioning requires a separate explicit request and finite capacity.</p>
<p><a href="https://docs.runlater.io/#connect">Read the Connect guide</a></p></html>`, {
      status: 400, headers: {...privateHeaders, 'Content-Type': 'text/html; charset=utf-8', Vary: 'Accept'},
    });
  }
  try {
    if (request.method === 'GET') {
      const parsed = normalizedAuthRequest(await oauth.parseAuthRequest(request), config);
      const details = await oauth.describeConsent(parsed);
      const consent = await oauth.beginConsent(parsed);
      const ownerEligible = parsed.scope.every(scope => MCP_SCOPES.includes(scope));
      const challenge = ownerEligible ? ownerChallenge(parsed, consent.handle, config) : null;
      const ownerLink = ownerEligible ? null : ownerTaskAuthorizationUrl(parsed);
      const deliveryNotice = parsed.scope.includes('http_schedule')
        ? 'General HTTPS delivery does not require a RunLater receiver, but the independently reviewed secure transport must be available. Connecting or provisioning does not establish transport readiness. Private endpoint authentication and custom headers are not configured by this flow.'
        : 'A verified beta receiver must be configured before registered tasks can deliver; this connection alone is not ready to send work.';
      const trialForm = config.trialEnabled ? `<h2>Start free agent project</h2><p>No account or sign-in. This client gets a seven-day credential with finite budget and no billing. Connecting creates no API project; the agent must explicitly provision its trial. ${deliveryNotice} Lost credentials cannot be recovered here. Refresh reuses the same trial and never resets its expiry or budget. Retrying a consumed refresh credential permanently revokes access.</p><form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(consent.handle)}"><button name="decision" value="trial">Start free agent project</button><button name="decision" value="deny">Deny</button></form>${ownerEligible ? '<details><summary>Link an existing project with your local owner key</summary>' : '<p>These additional permissions apply only to this newly consented agent trial. Existing owner-key grants do not silently acquire them.</p>'}` : '';
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize RunLater MCP</title>
<h1>Authorize RunLater MCP</h1><p>Client: <strong>${escape(details.clientName)}</strong></p>
<p>Client identifier: <code>${escape(parsed.clientId)}</code></p>
<p>${details.clientDomain ? `Published on ${escape(details.clientDomain)}.` : 'Client name is self-asserted, not a verified identity.'}</p>
<p>Redirect destination: <strong>${escape(parsed.redirectUri)}</strong></p>
${details.redirectIsLoopback ? '<p><strong>This grants access to an app on your computer. Continue only if you started this sign-in.</strong></p>' : ''}
<p>Permissions: <strong>${escape(parsed.scope.map(s=>({read:'view task status',enqueue:'schedule tasks to the registered beta receiver',http_schedule:'schedule bounded HTTP POST requests to customer-chosen public HTTPS URLs, when the secure transport is available',cancel:'cancel pending tasks',receiver_setup:'pair one fixed callback receiver and privately install its verification material'})[s]).join(', '))}</strong>. Scheduling consumes your existing finite attempt budget; cancellation cannot undo an in-flight effect.</p>
${trialForm}
${ownerLink ? `<p><a href="${escape(ownerLink)}">Connect existing project with task permissions only</a>. This starts a new consent screen without the additional trial-only permissions; it does not change an existing grant or create a project.</p>` : ''}
${ownerEligible ? `<p>Your private key stays on your device. Copy the public challenge below to a file, review it with the RunLater owner authorization helper, then paste only its signed approval below. Never paste a private key. This page expires after ten minutes.</p>
<label>Public challenge<textarea readonly rows="18" cols="90">${escape(JSON.stringify(challenge, null, 2))}</textarea></label>
<form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(consent.handle)}">
<label>Signed approval JSON<textarea name="approval" rows="8" cols="90" maxlength="12000"></textarea></label>
<p><button name="decision" value="approve">Approve this client</button> <button name="decision" value="deny">Deny</button></p></form>${config.trialEnabled ? '</details>' : ''}` : ''}</html>`;
      const headers = new Headers(consent.headers);
      for (const [key, value] of Object.entries(privateHeaders)) headers.set(key, value);
      headers.set('Content-Type', 'text/html; charset=utf-8');
      return new Response(html, {headers});
    }
    if (request.method !== 'POST' || request.headers.get('origin') !== MCP_RESOURCE) return oauthFailure();
    const form = await boundedForm(request), handle = form.get('handle');
    if (form.get('decision') === 'deny') {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, {status: 302, headers: denied.headers});
    }
    if (form.get('decision') === 'trial') {
      if (!config.trialEnabled || form.has('approval')) return oauthFailure();
      const approved = await oauth.approveConsent(request, handle);
      const parsed = normalizedAuthRequest(approved.request, config);
      const trial = createTrialAuthority({releaseId:config.releaseId,clientId:parsed.clientId,scopes:parsed.scope});
      const completed = await oauth.completeAuthorization({request:parsed,userId:trial.props.projectId,metadata:{authorityKind:'trial'},
        scope:parsed.scope,props:trial.props,revokeExistingGrants:false,trialRevocationSecret:trial.revocationSecret});
      const headers = new Headers(approved.headers);
      for (const [key,value] of Object.entries(privateHeaders)) headers.set(key,value);
      headers.set('Location',completed.redirectTo); return new Response(null,{status:302,headers});
    }
    if (form.get('decision') !== 'approve') return oauthFailure();
    // Library owns cookie binding and one-use transaction. Input cannot reconstruct a redirect.
    const approved = await oauth.approveConsent(request, handle);
    const parsed = normalizedAuthRequest(approved.request);
    const delegation = verifyOwnerApproval(JSON.parse(form.get('approval') || ''), ownerChallenge(parsed, handle, config), config);
    if (delegation.expires_at_ms - (config.now ?? Date.now()) < 60000) return oauthFailure();
    await requireActiveDelegation(delegation, config.validateDelegation);
    const completed = await oauth.completeAuthorization({request: parsed, userId: delegation.project_id,
      metadata: {}, scope: parsed.scope, props: {delegation}, revokeExistingGrants: true});
    const headers = new Headers(approved.headers);
    for (const [key, value] of Object.entries(privateHeaders)) headers.set(key, value);
    headers.set('Location', completed.redirectTo);
    return new Response(null, {status: 302, headers});
  } catch {return oauthFailure();} // Never echo client metadata, certificate, signature or library exceptions.
}
