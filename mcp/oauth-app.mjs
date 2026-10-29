import {MCP_RESOURCE, normalizedAuthRequest, ownerChallenge, verifyOwnerApproval} from './oauth-consent.mjs';
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
  try {
    if (request.method === 'GET') {
      const parsed = normalizedAuthRequest(await oauth.parseAuthRequest(request));
      const details = await oauth.describeConsent(parsed);
      const consent = await oauth.beginConsent(parsed);
      const challenge = ownerChallenge(parsed, consent.handle, config);
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize RunLater MCP</title>
<h1>Authorize RunLater MCP</h1><p>Client: <strong>${escape(details.clientName)}</strong></p>
<p>Client identifier: <code>${escape(parsed.clientId)}</code></p>
<p>${details.clientDomain ? `Published on ${escape(details.clientDomain)}.` : 'Client name is self-asserted, not a verified identity.'}</p>
<p>Redirect destination: <strong>${escape(parsed.redirectUri)}</strong></p>
${details.redirectIsLoopback ? '<p><strong>This grants access to an app on your computer. Continue only if you started this sign-in.</strong></p>' : ''}
<p>Permissions: <strong>${escape(parsed.scope.join(', '))}</strong>. Scheduling consumes your existing finite attempt budget; cancellation cannot undo an in-flight effect.</p>
<p>Your private key stays on your device. Copy the public challenge below to a file, review it with the RunLater owner authorization helper, then paste only its signed approval below. Never paste a private key. This page expires after ten minutes.</p>
<label>Public challenge<textarea readonly rows="18" cols="90">${escape(JSON.stringify(challenge, null, 2))}</textarea></label>
<form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(consent.handle)}">
<label>Signed approval JSON<textarea name="approval" rows="8" cols="90" maxlength="12000"></textarea></label>
<p><button name="decision" value="approve">Approve this client</button> <button name="decision" value="deny">Deny</button></p></form></html>`;
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
