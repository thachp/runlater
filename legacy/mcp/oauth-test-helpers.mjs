// Disposable local test helper. `call` must never follow redirects or access real hosts.
import assert from 'node:assert/strict';
import {createHash, sign} from 'node:crypto';
import {oauthConsentBytes} from './oauth-consent.mjs';
export async function authorizeFixture(call, {privateKey, delegation, scope = delegation.permissions}) {
  const verifier = 'v'.repeat(64), challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({response_type: 'code', client_id: 'https://client.example.com/metadata',
    redirect_uri: 'https://client.example.com/callback', scope: scope.join(' '), state: 'fixed-owner-state',
    code_challenge: challenge, code_challenge_method: 'S256', resource: 'https://mcp.runlater.io'});
  const page = await call('/authorize?' + query);
  assert.equal(page.status, 200, await page.clone().text());
  const html = await page.text();
  const publicChallenge = JSON.parse(html.match(/<textarea readonly[^>]*>([\s\S]*?)<\/textarea>/)[1]
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code))));
  const approval = {delegation, consent_signature: sign(null, oauthConsentBytes(publicChallenge, delegation), privateKey).toString('hex')};
  const consent = await call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: 'https://mcp.runlater.io', Cookie: page.headers.get('set-cookie').split(';')[0]},
  body: new URLSearchParams({handle: publicChallenge.handle, decision: 'approve', approval: JSON.stringify(approval)}).toString()});
  assert.equal(consent.status, 302);
  const callback = new URL(consent.headers.get('location'));
  assert.equal(callback.origin, 'https://client.example.com');
  const response = await call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'authorization_code', client_id: 'https://client.example.com/metadata',
      redirect_uri: 'https://client.example.com/callback', code: callback.searchParams.get('code'), code_verifier: verifier,
      resource: 'https://mcp.runlater.io'}).toString()});
  assert.equal(response.status, 200);
  return response.json();
}
