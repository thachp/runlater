// Public consent challenge / signature boundary. Never accepts an owner's private key.
import {createHash, createPublicKey, verify} from 'node:crypto';
import {delegationBytes, verifyDelegation} from './delegation.mjs';

export const MCP_RESOURCE = 'https://mcp.runlater.io';
export const MCP_SCOPES = Object.freeze(['cancel', 'enqueue', 'read']);
export const TRIAL_SCOPES = Object.freeze([...MCP_SCOPES, 'http_schedule', 'receiver_setup'].sort());
const hash = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object'
  && Object.keys(value).sort().join() === [...keys].sort().join();
function requireValue(value) {if (!value) throw new Error('invalid_owner_consent');}
export function normalizedAuthRequest(request, {receiverPairingEnabled = false, generalHttpEnabled = false} = {}) {
  const scopes = [...MCP_SCOPES, ...(receiverPairingEnabled ? ['receiver_setup'] : []), ...(generalHttpEnabled ? ['http_schedule'] : [])];
  requireValue(exact(request, ['responseType', 'clientId', 'redirectUri', 'scope', 'state', 'codeChallenge', 'codeChallengeMethod', 'resource', 'issuer'])
    && request.responseType === 'code' && request.resource === MCP_RESOURCE
    && request.issuer === MCP_RESOURCE && request.codeChallengeMethod === 'S256'
    && /^[A-Za-z0-9_-]{43}$/.test(request.codeChallenge || '')
    && typeof request.clientId === 'string' && request.clientId.length > 0 && request.clientId.length <= 2048
    && typeof request.redirectUri === 'string' && request.redirectUri.length <= 2048
    && typeof request.state === 'string' && request.state.length <= 2048
    && Array.isArray(request.scope) && request.scope.length > 0 && request.scope.length <= scopes.length
    && new Set(request.scope).size === request.scope.length
    && request.scope.every(scope => scopes.includes(scope)));
  const redirect = new URL(request.redirectUri);
  requireValue(redirect.href === request.redirectUri && !redirect.username && !redirect.password && !request.redirectUri.includes('#')
    && (redirect.protocol === 'https:' || (redirect.protocol === 'http:'
      && (redirect.hostname === 'localhost' || redirect.hostname === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(redirect.hostname)))));
  return {responseType: 'code', clientId: request.clientId, redirectUri: request.redirectUri,
    scope: [...request.scope].sort(), state: request.state, codeChallenge: request.codeChallenge,
    codeChallengeMethod: 'S256', resource: MCP_RESOURCE, issuer: MCP_RESOURCE};
}
export function ownerTaskAuthorizationUrl(request) {
  const r = normalizedAuthRequest(request, {receiverPairingEnabled: true, generalHttpEnabled: true});
  const scope = r.scope.filter(value => MCP_SCOPES.includes(value));
  if (!scope.length || scope.length === r.scope.length) return null;
  return MCP_RESOURCE + '/authorize?' + new URLSearchParams({response_type: r.responseType,
    client_id: r.clientId, redirect_uri: r.redirectUri, scope: scope.join(' '), state: r.state,
    code_challenge: r.codeChallenge, code_challenge_method: r.codeChallengeMethod, resource: r.resource});
}
export function ownerChallenge(request, handle, config) {
  requireValue(typeof handle === 'string' && /^[A-Za-z0-9_-]{16,256}$/.test(handle));
  return {version: 1, origin: MCP_RESOURCE, handle, request: normalizedAuthRequest(request),
    release_id: config.releaseId, gateway_public_key: config.gatewayPublicKey};
}
export function oauthConsentBytes(challenge, delegation) {
  requireValue(exact(challenge, ['version', 'origin', 'handle', 'request', 'release_id', 'gateway_public_key'])
    && challenge.version === 1 && challenge.origin === MCP_RESOURCE
    && /^[A-Za-z0-9_-]{16,256}$/.test(challenge.handle)
    && challenge.release_id === delegation.release_id && challenge.gateway_public_key === delegation.gateway_public_key);
  const request = normalizedAuthRequest(challenge.request);
  requireValue(JSON.stringify(request.scope) === JSON.stringify(delegation.permissions));
  const wire = [request.responseType, request.clientId, request.redirectUri, request.scope,
    request.state, request.codeChallenge, request.codeChallengeMethod, request.resource, request.issuer];
  return Buffer.from('RunLater MCP OAuth consent v1\n' + JSON.stringify([
    1, MCP_RESOURCE, challenge.handle, hash(JSON.stringify(wire)), hash(delegationBytes(delegation)),
  ]));
}
export function verifyOwnerApproval(approval, challenge, config) {
  requireValue(exact(approval, ['delegation', 'consent_signature'])
    && /^[a-f0-9]{128}$/.test(approval.consent_signature));
  verifyDelegation(approval.delegation, config);
  const key = createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(approval.delegation.owner_public_key, 'hex')]), type: 'spki', format: 'der'});
  requireValue(verify(null, oauthConsentBytes(challenge, approval.delegation), key,
    Buffer.from(approval.consent_signature, 'hex')));
  return approval.delegation;
}
