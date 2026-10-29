import {createHash, randomBytes} from 'node:crypto';
export const TRIAL_MS = 604800000;
const hash = s => createHash('sha256').update(s).digest('hex');
export function createTrialAuthority({releaseId, clientId, scopes, now = Date.now()}) {
  const bootstrap = randomBytes(32).toString('hex'), capability = randomBytes(32).toString('hex');
  const revocationSecret = randomBytes(32).toString('hex');
  const digest = (purpose, secret) => hash(`RunLater anonymous trial ${purpose} v1\n` + JSON.stringify([1, releaseId, bootstrap, secret]));
  const descriptor = {version: 1, release_id: releaseId, bootstrap_id: bootstrap,
    capability_hash: digest('capability', capability), revocation_hash: digest('revocation', revocationSecret),
    issued_at_ms: now, expires_at_ms: now + TRIAL_MS, permissions: [...scopes].sort()};
  const ticket = hash('RunLater anonymous trial project v1\n' + JSON.stringify([1, releaseId, bootstrap]));
  return {props: {kind: 'trial', descriptor, capability, clientId, projectId: 'p_' + ticket.slice(0,60)}, revocationSecret};
}
export function validateTrialAuthority(props, {releaseId, clientId, now = Date.now()}) {
  if (!props || Object.keys(props).sort().join() !== 'capability,clientId,descriptor,kind,projectId' || props.kind !== 'trial'
    || props.clientId !== clientId || !/^[a-f0-9]{64}$/.test(props.capability)) throw new Error('invalid_trial');
  const d = props.descriptor;
  if (!d || Object.keys(d).sort().join() !== 'bootstrap_id,capability_hash,expires_at_ms,issued_at_ms,permissions,release_id,revocation_hash,version'
    || d.version !== 1 || d.release_id !== releaseId || !/^[a-f0-9]{64}$/.test(d.bootstrap_id)
    || !/^[a-f0-9]{64}$/.test(d.revocation_hash) || !Number.isSafeInteger(d.issued_at_ms)
    || d.issued_at_ms > now || d.expires_at_ms !== d.issued_at_ms + TRIAL_MS || d.expires_at_ms <= now
    || !Array.isArray(d.permissions) || !d.permissions.length || d.permissions.some(s => !['cancel','enqueue','read'].includes(s))
    || JSON.stringify(d.permissions) !== JSON.stringify([...new Set(d.permissions)].sort())
    || d.capability_hash !== hash('RunLater anonymous trial capability v1\n' + JSON.stringify([1,d.release_id,d.bootstrap_id,props.capability]))) throw new Error('invalid_trial');
  const ticket = hash('RunLater anonymous trial project v1\n' + JSON.stringify([1,d.release_id,d.bootstrap_id]));
  if (props.projectId !== 'p_' + ticket.slice(0,60)) throw new Error('invalid_trial');
  return props;
}
