// Public receiver intent only. This module never accepts private setup/callback keys.
import {createPublicKey, verify} from 'node:crypto';
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
const fields = ['version', 'release_id', 'project_id', 'url', 'receiver_public_key', 'pairing_id', 'issued_at_ms', 'expires_at_ms', 'signature'];
export function receiverManifest(value, {project, releaseId, now, trialExpiresAt}) {
  const reject = () => {throw new PublicBetaClientError('invalid_receiver_manifest');};
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join() !== [...fields].sort().join()
    || value.version !== 1 || value.project_id !== project || value.release_id !== releaseId
    || !/^[a-f0-9]{64}$/.test(value.receiver_public_key) || !/^[a-f0-9]{64}$/.test(value.pairing_id)
    || !/^[a-f0-9]{128}$/.test(value.signature) || !Number.isSafeInteger(value.issued_at_ms)
    || !Number.isSafeInteger(value.expires_at_ms) || value.issued_at_ms < 0 || value.issued_at_ms > now
    || value.expires_at_ms <= now || value.expires_at_ms > trialExpiresAt
    || value.expires_at_ms - value.issued_at_ms > 300000 || typeof value.url !== 'string') reject();
  try {
    const u = new URL(value.url);
    if (u.href !== value.url || u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash
      || u.pathname !== '/callback' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/.test(u.hostname)) reject();
    const key = createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(value.receiver_public_key, 'hex')]), type: 'spki', format: 'der'});
    const wire = 'RunLater receiver manifest v1\n' + JSON.stringify([1, value.release_id, value.project_id,
      value.url, value.receiver_public_key, value.pairing_id, value.issued_at_ms, value.expires_at_ms]);
    if (!verify(null, Buffer.from(wire), key, Buffer.from(value.signature, 'hex'))) reject();
  } catch {reject();}
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}
