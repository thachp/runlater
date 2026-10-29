// Public, credential-free URL scheduling input. Secure egress is independently
// enforced by the API/adapter; syntax checks are NOT a DNS/rebinding defense.
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
const invalid = () => {throw new PublicBetaClientError('invalid_http_task');};
export function httpTaskInput(value, {expiresAt = Number.MAX_SAFE_INTEGER} = {}) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join() !== 'operation_key,payload,run_at_ms,url'
    || typeof value.url !== 'string' || Buffer.byteLength(value.url) > 2048
    || !/^[\x21-\x7e]+$/.test(value.url) || !Number.isSafeInteger(value.run_at_ms) || value.run_at_ms < 0
    || value.run_at_ms > expiresAt || typeof value.operation_key !== 'string'
    || !/^[A-Za-z0-9_-]{1,128}$/.test(value.operation_key)) invalid();
  try {
    const url = new URL(value.url);
    if (url.href !== value.url || url.protocol !== 'https:' || url.port || url.username || url.password || value.url.includes('#') || value.url.includes('\\')
      || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(url.hostname) || !url.hostname.includes('.')
      || url.hostname.length > 253 || /^\d+(?:\.\d+){3}$/.test(url.hostname)
      || ['localhost', 'local', 'internal', 'home', 'onion', 'arpa', 'invalid', 'test'].some(suffix => url.hostname === suffix || url.hostname.endsWith('.' + suffix))
      || /%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(value.url)
      || url.hostname.split('.').some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) invalid();
  } catch {invalid();}
  let nodes = 0;
  const visit = (x, depth = 0) => {
    if (++nodes > 512 || depth > 16) invalid();
    if (x === null || typeof x === 'string' || typeof x === 'boolean') return;
    if (typeof x === 'number' && Number.isFinite(x)) return;
    if (Array.isArray(x)) {for (const item of x) visit(item, depth + 1); return;}
    if (typeof x === 'object' && (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null)) {
      for (const [key, item] of Object.entries(x)) {if (key.length > 1024) invalid(); visit(item, depth + 1);} return;
    }
    invalid();
  };
  visit(value.payload);
  const payload = JSON.stringify(value.payload); if (Buffer.byteLength(payload) > 1024) invalid();
  return {url: value.url, payload: JSON.parse(payload), run_at_ms: value.run_at_ms, operation_key: value.operation_key};
}
