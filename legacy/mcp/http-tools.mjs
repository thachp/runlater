import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
import {taskResult} from './tools.mjs';
export const HTTP_SCHEDULE_TOOL = {name: 'schedule_http_request',
  description: 'Explicitly schedule a bounded HTTP POST with JSON to a customer-chosen public HTTPS URL. No RunLater receiver or completion notification is required. Requires http_schedule scope and an available independently reviewed secure egress adapter; source presence is not activation. Do not put endpoint credentials in this model-visible input: private endpoint auth/custom headers are unsupported. No redirects are followed. Use stable idempotency and operation keys; retries/delivery are finite and HTTP success is not business completion.',
  inputSchema: {type: 'object', additionalProperties: false, required: ['url', 'payload', 'run_at_ms', 'operation_key', 'idempotency_key'], properties: {
    url: {type: 'string', maxLength: 2048}, payload: {}, run_at_ms: {type: 'integer', minimum: 0},
    operation_key: {type: 'string', pattern: '^[A-Za-z0-9_-]{1,128}$'}, idempotency_key: {type: 'string', pattern: '^[A-Za-z0-9_-]{1,128}$'},
  }}, annotations: {readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true}};
const result = (value, isError = false) => ({content: [{type: 'text', text: JSON.stringify(value)}], structuredContent: value, isError});
const fail = (code, action, acceptance = 'not_attempted') => result({ok: false, error: {code, action}, task_acceptance: acceptance, automatic_retry: false}, true);
export function httpToolHandler({client, allowedScopes = [], enabled = false, next}) {
  return async (name, args = {}, authorized = false) => {
    if (name !== 'schedule_http_request') return next(name, args, authorized);
    if (!enabled) return fail('general_https_unavailable', 'General HTTPS scheduling is disabled. No task was attempted; a special receiver is not the missing product requirement.');
    if (!authorized || !client) return fail('credentials_required', 'Connect with explicitly consented http_schedule authority.');
    if (!allowedScopes.includes('http_schedule')) return fail('insufficient_scope', 'This token cannot schedule general HTTPS requests. Do not silently broaden it or create a replacement trial.');
    if (!args || Array.isArray(args) || Object.keys(args).sort().join() !== 'idempotency_key,operation_key,payload,run_at_ms,url')
      return fail('invalid_input', 'Use exactly URL, JSON payload, time and stable keys. Headers, auth, receiver and completion callback fields are unsupported.');
    try {
      const {idempotency_key, ...input} = args;
      const value = await client.scheduleHttp(input, idempotency_key);
      return result({ok: true, ...taskResult(value, undefined, allowedScopes.includes('read')), method: 'POST',
        receiver_required: false, completion_notification_configured: false});
    } catch (error) {
      if (error instanceof PublicBetaClientError) {
        if (['invalid_http_task', 'request_too_large', 'idempotency_key_required'].includes(error.code))
          return fail('invalid_input', 'Use a canonical public HTTPS URL, at most 1024 UTF-8 bytes of JSON payload, a time within trial expiry and unchanged stable keys. Private endpoint auth is not configured.');
        if (error.code === 'general_https_unavailable') return fail('general_https_unavailable', 'The API confirmed no task was admitted: the reviewed authenticated egress adapter is unavailable. Installing a RunLater receiver is not required for this general path.');
        if (error.code === 'insufficient_scope') return fail('insufficient_scope', 'No task was requested. Explicit http_schedule authority is required.');
      }
      return fail('result_uncertain', 'Task admission may be uncertain. Keep the identical URL, payload, time and keys; inspect this same project. Do not create a new identity or automatically retry with changed keys.', 'unknown');
    }
  };
}
