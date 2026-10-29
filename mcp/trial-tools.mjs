// Hosted-only lifecycle tools. No model-visible signing, callback or OAuth secrets.
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
const object = properties => ({type: 'object', additionalProperties: false, properties, required: Object.keys(properties)});
export const TRIAL_TOOLS = [
  {name: 'trial_status', description: 'Read this agent trial state without creating a project or consuming a project slot. Connected is not ready to schedule: a separately installed, ownership-verified receiver is required.', inputSchema: object({}), annotations: {readOnlyHint: true, openWorldHint: true}},
  {name: 'provision_trial', description: 'Explicitly allocate this agent’s one immutable free trial from the shared finite cohort. No account, payment or automatic renewal. This consumes a project slot which is not refunded. Retry only this same connected trial after an uncertain result; never reconnect to create a replacement. Receiver runtime setup is separate and not performed by this tool.', inputSchema: object({accept_finite_trial: {type: 'boolean', const: true}}), annotations: {readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true}},
  {name: 'revoke_trial', description: 'Permanently disable this connected trial’s credentials and project access. Does not cancel accepted tasks or undo callbacks; cancel known pending tasks first when possible. No recovery, quota refund or replacement project is provided.', inputSchema: object({confirm: {type: 'boolean', const: true}}), annotations: {readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true}},
];
const exact = (value, field) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join() === (field || '') && (!field || value[field] === true);
const result = (value, isError = false) => ({content: [{type: 'text', text: JSON.stringify(value)}], structuredContent: value, isError});
const failure = (code, action, state = 'not_attempted') => result({ok: false, error: {code, action},
  provisioning: state, automatic_retry: false}, true);
const receiverMessage = 'Connected; receiver setup required. Install and verify a callback receiver through a separately authorized runtime setup path. No callback secret is returned to the agent conversation. This source milestone does not implement that setup path.';
function safeStatus(value) {
  if (!value || !['unprovisioned', 'active'].includes(value.state) || !/^p_[a-f0-9]{60}$/.test(value.project_id)
    || !Number.isSafeInteger(value.expires_at_ms) || !Array.isArray(value.permissions)
    || value.permissions.some(scope => !['cancel', 'enqueue', 'read'].includes(scope))
    || value.receiver_ready !== false || value.attempt_units !== (value.state === 'active' ? 100 : 0)
    || value.client_operations_limit !== 1000) throw new Error('invalid_trial_status');
  return {state: value.state, project_id: value.project_id, expires_at_ms: value.expires_at_ms,
    permissions: [...value.permissions], receiver_ready: false, attempt_units: value.attempt_units,
    client_operations_limit: value.client_operations_limit, scheduling_ready: false, next_step: receiverMessage,
    recovery: 'Not configured. Lost OAuth credentials cannot be recovered using a public project ID or client name.'};
}
export function trialToolHandler({client, revokeTrial, markTrialProvisioned, taskHandler}) {
  return async (name, args = {}, authorized = false) => {
    const field = {trial_status: '', provision_trial: 'accept_finite_trial', revoke_trial: 'confirm'}[name];
    if (field === undefined) {
      if (name === 'schedule_task') return failure('receiver_setup_required', receiverMessage);
      return taskHandler(name, args, authorized);
    }
    if (!exact(args, field)) return failure('invalid_input', 'Use exactly the published schema and explicit confirmation.');
    if (!authorized || !client) return failure('credentials_required', 'Connect this agent using the RunLater OAuth flow.');
    try {
      if (name === 'revoke_trial') {
        if (typeof revokeTrial !== 'function') return failure('revocation_unavailable', 'No revocation was attempted.');
        const revoked = await revokeTrial();
        if (revoked?.revoked !== true || typeof revoked.api_revoked !== 'boolean' || typeof revoked.cleanup_pending !== 'boolean') throw new Error('revocation_unconfirmed');
        return result({ok: true, revoked: true, api_revoked: revoked.api_revoked, cleanup_pending: revoked.cleanup_pending,
          accepted_tasks_cancelled: false, quota_refunded: false});
      }
      const value = name === 'provision_trial' ? await client.provision() : await client.status();
      const safe = safeStatus(value);
      if (safe.state === 'active' && typeof markTrialProvisioned === 'function') await markTrialProvisioned();
      return result({ok: true, ...safe, provisioning: value.state === 'active' ? 'confirmed' : 'not_attempted'});
    } catch (error) {
      if (error instanceof PublicBetaClientError && error.code === 'http_error'
        && [400, 401, 403, 409, 429].includes(error.status)) return failure(error.status === 429 ? 'limits_exhausted' : 'trial_rejected',
        'The fixed trial request was rejected. Do not reconnect, change identity or create a replacement to bypass limits. Inspect this same trial.', 'not_confirmed');
      return failure(name === 'revoke_trial' ? 'revocation_pending_or_uncertain' : 'result_uncertain',
        name === 'provision_trial' ? 'Provisioning may have committed. Keep this connection and identity; only an explicitly requested repeat of provision_trial uses the same immutable project. Do not create a replacement.'
          : name === 'revoke_trial' ? 'Local access may already be disabled while API revocation is pending. Do not infer that accepted tasks were cancelled.'
            : 'No reliable status was received. No project allocation was requested.', name === 'provision_trial' ? 'unknown' : 'not_attempted');
    }
  };
}
