// Hosted-only lifecycle tools. No model-visible signing, callback or OAuth secrets.
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
import {TRIAL_SCOPES} from './oauth-consent.mjs';
const object = properties => ({type: 'object', additionalProperties: false, properties, required: Object.keys(properties)});
export const TRIAL_TOOLS = [
  {name: 'trial_status', description: 'Read this agent trial state without creating a project or consuming a project slot. Connected is not ready to schedule. Registered beta delivery needs a verified receiver; general URL delivery instead needs the separate secure egress transport and http_schedule authority.', inputSchema: object({}), annotations: {readOnlyHint: true, openWorldHint: true}},
  {name: 'provision_trial', description: 'Explicitly allocate this agent’s one immutable free trial from the shared finite cohort. No account, payment or automatic renewal. This consumes a project slot which is not refunded. Retry only this same connected trial after an uncertain result; never reconnect to create a replacement. Optional beta receiver setup is separate; general HTTPS delivery needs no special receiver. Neither infrastructure nor secure-transport activation is performed by this tool.', inputSchema: object({accept_finite_trial: {type: 'boolean', const: true}}), annotations: {readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true}},
  {name: 'revoke_trial', description: 'Permanently disable this connected trial’s credentials and project access. Does not cancel accepted tasks or undo callbacks; cancel known pending tasks first when possible. No recovery, quota refund or replacement project is provided.', inputSchema: object({confirm: {type: 'boolean', const: true}}), annotations: {readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true}},
];
const text = pattern => ({type: 'string', pattern});
export const RECEIVER_PAIRING_TOOL = {name: 'pair_receiver',
  description: 'Explicitly bind this trial to one separately deployed receiver. Requires receiver_setup scope and a fresh public signed manifest from that privately configured runtime. This permanently fixes the receiver; it does not deploy infrastructure or reveal/install secrets through this conversation. Pairing may remain pending while the receiver privately pulls material and proves ownership. Never change identity or manifest after an uncertain result; inspect trial_status. No automatic replacement or quota refund.',
  inputSchema: object({confirm: {type: 'boolean', const: true}, manifest: object({version: {type: 'integer', const: 1},
    release_id: text('^[A-Za-z0-9_-]{1,32}$'), project_id: text('^p_[a-f0-9]{60}$'),
    url: {type: 'string', maxLength: 256}, receiver_public_key: text('^[a-f0-9]{64}$'), pairing_id: text('^[a-f0-9]{64}$'),
    issued_at_ms: {type: 'integer', minimum: 0}, expires_at_ms: {type: 'integer', minimum: 0}, signature: text('^[a-f0-9]{128}$')})}),
  annotations: {readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true}};
const exact = (value, field) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join() === (field || '') && (!field || value[field] === true);
const result = (value, isError = false) => ({content: [{type: 'text', text: JSON.stringify(value)}], structuredContent: value, isError});
const failure = (code, action, state = 'not_attempted') => result({ok: false, error: {code, action},
  provisioning: state, automatic_retry: false}, true);
const receiverMessage = 'Connected; receiver setup required. Separately authorize deployment/private configuration of a receiver, then explicitly pair its public signed manifest using receiver_setup authority. No infrastructure or callback secret is supplied by this connection. Inspect trial_status until receiver_ready is true; do not automatically retry or replace a failed binding.';
function safeStatus(value, allowedScopes) {
  if (!value || !['unprovisioned', 'active'].includes(value.state) || !/^p_[a-f0-9]{60}$/.test(value.project_id)
    || !Number.isSafeInteger(value.expires_at_ms) || !Array.isArray(value.permissions)
    || value.permissions.some(scope => !TRIAL_SCOPES.includes(scope))
    || !(value.receiver_ready === false || (value.receiver_ready === true && value.state === 'active' && value.endpoint_id === 'receiver'))
    || value.attempt_units !== (value.state === 'active' ? 100 : 0)
    || value.client_operations_limit !== 1000) throw new Error('invalid_trial_status');
  const scopes = allowedScopes.filter(scope => value.permissions.includes(scope));
  const canSchedule = value.receiver_ready && scopes.includes('enqueue');
  const general = scopes.includes('http_schedule');
  return {state: value.state, project_id: value.project_id, expires_at_ms: value.expires_at_ms,
    permissions: scopes, receiver_ready: value.receiver_ready, attempt_units: value.attempt_units,
    client_operations_limit: value.client_operations_limit, scheduling_ready: canSchedule,
    ...(value.receiver_ready ? {endpoint_id: 'receiver'} : {}),
    general_https_readiness: general ? 'not_established_by_project_status' : 'not_authorized',
    next_step: general ? 'General HTTPS requests need no RunLater receiver. This status does not establish secure egress availability; scheduling is refused when that transport is unavailable. Do not put private endpoint credentials in model-visible input.' : value.receiver_ready ? (canSchedule
      ? 'Receiver ownership verified. Scheduling may now be explicitly requested within existing scopes and finite budgets. HTTP delivery is not proof that an agent conversation wakes or downstream work completes.'
      : 'Receiver ownership verified, but this access token lacks enqueue permission. Receiver readiness does not grant task authority.') : receiverMessage,
    recovery: 'Not configured. Lost OAuth credentials cannot be recovered using a public project ID or client name.'};
}
export function trialToolHandler({client, revokeTrial, markTrialProvisioned, taskHandler, receiverPairingEnabled = false, allowedScopes = []}) {
  return async (name, args = {}, authorized = false) => {
    if (name === 'pair_receiver') {
      if (!receiverPairingEnabled) return failure('capability_unavailable', 'Receiver pairing is disabled; no setup request was made.');
      if (!authorized || !client) return failure('credentials_required', 'Connect this agent using the RunLater OAuth flow.');
      if (!allowedScopes.includes('receiver_setup')) return failure('insufficient_scope', 'This credential did not consent to receiver setup. Do not reconnect to create a replacement trial or change its scopes silently.');
      if (!args || Array.isArray(args) || Object.keys(args).sort().join() !== 'confirm,manifest' || args.confirm !== true) return failure('invalid_input', 'Use the public signed manifest and explicit confirmation only.');
      try {
        const value = await client.pairReceiver(args.manifest);
        if (!value || !/^p_[a-f0-9]{60}$/.test(value.project_id)
          || !((value.state === 'awaiting_receiver' && value.receiver_ready === false && value.endpoint_id === null)
            || (value.state === 'ready' && value.receiver_ready === true && value.endpoint_id === 'receiver'))) throw new Error();
        return result({ok: true, state: value.state, project_id: value.project_id, receiver_ready: value.receiver_ready,
          endpoint_id: value.endpoint_id, infrastructure_created: false, secrets_returned: false, automatic_retry: false,
          next_step: value.receiver_ready ? 'Receiver verified; explicitly request tasks within existing scope and budget.'
            : 'Receiver pairing is pending. Its private runtime must complete installation and ownership verification before the fixed setup deadline. Inspect trial_status; do not redeploy or replace the binding automatically.'});
      } catch (error) {
        if (error instanceof PublicBetaClientError && ['invalid_receiver_manifest', 'insufficient_scope', 'identity_expired'].includes(error.code))
          return failure(error.code, 'No receiver binding was requested. Review this same trial and its privately configured public manifest.');
        return failure('receiver_pairing_uncertain', 'Binding may have committed. Inspect this same trial_status. Only an explicit repeat of the identical unexpired manifest is safe; never reset or substitute the receiver.', 'unknown');
      }
    }
    const field = {trial_status: '', provision_trial: 'accept_finite_trial', revoke_trial: 'confirm'}[name];
    if (field === undefined) {
      if (name === 'schedule_task') {
        if (!authorized || !client) return failure('credentials_required', 'Connect this agent using the RunLater OAuth flow.');
        try {if (!safeStatus(await client.status(), allowedScopes).receiver_ready) return failure('receiver_setup_required', receiverMessage);}
        catch {return failure('receiver_status_unavailable', 'No task was attempted. Inspect this same trial; do not infer receiver readiness or create a replacement.');}
      }
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
      const safe = safeStatus(value, allowedScopes);
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
