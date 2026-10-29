// MCP adapter only: the signed API remains the sole task/funding authority.
import {PublicBetaClientError, ORIGIN} from '../examples/public-beta-client.v1.mjs';

export {TOOLS} from './tool-schema.mjs';
import * as validators from './tool-validation.generated.mjs';
const scopes = {schedule_task: 'enqueue', task_status: 'read', cancel_task: 'cancel'};
const states = ['scheduled', 'ready', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled'];
const integer = n => Number.isSafeInteger(n) && n >= 0;
const nullableTime = n => n === null || integer(n);
const result = (value, isError = false) => ({content: [{type: 'text', text: JSON.stringify(value)}], structuredContent: value, isError});
function failure(code, action, acceptance = 'not_attempted') {
  return result({ok: false, error: {code, action}, task_acceptance: acceptance, automatic_retry: false}, true);
}
export function taskResult(value, expectedId, canRead) {
  const task = value?.result;
  if (!task || !/^task_[a-f0-9]{16}$/.test(task.id) || (expectedId && task.id !== expectedId)
    || !states.includes(task.status) || value.task_accepted !== true || typeof value.replayed !== 'boolean') throw new Error('invalid_response');
  // Positive allowlist: never return input/payload, destination, keys, arbitrary error/outcome strings or headers.
  const safe = {task_id: task.id, status: task.status, task_accepted: true, replayed: value.replayed,
    delivery_confirmed: task.status === 'succeeded', delivery_meaning: 'A recorded HTTP success is not downstream business completion.'};
  if (canRead) for (const field of ['due_ms', 'terminal_ms']) if (nullableTime(task[field])) safe[field] = task[field];
  if (typeof task.cancel_requested === 'boolean') safe.cancel_requested = task.cancel_requested;
  if (canRead && Array.isArray(task.attempts) && task.attempts.length <= 5) safe.attempts = task.attempts.map(attempt => {
    if (!integer(attempt.fence) || !integer(attempt.started_ms) || !nullableTime(attempt.finished_ms)) throw new Error('invalid_response');
    const outcome = attempt.outcome;
    return {fence: attempt.fence, started_ms: attempt.started_ms, finished_ms: attempt.finished_ms,
      outcome: outcome === null ? 'pending' : typeof outcome === 'string' && /^(timeout|lease_expired_unknown|http_[1-5][0-9]{2})$/.test(outcome) ? outcome : 'recorded_outcome_redacted'};
  });
  return safe;
}

export async function publicStatus(fetchImpl = fetch) {
  const controller = new AbortController(); let reader, timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => {controller.abort(); reject(new Error('status_unavailable'));}, 5000); });
  try {
    return await Promise.race([timeout, (async () => {
      const response = await fetchImpl(ORIGIN + '/v1/beta', {redirect: 'manual', signal: controller.signal});
      if (!response.ok) throw new Error('status_unavailable');
      reader = response.body?.getReader(); let size = 0, chunks = 0; const parts = [];
      if (reader) for (;;) {const {done, value} = await reader.read(); if (done) break;
        if ((size += value.byteLength) > 8192 || ++chunks > 32) throw new Error('status_unavailable'); parts.push(Buffer.from(value));}
      const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts)));
      if (value.mode !== 'public_free_beta' || value.payments !== false || typeof value.registration_open !== 'boolean'
        || !integer(value.remaining_projects) || value.remaining_projects > 10
        || value.trial?.attempt_units !== 100 || value.trial?.duration_ms !== 604800000 || value.trial?.units_reserved_per_task !== 5
        || value.limits?.client_operations_per_project !== 1000 || value.limits?.lifetime_projects !== 10
        || value.limits?.lifetime_publications_per_project !== 128 || value.limits?.lifetime_tasks_per_project !== 16
        || value.limits?.receiver !== 'worker.account.workers.dev') throw new Error('status_unavailable');
      return {mode: value.mode, registration_open: value.registration_open, remaining_projects: value.remaining_projects,
        payments: false, receiver_policy: 'ownership_verified_workers_dev_only', status_source: 'live_public_API_sample',
        note: 'Public discovery is not permission, funded entitlement or proof a receiver is verified.'};
    })()]);
  } finally {clearTimeout(timer); controller.abort(); if (reader) {void reader.cancel().catch(() => {}); try {reader.releaseLock();} catch { /* pending read */ }}}
}

export function toolHandler({client = null, allowedScopes = [], status = publicStatus} = {}) {
  // One configured client per process; neither project identity nor credentials can be selected by tools.
  let active = 0;
  return async (name, args = {}, authorized = false) => {
    if (!Object.hasOwn(validators, name)) return failure('capability_unavailable', 'Use tools/list. List, redrive, enrollment, receiver changes and payments are not exposed.');
    if (!validators[name](args) || (name === 'schedule_task' && Buffer.byteLength(args.body) > 1024)) return failure('invalid_input', 'Use exactly the published tool schema; credentials and project overrides are not accepted.');
    if (name !== 'service_status' && (!authorized || !client)) return failure('credentials_required', 'Configure an existing project identity and MCP access token outside the conversation; reconnect with Authorization.');
    if (name !== 'service_status' && !allowedScopes.includes(scopes[name])) return failure('insufficient_scope', 'Ask the owner to review existing authority; discovery does not grant permissions.');
    if (active >= 4) return failure('busy', 'Wait for in-flight calls to finish. Never retry a mutation with a different idempotency key.');
    active++;
    let sent = false;
    try {
      if (name === 'service_status') return result({ok: true, ...await status()});
      sent = true;
      let response;
      if (name === 'schedule_task') {const {idempotency_key, ...input} = args; response = await client.enqueue(input, idempotency_key);}
      else if (name === 'task_status') response = await client.task(args.task_id);
      else response = await client.cancel(args.task_id);
      return result({ok: true, ...taskResult(response, args.task_id, allowedScopes.includes('read')), ...(name === 'cancel_task' ? {cancellation_cannot_undo_callback: true} : {})});
    } catch (error) {
      // Never serialize upstream error bodies/messages, signed headers, receipts, payloads or exceptions.
      if (name === 'service_status') return failure('status_unavailable', 'Public status is unavailable or the profile is unsupported. Do not infer hosted capabilities.');
      if (error instanceof PublicBetaClientError) {
        if (['identity_expired', 'enrollment_required'].includes(error.code)) return failure('credentials_expired_or_missing', 'Owner must inspect the existing identity outside the model; no enrollment or recovery is performed.');
        if (['invalid_task', 'request_too_large', 'idempotency_key_required'].includes(error.code)) return failure('invalid_input', 'Check UTF-8 size, stable operation keys and schedule against identity expiry.');
        const actions = {400: ['invalid_request', 'Check the hosted contract and schedule.'], 401: ['credentials_rejected', 'Check existing identity expiry, revocation and signing clock.'], 403: ['insufficient_scope_or_project', 'Check project ownership and existing permissions; do not substitute another project.'], 404: ['not_found', 'Check the task ID within the configured project.'], 409: ['conflict', 'Do not change a stable key to bypass conflict. Reuse identical arguments or inspect the known task.'], 429: ['limits_exhausted', 'Inspect finite project/grant limits. No purchase, automatic retry or new project is performed.']};
        if (error.code === 'http_error' && actions[error.status]) {const [code, action] = actions[error.status]; return failure(code, action, name === 'schedule_task' ? 'not_confirmed' : 'not_applicable');}
      }
      return failure('result_uncertain', name === 'schedule_task'
        ? 'The task may have been accepted. Retain this exact idempotency_key and all arguments; only an explicitly requested retry with identical values can recover it. Do not use a new key.'
        : 'No reliable result was received. Inspect the same task ID; cancellation cannot undo an in-flight callback.', sent ? 'unknown' : 'not_attempted');
    } finally {active--;}
  };
}
