// Operational release guard only: approval of residual risk is not a provider spending certificate.
import assert from 'node:assert/strict';
export function authorizeCampaign(manifest,{executionSha,phase}){
 const budget=manifest.budget??{},release=manifest.execution_readiness??{},limits=manifest.test_envelope??{};
 assert.equal(budget.risk_budget_approved,true,'LIVE BLOCKED: risk budget approval missing');
 assert.ok(typeof budget.authorized_incremental_usd==='number'&&budget.authorized_incremental_usd>0&&budget.authorized_incremental_usd<=20,'Approved risk amount must not exceed USD20');
 assert.ok(Number.isFinite(budget.conservative_whole_rate_unit_reserve_usd)&&budget.conservative_whole_rate_unit_reserve_usd>0&&budget.conservative_whole_rate_unit_reserve_usd<=budget.authorized_incremental_usd,'Campaign reserve exceeds approved risk amount');
 assert.equal(budget.residual_provider_billing_risk_acknowledged,true,'LIVE BLOCKED: provider risk acknowledgement missing');
 assert.equal(budget.anonymous_ingress_risk_acknowledged,true,'LIVE BLOCKED: public ingress risk acknowledgement missing');
 assert.equal(release.campaign_limits_reviewed,true,'LIVE BLOCKED: finite campaign limits not reviewed');
 assert.equal(release.parent_live_release,true,'LIVE BLOCKED: parent has not released execution');
 assert.match(release.reviewed_sha??'',/^[0-9a-f]{40}$/,'Exact reviewed SHA required');
 assert.match(executionSha??'',/^[0-9a-f]{40}$/,'Execution SHA required');
 assert.equal(release.reviewed_sha,executionSha,'Execution differs from reviewed SHA');
 assert.ok(['disabled','receiver'].includes(phase)&&Array.isArray(release.released_phases)&&release.released_phases.includes(phase),'Phase not released');
 for(const[name,max]of Object.entries({lifetime_seconds:900,operator_http_requests_max:200,accepted_tasks_max:12,queue_publish_calls_max:128,synthetic_payload_bytes_max:256,worker_cpu_ms_per_invocation:50,worker_subrequests_per_invocation:4,controlled_callback_timeout_ms:3000,controlled_callback_response_bytes_max:1024,response_header_bytes_max:2048}))assert.ok(Number.isSafeInteger(limits[name])&&limits[name]>=1&&limits[name]<=max,`Invalid finite campaign limit: ${name}`);
 for(const name of ['queue_transport_retries','consumer_batch_size','consumer_concurrency'])assert.equal(limits[name],1,`Unexpected campaign setting: ${name}`);
 assert.equal(limits.staging_project,'alpha');
 return {operatorHttpCallsMax:limits.operator_http_requests_max,reviewedSha:release.reviewed_sha,phase};
}
