import {DurableObject} from 'cloudflare:workers';
import {importJWK, jwtVerify} from 'jose';

const AUD = 'https://fixture.invalid/agent/execute';
const WEEK = 604800000;
const LIMIT = 10;
const validId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(value);
const fail = code => {throw new Error(code);};
async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}
function b64(bytes) {return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}

// Local-only storage/security primitive proof. No Better Auth adapter or HTTP
// authentication endpoint is wired to this class. Enrollment/clock/cleanup RPCs
// are trusted test fixture operations, not protocol operations.
export class FixtureCoordinator extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.enabled = env.LOCAL_COORDINATOR_FIXTURE === 'enabled';
    if (!this.enabled) return;
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS ledger (
        entitlement TEXT PRIMARY KEY, project TEXT UNIQUE NOT NULL,
        issued INTEGER NOT NULL, expires INTEGER NOT NULL, remaining INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0, cleanup_done INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS hosts (
        id TEXT PRIMARY KEY, entitlement TEXT NOT NULL, public_key TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS replay (
        host TEXT NOT NULL, jti TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(host,jti));
        CREATE TABLE IF NOT EXISTS fixture_clock (id INTEGER PRIMARY KEY CHECK(id=1), now INTEGER NOT NULL);`);
    });
  }
  // Normalize expected fixture errors at the local harness boundary: the pinned
  // Miniflare beta's Node RPC bridge misdecodes rejected Promise results.
  async fixtureCall(method, args) {
    if (!['fixtureClock','fixtureEnroll','execute','fixtureRevoke','fixtureCleanupPending','fixtureFinishCleanup','fixtureInspect'].includes(method)) return {ok:false,error:'unknown_fixture_method'};
    try {return {ok:true,value:await this[method](...args)};}
    catch(error) {return {ok:false,error:error.message};}
  }
  #sql(query, ...args) {return this.ctx.storage.sql.exec(query,...args).toArray();}
  #now() {
    if (!this.enabled) fail('fixture_disabled');
    const clock = this.#sql('SELECT now FROM fixture_clock WHERE id=1')[0];
    if (!clock) fail('fixture_clock_missing');
    return clock.now;
  }
  async fixtureClock(now) {
    if (!this.enabled) fail('fixture_disabled');
    if (!Number.isSafeInteger(now) || now < 0) fail('invalid_clock');
    this.ctx.storage.transactionSync(() => {
      const previous = this.#sql('SELECT now FROM fixture_clock WHERE id=1')[0];
      if (previous && now < previous.now) fail('clock_reversal');
      this.#sql('INSERT INTO fixture_clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET now=excluded.now',now);
    });
    await this.ctx.storage.sync();
  }
  async fixtureEnroll({entitlement, project, issued, host, publicKey}) {
    const now = this.#now();
    if (![entitlement,project,host].every(validId) || !Number.isSafeInteger(issued) || issued < 0 || issued > now || !Number.isSafeInteger(issued+WEEK)) fail('invalid_enrollment');
    if (publicKey?.kty !== 'OKP' || publicKey.crv !== 'Ed25519' || typeof publicKey.x !== 'string' || publicKey.d || Object.keys(publicKey).some(k=>!['kty','crv','x'].includes(k))) fail('invalid_public_key');
    // import validates key shape before any persistent quota/identity reservation.
    await importJWK(publicKey,'EdDSA');
    const key = JSON.stringify({kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x});
    const result = this.ctx.storage.transactionSync(() => {
      const current = this.#now();
      const prior = this.#sql('SELECT * FROM ledger WHERE entitlement=?',entitlement)[0];
      if (prior && (prior.project !== project || prior.issued !== issued)) fail('identity_conflict');
      if (prior?.revoked || (prior && prior.expires <= current)) fail('authority_inactive');
      if (!prior) {
        if (issued+WEEK <= current) fail('authority_inactive');
        if (this.#sql('SELECT count(*) AS count FROM ledger')[0].count >= LIMIT) fail('lifetime_project_cap');
        this.#sql('INSERT INTO ledger(entitlement,project,issued,expires,remaining) VALUES(?,?,?,?,100)',entitlement,project,issued,issued+WEEK);
      }
      const oldHost = this.#sql('SELECT * FROM hosts WHERE id=?',host)[0];
      if (oldHost && (oldHost.entitlement !== entitlement || oldHost.public_key !== key)) fail('host_conflict');
      if (!oldHost) {
        if (this.#sql('SELECT count(*) AS count FROM hosts WHERE entitlement=?',entitlement)[0].count >= 4) fail('host_cap');
        this.#sql('INSERT INTO hosts VALUES(?,?,?)',host,entitlement,key);
      }
      return this.#sql('SELECT * FROM ledger WHERE entitlement=?',entitlement)[0];
    });
    await this.ctx.storage.sync();
    return result;
  }
  async execute(token, command) {
    const now = this.#now();
    if (typeof token !== 'string' || token.length > 4096) fail('invalid_token');
    if (!command || Object.keys(command).sort().join() !== 'capability,units' || command.capability !== 'fixture_debit' || !Number.isSafeInteger(command.units) || command.units < 1 || command.units > 100) fail('invalid_command');
    // Decode only to locate a registered verification key. No untrusted public
    // key or URL is accepted and no decoded claim grants authority.
    let sub;
    try {sub = JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).sub;} catch {fail('invalid_token');}
    if (!validId(sub)) fail('invalid_token');
    const host = this.#sql('SELECT * FROM hosts WHERE id=?',sub)[0];
    if (!host) fail('unknown_host');
    const {payload,protectedHeader} = await jwtVerify(token,await importJWK(JSON.parse(host.public_key),'EdDSA'),{
      algorithms:['EdDSA'],audience:AUD,typ:'agent+jwt',maxTokenAge:60,clockTolerance:30,currentDate:new Date(now),requiredClaims:['sub','iat','exp','jti']});
    if (protectedHeader.typ !== 'agent+jwt' || payload.aud !== AUD || payload.sub !== sub || !validId(payload.jti) || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.exp <= payload.iat || payload.exp-payload.iat > 60 || payload.htm !== 'POST' || payload.htu !== AUD || JSON.stringify(payload.capabilities) !== '["fixture_debit"]' || payload.ath !== b64(await digest(JSON.stringify(command)))) fail('request_binding_rejected');
    const result = this.ctx.storage.transactionSync(() => {
      // Re-read lifecycle and time after asynchronous cryptographic verification.
      const current = this.#now();
      if (payload.exp*1000+30000 <= current) fail('token_expired');
      const ledger = this.#sql('SELECT * FROM ledger WHERE entitlement=?',host.entitlement)[0];
      if (!ledger || ledger.revoked || ledger.expires <= current) fail('authority_inactive');
      this.#sql('DELETE FROM replay WHERE expires<=?',current);
      if (this.#sql('SELECT 1 FROM replay WHERE host=? AND jti=?',sub,payload.jti).length) fail('replay_rejected');
      if (this.#sql('SELECT count(*) AS count FROM replay')[0].count >= 512) fail('replay_capacity');
      if (ledger.remaining < command.units) fail('quota_exhausted');
      this.#sql('INSERT INTO replay VALUES(?,?,?)',sub,payload.jti,(payload.exp+30)*1000);
      this.#sql('UPDATE ledger SET remaining=remaining-? WHERE entitlement=?',command.units,host.entitlement);
      return this.#sql('SELECT * FROM ledger WHERE entitlement=?',host.entitlement)[0];
    });
    await this.ctx.storage.sync();
    return {...result,fixture:true,scheduling_enabled:false};
  }
  async fixtureRevoke(entitlement) {
    this.#now();
    if (!validId(entitlement)) fail('invalid_entitlement');
    this.#sql('UPDATE ledger SET revoked=1 WHERE entitlement=?',entitlement);
    await this.ctx.storage.sync();
    // Tombstone committed first. Cleanup can be retried independently even if
    // revocation was already requested. No network cleanup exists in this proof.
    return {revoked:true};
  }
  fixtureCleanupPending() {this.#now(); return this.#sql('SELECT entitlement FROM ledger WHERE revoked=1 AND cleanup_done=0');}
  async fixtureFinishCleanup(entitlement) {
    this.#now();
    this.#sql('UPDATE ledger SET cleanup_done=1 WHERE entitlement=? AND revoked=1',entitlement);
    await this.ctx.storage.sync();
  }
  fixtureInspect(entitlement) {this.#now();return this.#sql('SELECT * FROM ledger WHERE entitlement=?',entitlement)[0] ?? null;}
}
// Deliberately no external ingress into enrollment, clock, ledger or debit RPCs.
export default {fetch() {return new Response('local fixture only',{status:503});}};
