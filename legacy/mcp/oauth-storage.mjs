// A strongly consistent, bounded KV-shaped adapter for the OAuth library.
// The caller MUST serialize complete OAuth operations, not just individual methods.
export function createOAuthStorage(storage, {clock = Date.now, maxEntries = 512, maxBytes = 16384, trialEnabled = false} = {}) {
  const prefix = 'oauth:';
  const parse = value => {try{return JSON.parse(value);}catch{return null;}};
  const valid = key => {if (typeof key !== 'string' || key.length > 2048) throw new Error('oauth_storage_key'); return prefix + key;};
  const now = () => Math.floor(clock() / 1000);
  const bucket = key => key.startsWith('oauth:transaction:') ? 'consent'
    : key.startsWith('oauth:family:') ? 'families'
    : /^oauth:(?:grant|token):/.test(key) ? 'authority' : 'other';
  const bucketLimits = {consent: Math.min(64, maxEntries), authority: Math.min(384, maxEntries), other: Math.min(trialEnabled ? 22 : 64, maxEntries), families: Math.min(trialEnabled ? 42 : 0, maxEntries)};
  let writes = Promise.resolve();
  const atomicWrite = fn => {const result = writes.then(fn); writes = result.catch(() => {}); return result;};
  async function records() {
    const values = await storage.list({prefix, limit: maxEntries + 1});
    for (const [key, record] of values) if (record.expiration !== undefined && record.expiration <= now()) {
      await storage.delete(key); values.delete(key);
    }
    return values;
  }
  return {
    async get(key, options) {
      const name = valid(key), record = await storage.get(name);
      if (!record) return null;
      if (record.expiration !== undefined && record.expiration <= now()) {await storage.delete(name); return null;}
      const type = typeof options === 'string' ? options : options?.type;
      if (type === 'json') return JSON.parse(record.value);
      if (type && type !== 'text') throw new Error('unsupported_oauth_storage_type');
      return record.value;
    },
    async put(key, value, options = {}) {
      return atomicWrite(async () => {
      const name = valid(key);
      if (typeof value !== 'string' || Buffer.byteLength(value) > maxBytes) throw new Error('oauth_storage_value');
      let expiration = options.expiration ?? (options.expirationTtl === undefined ? now() + 4200 : now() + options.expirationTtl);
      if (!Number.isInteger(expiration) || expiration <= now()) throw new Error('oauth_storage_expiry');
      const current = await records();
      if (!current.has(name) && current.size >= maxEntries) throw new Error('oauth_storage_capacity');
      const group = bucket(name);
      if (!current.has(name) && [...current.keys()].filter(key => bucket(key) === group).length >= bucketLimits[group]) {
        throw new Error('oauth_storage_partition_capacity');
      }
      if (group === 'authority' && !current.has(name)) {
        const project = name.split(':')[2];
        if ([...current.keys()].filter(key => bucket(key) === 'authority' && key.split(':')[2] === project).length >= 32) {
          throw new Error('oauth_project_capacity');
        }
      }
      // Seven-day records require a locally authored trial grant/family classification.
      const project = name.split(':')[2], grantId = name.split(':')[3];
      const grant = key.startsWith('grant:') ? parse(value) : parse(current.get(`oauth:grant:${project}:${grantId}`)?.value || 'null');
      const isTrial = key.startsWith('family:') || grant?.metadata?.authorityKind === 'trial';
      const existingGrant=parse(current.get(`oauth:grant:${project}:${grantId}`)?.value);
      if(!trialEnabled && group==='authority' && (isTrial || existingGrant?.metadata?.authorityKind==='trial'
        || current.has(`oauth:family:${project}:${grantId}`))) throw new Error('trial_storage_disabled');
      if(key.startsWith('family:')) {
        const family=parse(value), prior=parse(current.get(name)?.value);
        if(!trialEnabled) {
          // Rollback stops issuance, not already-requested irreversible cleanup.
          // Only retry bookkeeping/confirmation on an existing tombstone may change.
          const mutable=new Set(['cleanupAttempts','nextAttemptAtMs','cleanupDone','revocationSecret']);
          const fixed=o=>Object.fromEntries(Object.entries(o||{}).filter(([k])=>!mutable.has(k)));
          const attempts=family?.cleanupAttempts||0, oldAttempts=prior?.cleanupAttempts||0;
          const next=family?.nextAttemptAtMs||0, oldNext=prior?.nextAttemptAtMs||0;
          if(!prior || prior.revoked!==true || family?.revoked!==true
            || JSON.stringify(fixed(prior))!==JSON.stringify(fixed(family))
            || !Number.isSafeInteger(attempts) || attempts<oldAttempts || attempts>Math.min(32,oldAttempts+1)
            || !Number.isSafeInteger(next) || next<oldNext || next>prior.expiresAt
            || typeof family.cleanupDone!=='boolean' || (prior.cleanupDone && !family.cleanupDone)
            || (family.revocationSecret!==prior.revocationSecret && !(family.cleanupDone && family.revocationSecret===undefined))
            || expiration>Math.ceil(prior.expiresAt/1000)
            || JSON.stringify(options.metadata)!==JSON.stringify(current.get(name).metadata)) throw new Error('trial_storage_disabled');
          expiration=Math.min(expiration,current.get(name).expiration);
        }
        if(!current.has(name) || !!prior?.provisioned !== !!family?.provisioned) {
          const same=[...current].filter(([k,r])=>k!==name&&k.startsWith('oauth:family:')&&!!parse(r.value)?.provisioned===!!family?.provisioned).length;
          if(same >= (family?.provisioned ? 10 : 32)) throw new Error('trial_family_partition_capacity');
          if(!family?.provisioned && [...current].filter(([k,r])=>k!==name&&k.startsWith('oauth:family:')&&!parse(r.value)?.provisioned&&parse(r.value)?.clientId===family.clientId).length>=8) throw new Error('trial_client_pending_capacity');
        }
      }
      if (group === 'authority' && !current.has(name)) {
        const trialCount = [...current].filter(([k,r]) => /^oauth:grant:/.test(k) && parse(r.value)?.metadata?.authorityKind === 'trial').length;
        if (isTrial && key.startsWith('grant:') && trialCount >= 42) throw new Error('trial_capacity');
        const trialRecords = [...current].filter(([k]) => /^oauth:(?:grant|token):/.test(k) && current.has(`oauth:family:${k.split(':')[2]}:${k.split(':')[3]}`)).length;
        if (trialEnabled && !isTrial && [...current.keys()].filter(k=>/^oauth:(?:grant|token):/.test(k)).length-trialRecords >= 256) throw new Error('owner_authority_capacity');
        if (isTrial && trialRecords >= 128) throw new Error('trial_authority_capacity');
        if(isTrial) {
          const active=!!parse(current.get(`oauth:family:${project}:${grantId}`)?.value)?.provisioned;
          const matching=[...current].filter(([k])=>/^oauth:(?:grant|token):/.test(k)&&current.has(`oauth:family:${k.split(':')[2]}:${k.split(':')[3]}`)&&!!parse(current.get(`oauth:family:${k.split(':')[2]}:${k.split(':')[3]}`)?.value)?.provisioned===active).length;
          if(matching>=64)throw new Error('trial_authority_partition_capacity');
        }
      }
      await storage.put(name, {value, metadata: options.metadata, expiration: Math.min(expiration, now() + (isTrial ? 604800 : 4200))});
      });
    },
    async delete(key) {await storage.delete(valid(key));},
    async list(options = {}) {
      const values = [...await records()].filter(([key]) => key.startsWith(prefix + (options.prefix || '')))
        .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
      const after = options.cursor ? Buffer.from(options.cursor, 'base64url').toString() : '';
      const eligible = values.filter(([key]) => key > after);
      const limit = Math.min(options.limit ?? 1000, maxEntries);
      const page = eligible.slice(0, limit), complete = page.length === eligible.length;
      return {keys: page.map(([key, value]) => ({name: key.slice(prefix.length), expiration: value.expiration, metadata: value.metadata})),
        list_complete: complete, cursor: complete ? '' : Buffer.from(page.at(-1)[0]).toString('base64url')};
    },
  };
}
