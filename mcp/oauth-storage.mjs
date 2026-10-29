// A strongly consistent, bounded KV-shaped adapter for the OAuth library.
// The caller MUST serialize complete OAuth operations, not just individual methods.
export function createOAuthStorage(storage, {clock = Date.now, maxEntries = 512, maxBytes = 16384} = {}) {
  const prefix = 'oauth:';
  const valid = key => {if (typeof key !== 'string' || key.length > 2048) throw new Error('oauth_storage_key'); return prefix + key;};
  const now = () => Math.floor(clock() / 1000);
  const bucket = key => key.startsWith('oauth:transaction:') ? 'consent'
    : /^oauth:(?:grant|token):/.test(key) ? 'authority' : 'other';
  const bucketLimits = {consent: Math.min(64, maxEntries), authority: Math.min(384, maxEntries), other: Math.min(64, maxEntries)};
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
      const expiration = options.expiration ?? (options.expirationTtl === undefined ? now() + 4200 : now() + options.expirationTtl);
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
      // No OAuth record can silently outlive this bounded one-hour delegation milestone.
      await storage.put(name, {value, metadata: options.metadata, expiration: Math.min(expiration, now() + 4200)});
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
