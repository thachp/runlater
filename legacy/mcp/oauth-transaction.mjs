// Network work operates on an isolated snapshot. Only a short compare-and-swap
// commit runs inside the Durable Object transaction; conflicts fail closed.
import {createOAuthStorage} from './oauth-storage.mjs';
export async function oauthTransaction(storage, operation, options = {}) {
  if (typeof storage.transaction !== 'function') throw new Error('atomic_storage_required');
  const before = await storage.list({prefix:'oauth:', limit:513});
  const view = new Map([...before].map(([k,v]) => [k,structuredClone(v)]));
  const overlay = {
    async get(k) {return structuredClone(view.get(k));},
    async put(k,v) {view.set(k,structuredClone(v));},
    async delete(k) {return view.delete(k);},
    async list({prefix='',limit=1000}={}) {return new Map([...view].filter(([k])=>k.startsWith(prefix)).sort(([a],[b])=>a<b?-1:a>b?1:0).slice(0,limit).map(([k,v])=>[k,structuredClone(v)]));},
  };
  const same=(a,b)=>a===b||!!a&&!!b&&a.value===b.value&&a.expiration===b.expiration&&JSON.stringify(a.metadata)===JSON.stringify(b.metadata);
  const result = await operation(createOAuthStorage(overlay,options));
  if (view.size === before.size && [...before].every(([k,v]) => same(view.get(k),v))) return result;
  await storage.transaction(async tx => {
    const current = await tx.list({prefix:'oauth:',limit:513});
    if (current.size !== before.size || [...before].some(([k,v]) => !same(current.get(k),v))) throw new Error('oauth_commit_conflict');
    for (const [k,v] of view) if (!same(before.get(k),v)) await tx.put(k,v);
    for (const k of before.keys()) if (!view.has(k)) await tx.delete(k);
  });
  return result;
}
