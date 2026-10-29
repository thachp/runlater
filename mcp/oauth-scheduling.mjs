// Network-bearing authorization must never own the token-validation lane.
export function createOAuthScheduling() {
  const lanes = new Map();
  let queued = 0, validations = 0, setupNetwork = 0, tokenNetwork = 0, revocationNetwork = 0;
  const capacity = () => new Error('oauth_capacity');
  function critical(key, fn) {
    const prior = lanes.get(key);
    if (queued >= 32 || (prior?.count ?? 0) >= 4) return Promise.reject(capacity());
    queued++;
    const lane = prior || {promise: Promise.resolve(), count: 0}; lane.count++; lanes.set(key, lane);
    const result = lane.promise.then(fn).finally(() => {
      queued--; lane.count--; if (!lane.count) lanes.delete(key);
    });
    lane.promise = result.catch(() => {}); return result;
  }
  async function validate(fn) {
    if (validations >= 32) throw capacity(); validations++;
    try {return await fn();} finally {validations--;}
  }
  async function network(kind, fn) {
    if (kind === 'setup') {if (setupNetwork >= 4) throw capacity(); setupNetwork++;}
    else if (kind === 'revocation') {if (revocationNetwork >= 2) throw capacity(); revocationNetwork++;}
    else {if (tokenNetwork >= 4) throw capacity(); tokenNetwork++;}
    try {return await fn();} finally {
      if (kind === 'setup') setupNetwork--; else if (kind === 'revocation') revocationNetwork--; else tokenNetwork--;
    }
  }
  return {critical, validate, network};
}
