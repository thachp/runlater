"""Execution-phase helper only: generate exactly two approved staging secrets into /tmp, never stdout."""
import argparse,json,os,pathlib,secrets
p=argparse.ArgumentParser();p.add_argument('--parent-released-execution',action='store_true');p.add_argument('output');a=p.parse_args()
if not a.parent_released_execution:raise SystemExit('Review-only phase: no secret generation permitted')
path=pathlib.Path(a.output).absolute()
if path.parent.resolve()!=pathlib.Path('/tmp').resolve():raise SystemExit('Use an untracked private /tmp file')
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w')as f:json.dump({'STAGING_INGRESS':secrets.token_hex(32),'STAGING_CALLBACK_HMAC':secrets.token_hex(32)},f)
print('Two staging-only secrets written to private file; values omitted')
