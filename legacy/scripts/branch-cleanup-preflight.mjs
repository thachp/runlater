// Offline snapshot validator only: no network, subprocess, Git or deletion capability.
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
// Literal refs/heads tail, following git-check-ref-format (no normalization or checkout shorthand).
// https://git-scm.com/docs/git-check-ref-format
export function validBranchRef(name) {
 if(typeof name!=='string'||name.length===0||name.includes('..')||name.includes('@{')||name.endsWith('.'))return false;
 if([...name].some(c=>c.codePointAt(0)<=32||c.codePointAt(0)===127||'~^:?*[\\'.includes(c)))return false;
 return name.split('/').every(part=>part.length>0&&!part.startsWith('.')&&!part.endsWith('.lock'));
}
export function preflight(s, now=Date.now()) {
 const blockers=[];
 const add=code=>{if(!blockers.includes(code))blockers.push(code)};
 if(!s||typeof s!=='object'||Array.isArray(s))return {eligible:false,blockers:['invalid_snapshot'],dependentOpenPullRequests:[]};
 const sha=v=>typeof v==='string'&&/^[0-9a-f]{40}$/.test(v);
 const branch=s.branch;
 if(!validBranchRef(s.defaultBranch))add('missing_default_branch');
 if(!validBranchRef(branch)||branch===s.defaultBranch||['main','master','HEAD'].includes(branch))add('protected_or_invalid_branch');
 if(typeof s.repository!=='string'||!/^[-\w.]+\/[-\w.]+$/.test(s.repository))add('invalid_repository');
 const at=Date.parse(s.observedAt);
 if(!Number.isFinite(at)||!Number.isFinite(now)||at>now||now-at>300000)add('stale_or_invalid_inventory');
 if(s.completeOpenPrInventory!==true)add('incomplete_open_pr_inventory');
 const p=s.mergedPullRequest;
 if(!p||!Number.isSafeInteger(p.number)||p.number<=0||p.repository!==s.repository||p.head?.repository!==s.repository||p.merged!==true||p.base!==s.defaultBranch||p.head?.ref!==branch||!sha(p.head?.sha)||!sha(p.mergeCommitSha)||p.head.sha!==s.expectedMergedHead)add('merged_pr_identity_mismatch');
 if(s.candidateRef?.protected!==false)add('protected_or_unknown_candidate_ref');
 if(!sha(s.expectedMergedHead)||s.candidateRef?.ref!==`refs/heads/${branch}`||s.candidateRef?.sha!==s.expectedMergedHead)add('candidate_ref_mismatch');
 const open=s.openPullRequests;
 if(!Array.isArray(open))add('missing_open_pr_inventory');
 const rows=Array.isArray(open)?open:[];
 const dependencies=[];
 const seen=new Set();
 for(const r of rows){
  if(!r||typeof r!=="object"||Array.isArray(r)){add("malformed_open_pr");continue}
  if(seen.has(r.number))add("duplicate_open_pr");seen.add(r.number);
  if(!Number.isSafeInteger(r.number)||r.number<=0||r.state!=='open'||!validBranchRef(r.base)||!sha(r.head?.sha)||!validBranchRef(r.head?.ref)||(typeof r.head?.repository!=='string'||!/^[-\w.]+\/[-\w.]+$/.test(r.head.repository))){add('malformed_open_pr');continue}
  if(r.base===branch){dependencies.push({number:r.number,base:r.base,head:r.head});add('open_pr_depends_on_base')}
  if(r.head.repository===s.repository&&r.head.ref===branch)add('branch_heads_open_pr');
  if(!Array.isArray(s.observedPrHeadRefs)||!s.observedPrHeadRefs.some(h=>h?.repository===r.head.repository&&h?.ref===`refs/heads/${r.head.ref}`&&h?.sha===r.head.sha))add('open_pr_head_not_preserved');
 }
 return {eligible:blockers.length===0,blockers,dependentOpenPullRequests:dependencies,notice:'Snapshot consistency only. Recheck fresh provider state before an independently authorized mutation; this tool never deletes or retargets anything.'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{const raw=fs.readFileSync(0,'utf8');if(Buffer.byteLength(raw)>65536)throw Error();const result=preflight(JSON.parse(raw));process.stdout.write(JSON.stringify(result,null,2)+'\n');process.exitCode=result.eligible?0:2;}
 catch{process.stderr.write('Invalid bounded cleanup snapshot JSON. No action performed.\n');process.exitCode=2;}
}
