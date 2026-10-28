// Shared bounded local demonstration only; not durable business-operation storage.
import {createHash} from 'node:crypto';
export function operationDedup(){const seen=new Map();return (tenant,operation,bytes)=>{const key=tenant+':'+operation,digest=createHash('sha256').update(bytes).digest('hex');if(seen.has(key))return seen.get(key)===digest?{status:204,duplicate:true}:{status:409};if(seen.size>=1024)return {status:503};seen.set(key,digest);return {status:204,duplicate:false};};}
