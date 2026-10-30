// Classify captured child failures without returning child text or arbitrary values.
// These are diagnostic hints, never evidence that an upload had no effect.
const OUTPUT_BOUND=32768;
const AUTH_CODES=[10000,9103,9106,9109];
function bounded(value){
 if(typeof value==='string')return value.slice(0,OUTPUT_BOUND);
 if(Buffer.isBuffer(value))return value.subarray(0,OUTPUT_BOUND).toString('utf8');
 return '';
}
export function classifyWranglerFailure(error){
 const text=bounded(error?.stdout)+'\n'+bounded(error?.stderr);
 const auth_error_codes=AUTH_CODES.filter(code=>new RegExp('\\[code:\\s*'+code+'\\]').test(text));
 let kind='unclassified';
 if(text.includes('Aborting the upload operation because of conflicts.'))kind='strict_conflict';
 else if(text.includes('Unable to fetch bindings, routes, or services metadata from the dashboard.'))kind='dashboard_metadata_read_failed';
 else if(auth_error_codes.length)kind='provider_auth_rejected';
 else if(error?.code==='ETIMEDOUT'||/\bETIMEDOUT\b/.test(text))kind='timeout';
 else if(/\b(ECONNRESET|ENOTFOUND|EAI_AGAIN|ECONNREFUSED)\b/.test(text))kind='network_failure';
 return {exit_status:Number.isInteger(error?.status)&&error.status>=0&&error.status<=255?error.status:'unknown',kind,auth_error_codes};
}
