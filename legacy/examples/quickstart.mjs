// Start `npm run dev -- --ip 127.0.0.1`, then run `npm run example:local`.
import {LocalRunLater} from './local-client.mjs';
import {RunLaterError} from './local-client.mjs';
const client=new LocalRunLater(),key='example_'+Date.now();
const input={destination:'fixture://success',body:JSON.stringify({message:'local fixture'}),operation_key:key,run_at_ms:Date.now()+60000};
try{
 const first=await client.enqueue(input,key),replay=await client.enqueue(input,key);
 if(first.data.id!==replay.data.id)throw new Error('Idempotency mismatch');
 const view=await client.inspection(first.data.id);
 await client.cancel(first.data.id);
 console.log(JSON.stringify({id:view.data.id,initial_status:view.data.status,replay_status:replay.status,final_status:(await client.inspection(first.data.id)).data.status}));
}catch(e){if(e instanceof RunLaterError)console.error(JSON.stringify({status:e.status,retry_after_seconds:e.retryAfterSeconds}));else console.error('Local example failed');process.exitCode=1;}
