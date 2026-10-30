// Preview the built production Worker locally, never deploy.
import {spawn} from 'node:child_process';
const role=process.argv[2]??'landing';
if(!['landing','docs'].includes(role))throw Error('Use landing or docs');
const child=spawn('node_modules/.bin/wrangler',['dev','--local','--config',`web/${role}/wrangler.jsonc`,'--ip','127.0.0.1','--port',role==='landing'?'4173':'4174','--host',role==='landing'?'runlater.io':'docs.runlater.io','--upstream-protocol','https'],{stdio:'inherit',env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
child.on('exit',code=>process.exit(code??1));
