import {createNativeEgress} from '../index.mjs';
import {createIngress} from './listener.mjs';
// Both host controller and this process must be explicitly enabled by a reviewed deployment.
const enabled=process.env.RUNLATER_NATIVE_EGRESS_ENABLED==='true';
const server=createIngress({enabled,revision:process.env.EGRESS_REVIEW_REVISION,adapter:createNativeEgress({enabled})});
server.listen(8080,'0.0.0.0');
process.once('SIGTERM',()=>{server.close();server.closeAllConnections();});
