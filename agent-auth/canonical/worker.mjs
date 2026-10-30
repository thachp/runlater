import replacement,{createAgentAuthHub} from '../replacement/worker.mjs';
import {CanonicalProjects,capabilities,apiClientFactory} from './projects.mjs';
const projectStore=({env,storage})=>new CanonicalProjects({storage,releaseId:env.MCP_RELEASE_ID,clientFor:(authority,revoke)=>apiClientFactory(env)(authority,revoke)});
export const CanonicalAgentAuth=createAgentAuthHub({capabilities,additionalReady:env=>env.CANONICAL_AGENT_AUTH_ENABLED==='operator-approved',
 onExecute:async input=>projectStore(input).execute(input.agentSession.agent.hostId,input.capability,input.arguments),
 onHostRevoked:async input=>projectStore(input).tombstone(input.hostId,{hostRevoked:true}),
 onAlarm:async input=>projectStore(input).cleanup()});
export default {fetch(request,env){
 if(env.CANONICAL_AGENT_AUTH_ENABLED!=='operator-approved')return Response.json({error:'canonical_agent_auth_disabled'},{status:503});
 // No deployment entrypoint/binding is configured by this source-only slice.
 return replacement.fetch(request,env);
}};
