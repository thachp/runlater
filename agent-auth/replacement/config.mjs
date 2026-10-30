import {agentAuth} from '@better-auth/agent-auth';
export const ORIGIN = 'https://mcp.runlater.io';
export const BASE = '/api/auth';
export function pluginOptions({onExecute,resolveAutonomousUser} = {}) {
  return {providerName:'RunLater',modes:['autonomous'],allowedKeyAlgorithms:['Ed25519'],
    allowDynamicHostRegistration:true,defaultHostCapabilities:['connection_status'],
    capabilities:[{name:'connection_status',description:'Inspect this agent connection. Does not create a project or grant scheduling access.'}],
    validateCapabilities: caps=>caps.every(c=>c==='connection_status'),
    jwtMaxAge:60,agentSessionTTL:3600,agentMaxLifetime:604800,absoluteLifetime:604800,
    resolveGrantTTL:()=>604800,jtiCacheStorage:'secondary-storage',jwksCacheStorage:'secondary-storage',
    resolveAutonomousUser,onExecute};
}
export function authOptions({database,secret,secondaryStorage,onExecute,resolveAutonomousUser,background} = {}) {
  return {baseURL:ORIGIN,basePath:BASE,database,secret,
    secondaryStorage,plugins:[agentAuth(pluginOptions({onExecute,resolveAutonomousUser}))],
    advanced:{backgroundTasks:{handler:background}},
    // Ingress/admission caps are enforced before dynamic registration. These
    // protocol limits add request throttling but do not prove one customer.
    rateLimit:{enabled:true,storage:'secondary-storage'},logger:{disabled:true}};
}
