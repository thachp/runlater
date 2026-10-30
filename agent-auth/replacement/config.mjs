import {agentAuth} from '@better-auth/agent-auth';
export const ORIGIN = 'https://mcp.runlater.io';
export const BASE = '/api/auth';
const defaultCapabilities=[{name:'connection_status',description:'Inspect this agent connection. Does not create a project or grant scheduling access.'}];
export function pluginOptions({onExecute,resolveAutonomousUser,capabilities=defaultCapabilities} = {}) {
  return {providerName:'RunLater',modes:['autonomous'],allowedKeyAlgorithms:['Ed25519'],
    allowDynamicHostRegistration:true,defaultHostCapabilities:capabilities.map(c=>c.name),
    capabilities,validateCapabilities:caps=>caps.every(c=>capabilities.some(def=>def.name===c)),
    jwtMaxAge:60,agentSessionTTL:3600,agentMaxLifetime:604800,absoluteLifetime:604800,
    resolveGrantTTL:()=>604800,jtiCacheStorage:'secondary-storage',jwksCacheStorage:'secondary-storage',
    resolveAutonomousUser,onExecute};
}
export function authOptions({database,secret,secondaryStorage,onExecute,resolveAutonomousUser,background,capabilities} = {}) {
  return {baseURL:ORIGIN,basePath:BASE,database,secret,
    secondaryStorage,plugins:[agentAuth(pluginOptions({onExecute,resolveAutonomousUser,capabilities}))],
    advanced:{backgroundTasks:{handler:background}},
    // Ingress/admission caps are enforced before dynamic registration. These
    // protocol limits add request throttling but do not prove one customer.
    rateLimit:{enabled:true,storage:'secondary-storage'},logger:{disabled:true}};
}
