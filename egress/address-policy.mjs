// Conservative public-address profile. Review against IANA before enabling a deployment.
import {isIP} from 'node:net';
const v4Denied = [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.31.196.0',24],['192.52.193.0',24],['192.175.48.0',24],['192.88.99.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]];
const v6Denied = [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20],['2620:4f:8000::',48]];
export function addressNumber(address) {
 const family=isIP(address);if(!family||address.includes('%'))throw Error('invalid_address');
 if(family===4)return {family,bits:32,value:address.split('.').reduce((n,x)=>(n<<8n)+BigInt(x),0n)};
 // IPv4-in-IPv6 forms are deliberately refused, even if they embed a public address.
 if(address.includes('.'))throw Error('invalid_address');
 const halves=address.toLowerCase().split('::');if(halves.length>2)throw Error('invalid_address');
 const left=halves[0]?halves[0].split(':'):[],right=halves[1]?halves[1].split(':'):[];
 const words=halves.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
 if(words.length!==8)throw Error('invalid_address');
 return {family,bits:128,value:words.reduce((n,x)=>(n<<16n)+BigInt('0x'+x),0n)};
}
function inside(n,base,prefix){const b=addressNumber(base);return n.family===b.family&&(n.value>>BigInt(n.bits-prefix))===(b.value>>BigInt(n.bits-prefix));}
export function publicAddress(address){
 try{const n=addressNumber(address);
  if(n.family===4)return !v4Denied.some(([base,prefix])=>inside(n,base,prefix));
  // Positive global-unicast boundary rejects mapped/NAT64/ULA/link-local/multicast/future ranges.
  return inside(n,'2000::',3)&&!v6Denied.some(([base,prefix])=>inside(n,base,prefix));
 }catch{return false;}
}
export function sameAddress(a,b){try{const x=addressNumber(a),y=addressNumber(b);return x.family===y.family&&x.value===y.value;}catch{return false;}}
export function publicHostname(host){
 return typeof host==='string'&&host.length<=253&&host===host.toLowerCase()&&!isIP(host)
  &&host.split('.').length>=2&&host.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))
  &&!/(?:^|\.)(?:localhost|local|internal|home|onion|arpa|invalid|test)$/.test(host);
}
export function destinationURL(raw){
 if(typeof raw!=='string'||raw.length>2048||raw.includes('#')||!/^https:\/\/[\x21-\x7e]+$/.test(raw)||/[\\]/.test(raw)||/%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(raw))throw Error('destination_rejected');
 let u;try{u=new URL(raw);}catch{throw Error('destination_rejected');}
 if(u.href!==raw||u.protocol!=='https:'||u.username||u.password||u.port||u.hash||!publicHostname(u.hostname))throw Error('destination_rejected');
 return {hostname:u.hostname,path:raw.slice(u.origin.length)};
}
export async function resolvePublic(hostname,resolver,signal){
 if(!publicHostname(hostname))throw Error('dns_rejected');
 const seen=new Set(),addresses=new Map();let current=hostname;
 const lookup=async method=>{try{return await resolver[method](current);}catch(e){if(e?.code==='ENODATA')return [];throw Error('dns_rejected');}};
 for(let depth=0;depth<8;depth++){
  if(signal?.aborted||seen.has(current))throw Error('dns_rejected');seen.add(current);
  const [aliases,ipv4,ipv6]=await Promise.all([lookup('resolveCname'),lookup('resolve4'),lookup('resolve6')]);
  if(![aliases,ipv4,ipv6].every(Array.isArray)||aliases.length>1||ipv4.length+ipv6.length>16)throw Error('dns_rejected');
  for(const [items,family]of [[ipv4,4],[ipv6,6]])for(const address of items){
   if(!publicAddress(address)||isIP(address)!==family)throw Error('dns_rejected');addresses.set(address,{address,family});
  }
  if(addresses.size>16)throw Error('dns_rejected');
  if(!aliases.length){if(!addresses.size)throw Error('dns_rejected');return [...addresses.values()];}
  const alias=aliases[0];if(!publicHostname(alias))throw Error('dns_rejected');current=alias;
 }
 throw Error('dns_rejected');
}
