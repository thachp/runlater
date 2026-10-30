// Build both independent Next.js applications; no uploads, provisioning or network calls.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {buildDiscovery} from './discovery.mjs';
export const repo = fileURLToPath(new URL('../', import.meta.url));
export function prepareWeb() {
 const {output} = buildDiscovery();
 for (const role of ['landing', 'docs']) {
  const root = path.join(repo, 'web', role);
  for (const name of ['app', 'public']) fs.rmSync(path.join(root, name), {recursive:true, force:true});
  fs.cpSync(path.join(repo,'web/next/app'),path.join(root,'app'),{recursive:true});
  fs.cpSync(path.join(output,role),path.join(root,'public'),{recursive:true});
  for(const name of ['index.html','404.html','_headers']) fs.rmSync(path.join(root,'public',name));
  // Only repository-owned HTML is parsed, never request or user content.
  const pages={};
  for(const [key,file] of [['home','index.html'],['missing','404.html']]) {
   const html=fs.readFileSync(path.join(root,file),'utf8');
   pages[key]={head:html.match(/<head>([\s\S]*?)<\/head>/)[1],body:html.match(/<body>([\s\S]*?)<\/body>/)[1]};
  }
  fs.writeFileSync(path.join(root,'app/content.json'),JSON.stringify(pages));
  for(const name of ['next.config.mjs','open-next.config.ts']) fs.copyFileSync(path.join(repo,'web/next',name),path.join(root,name));
  fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'runlater-web-'+role,private:true,scripts:{build:'next build --webpack'},dependencies:JSON.parse(fs.readFileSync(path.join(repo,'package.json'))).dependencies},null,2));
 }
}
export function buildWeb() {
 prepareWeb();
 for(const role of ['landing','docs']) {
  const result=spawnSync(path.join(repo,'node_modules/.bin/opennextjs-cloudflare'),['build'],{cwd:path.join(repo,'web',role),stdio:'inherit',env:{...process.env,NEXT_TELEMETRY_DISABLED:'1',WRANGLER_SEND_METRICS:'false'}});
  if(result.status!==0) throw Error(`${role} OpenNext build failed (${result.status})`);
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) buildWeb();
