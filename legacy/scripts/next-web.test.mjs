import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWebHandler,policy,security} from '../web/next/handler.mjs';
import {prepareWeb} from './build-web.mjs';
test('generated Next inputs retain source heads/bodies and exact public assets without source leakage',()=>{
 prepareWeb();
 for(const role of ['landing','docs']) {
  const root=`web/${role}`;
  const content=JSON.parse(fs.readFileSync(`${root}/app/content.json`));
  for(const [key,file] of [['home','index.html'],['missing','404.html']]) {
   const html=fs.readFileSync(`${root}/${file}`,'utf8');
   assert.equal(content[key].head,html.match(/<head>([\s\S]*?)<\/head>/)[1]);
   assert.equal(content[key].body,html.match(/<body>([\s\S]*?)<\/body>/)[1]);
  }
  for(const file of fs.readdirSync(`build/discovery/${role}`,{recursive:true})) {
   const source=`build/discovery/${role}/${file}`;
   if(!fs.statSync(source).isFile()||['index.html','404.html','_headers'].includes(file))continue;
   assert.deepEqual(fs.readFileSync(`${root}/public/${file}`),fs.readFileSync(source),file);
  }
  for(const file of ['wrangler.jsonc','package.json','worker-next.mjs','index.html','404.html','_headers'])assert.equal(fs.existsSync(`${root}/public/${file}`),false);
 }
});
test('canonicalization happens before Next or Assets for every method and encoded path',async()=>{
 const handler=createWebHandler('landing',{fetch(){throw Error('Next called')}});
 const env={ASSETS:{fetch(){throw Error('asset called')}}};
 for(const method of ['GET','HEAD','POST']) for(const path of ['/','/index.html','/site.css','/a%2Fb?x=1&x=2']) {
  const r=await handler.fetch(new Request('https://www.runlater.io'+path,{method}),env,{});
  assert.equal(r.status,308);assert.equal(r.headers.get('location'),'https://runlater.io'+path);
 }
 assert.equal((await handler.fetch(new Request('https://attacker.example/'),env,{})).status,404);
});
test('request HTML receives a fresh unspoofable nonce and no shared cache, assets stay byte-identical',async()=>{
 const seen=[];
 const handler=createWebHandler('docs',{fetch:async req=>{seen.push(req);return new Response('rendered',{status:404})}});
 const env={ASSETS:{fetch:async req=>new Response(req.url.endsWith('/site.css')?'exact bytes':'missing',{status:req.url.endsWith('/site.css')?200:404})}};
 for(let i=0;i<2;i++) {
  const r=await handler.fetch(new Request('https://docs.runlater.io/missing',{headers:{'x-nonce':'spoof','Content-Security-Policy':'spoof'}}),env,{});
  const nonce=seen[i].headers.get('x-nonce');assert.notEqual(nonce,'spoof');
  assert.equal(r.status,404);assert.equal(r.headers.get('Content-Security-Policy'),policy(nonce));
  assert.equal(r.headers.get('Cache-Control'),'private, no-store');
  for(const [key,value]of Object.entries(security))assert.equal(r.headers.get(key),value);
 }
 assert.notEqual(seen[0].headers.get('x-nonce'),seen[1].headers.get('x-nonce'));
 const css=await handler.fetch(new Request('https://docs.runlater.io/site.css'),env,{});
 assert.equal(await css.text(),'exact bytes');assert.equal(css.headers.get('Cache-Control'),'public, max-age=300');
 assert.equal(seen.length,2);
});
test('legacy index and 404 aliases preserve native static statuses and queries',async()=>{
 const handler=createWebHandler('landing',{fetch:async()=>new Response('original 404 content',{status:404})});
 const env={ASSETS:{fetch:async()=>new Response('missing',{status:404})}};
 for(const [path,location]of [['/index.html?q=x%20y','/?q=x%20y'],['/index?x=1','/?x=1'],['/404.html?x=1','/404?x=1'],['/404/','/404']]) {
  const r=await handler.fetch(new Request('https://runlater.io'+path),env,{});
  assert.equal(r.status,307);assert.equal(r.headers.get('location'),location);
 }
 assert.equal((await handler.fetch(new Request('https://runlater.io/404'),env,{})).status,200);
 assert.equal((await handler.fetch(new Request('https://runlater.io/missing'),env,{})).status,404);
});
