// Real Chromium + production workerd; no public network access or live API calls.
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-next-browser-'));
fs.mkdirSync('build/web-qa',{recursive:true});
const browser=await chromium.launch({headless:true});
let assets=0;
try {for(const [role,port,host]of [['landing',14183,'runlater.io'],['docs',14184,'docs.runlater.io']]) {
 const log=fs.openSync(path.join(tmp,role+'.log'),'w');
 const child=spawn(path.resolve('node_modules/.bin/wrangler'),['dev','--local','--config',`web/${role}/wrangler.jsonc`,'--ip','127.0.0.1','--port',String(port),'--host',host,'--upstream-protocol','https','--inspector-port','0','--persist-to',path.join(tmp,role),'--show-interactive-dev-session','false'],{stdio:['ignore',log,log],detached:true,env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',WRANGLER_LOG_PATH:path.join(tmp,role+'-wrangler.log')}});
 try {
  const base=`http://127.0.0.1:${port}`;
  let ready=false;for(let n=0;n<80;n++){try{if((await fetch(base,{signal:AbortSignal.timeout(500)})).ok){ready=true;break}}catch{}await delay(250)}
  assert.ok(ready,fs.readFileSync(path.join(tmp,role+'.log'),'utf8'));
  for(const file of fs.readdirSync(`build/discovery/${role}`,{recursive:true})) {
   const source=`build/discovery/${role}/${file}`;
   if(!fs.statSync(source).isFile()||['index.html','404.html','_headers'].includes(file))continue;
   const r=await fetch(`${base}/${file}`);assert.equal(r.status,200,file);
   assert.deepEqual(Buffer.from(await r.arrayBuffer()),fs.readFileSync(source),file);assets++;
  }
  const context=await browser.newContext({viewport:{width:1440,height:1000},permissions:['clipboard-read','clipboard-write']});
  const page=await context.newPage();const failures=[];const external=[];
  await page.route('**/*',route=>{if(new URL(route.request().url()).origin!==base){external.push(route.request().url());return route.abort()}return route.continue()});
  page.on('pageerror',e=>failures.push(e.message));
  page.on('console',m=>{if(m.type()==='error'&&!m.text().includes('the server responded with a status of 404'))failures.push(m.text())});
  await page.addInitScript(()=>{window.cspViolations=[];document.addEventListener('securitypolicyviolation',e=>window.cspViolations.push(e.violatedDirective+':'+e.blockedURI))});
  const response=await page.goto(base);await page.waitForLoadState('networkidle');
  assert.equal(response.status(),200);
  const csp=response.headers()['content-security-policy'];assert.match(csp,/nonce-/);assert.doesNotMatch(csp,/unsafe-inline|unsafe-eval/);
  const source=fs.readFileSync(`web/${role}/index.html`,'utf8');
  const parity=await page.evaluate(html=>{
   const original=new DOMParser().parseFromString(html,'text/html');
   const collect=d=>({title:d.title,meta:[...d.querySelectorAll('meta[name="description"],meta[property],link[rel="canonical"],link[rel="alternate"]')].map(x=>x.outerHTML).sort(),code:[...d.querySelectorAll('main pre')].map(x=>x.textContent),links:[...d.querySelectorAll('a')].map(x=>[x.getAttribute('href'),x.textContent]),ids:[...d.querySelectorAll('main [id],main[id]')].map(x=>x.id)});
   return {source:collect(original),actual:collect(document)};
  },source);
  assert.deepEqual(parity.actual,parity.source,role+' DOM/SEO parity');
  assert.equal(await page.locator('meta[name=viewport]').count(),1,'single viewport');
  assert.equal(await page.locator('meta[charset]').count(),1,'single charset');
  if(role==='docs') {
   const copy=page.locator('[data-copy="http-code"]');await copy.waitFor({state:'visible'});await copy.click();
   await page.waitForFunction(()=>document.getElementById('copy-status').textContent==='Code copied to clipboard');
   assert.equal(await page.locator('#copy-status').textContent(),'Code copied to clipboard');
   assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),await page.locator('#http-code').textContent());
   await page.locator('.sidebar a[href="#connect"]').click();assert.equal(new URL(page.url()).hash,'#connect');
  }else {assert.equal(await page.locator('a.button').first().getAttribute('href'),'https://docs.runlater.io/#connect');await page.locator('.nav a[href="#how-it-works"]').click();assert.equal(new URL(page.url()).hash,'#how-it-works');}
  await page.goto(base);await page.keyboard.press('Tab');assert.equal(await page.locator(':focus').getAttribute('href'),'#main');await page.keyboard.press('Enter');assert.equal(new URL(page.url()).hash,'#main');await page.screenshot({path:`build/web-qa/${role}-desktop.png`,fullPage:true});
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:`build/web-qa/${role}-mobile.png`,fullPage:true});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),role+' mobile overflow');
  await page.setViewportSize({width:320,height:780});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),role+' narrow overflow');
  assert.deepEqual(await page.evaluate(()=>window.cspViolations),[]);assert.deepEqual(external,[]);assert.deepEqual(failures,[]);
  const missing=await page.goto(base+'/missing/deep-link');assert.equal(missing.status(),404);assert.equal(await page.locator('h1').textContent(),'This page isn’t here.');
  assert.deepEqual(await page.evaluate(()=>window.cspViolations),[]);assert.deepEqual(failures,[]);
  const head=await fetch(base,{method:'HEAD'});assert.equal(head.status,200);assert.equal(await head.text(),'');
  console.log(JSON.stringify({role,browser:'Chromium',runtime:'production OpenNext + workerd',seo_content_links:'equal',clipboard:role==='docs',mobile:'390px no overflow',csp_errors:failures.length,external_requests:external.length,not_found:404}));
  await context.close();
 } finally {try{process.kill(-child.pid,'SIGTERM')}catch{}await Promise.race([new Promise(resolve=>child.once('exit',resolve)),delay(2000)]);try{process.kill(-child.pid,'SIGKILL')}catch{}fs.closeSync(log)}
}console.log(JSON.stringify({asset_bytes_verified:assets,screenshots:'build/web-qa',remote_calls:0}));}
finally {await browser.close()}
