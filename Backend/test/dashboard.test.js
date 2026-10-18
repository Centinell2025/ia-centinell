const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createHash, webcrypto } = require('node:crypto');
const { JSDOM, VirtualConsole } = require('jsdom');
const app = require('../server');
const server = app.listen(0, '127.0.0.1');
after(() => server.close());
const url = () => `http://127.0.0.1:${server.address().port}`;

test('serves dashboard without exposing backend/configuration files', async () => {
 const r = await fetch(url()); assert.equal(r.status,200); assert.match(await r.text(), /DEMO ONLY/);
 for(const path of ['/Backend/server.js','/Backend/.env.example','/.env','/unknown','/api/unknown']) assert.equal((await fetch(url()+path)).status,404);
 const health = await (await fetch(url()+'/api/health')).json(); assert.equal(health.ai,'unavailable'); assert.equal(health.mode,'demo');
});
test('unconfigured AI endpoints fail explicitly, not fabricated success', async () => {
 for(const path of ['/api/analyst/query','/api/shield/behavior','/api/ia-core/threat','/api/algo/solve']) {
  const r=await fetch(url()+path,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  assert.equal(r.status,503); assert.equal((await r.json()).available,false);
 }
});
test('local authenticated hash scan distinguishes empty file from EICAR', async () => {
 const r=await fetch(url()+'/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'demo@example.invalid',password:'local-test-only'})});
 assert.equal(r.status,201); const {token}=await r.json();
 for(const [content,expected] of [['','NO_TEST_SIGNATURE_MATCH'],['X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*','TEST_SIGNATURE_MATCH']]) {
  const form=new FormData();form.set('file',new Blob([content]),'test.txt');
  const result=await (await fetch(url()+'/api/shield/scan',{method:'POST',headers:{Authorization:`Bearer ${token}`},body:form})).json();
  assert.equal(result.verdict,expected);assert.equal(result.hash,createHash('sha256').update(content).digest('hex'));assert.equal(result.mode,'simulated');
 }
});
function dashboard() {
 const errors=[];const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
 const timers=[];
 const dom=new JSDOM(readFileSync(require.resolve('../../index.html'),'utf8'),{url:url(),runScripts:'dangerously',virtualConsole:vc,beforeParse(w){
  w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:webcrypto});
  w.setInterval=()=>1;w.clearInterval=()=>{};w.setTimeout=(fn,delay)=>{timers.push({fn,delay});return timers.length;};w.requestAnimationFrame=()=>1;w.cancelAnimationFrame=()=>{};
 }});return {dom,w:dom.window,errors,timers};
}
test('script initializes, navigation and true binary SHA-256 work', async () => {
 const {dom,w,errors,timers}=dashboard();
 try {
 assert.deepEqual(errors,[]);assert.equal(typeof w.runRemediation,'function');
 for(const bytes of [new Uint8Array([]),new Uint8Array([0,1,255]),new TextEncoder().encode('abc')]) assert.equal(await w.sha256(bytes.buffer),createHash('sha256').update(bytes).digest('hex'));
 assert.equal(await w.sha256('abc'),createHash('sha256').update('abc').digest('hex'));
 for(const page of w.document.querySelectorAll('.page')) { w.nav(page.id.slice(5));const navTimers=timers.splice(0).filter(t=>t.delay===150||t.delay===160);navTimers.forEach(t=>t.fn());assert.ok(page.classList.contains('active')); }
 await w.runRemediation();assert.match(w.document.getElementById('remOut').textContent,/AI unavailable/);
 w.document.getElementById('mainInput').value='<img src=x onerror=alert(1)>';
 await w.sendMain();assert.equal(w.document.querySelector('#mainChat img'),null);assert.match(w.document.getElementById('mainChat').textContent,/AI unavailable/);assert.equal(w.document.getElementById('mainBtn').disabled,false);
 w.nav('shield'); w.nav('guardian'); w.nav('bridge'); assert.equal(w.document.querySelector('.page.active').id,'page-bridge');
 assert.deepEqual(errors,[]);
 } finally {dom.window.close();}
});
test('file scan uses bytes; baseline labels need fresh selection and filenames are inert', async () => {
 const {dom,w,errors}=dashboard();try {
 const bytes=new TextEncoder().encode('file contents');const file={name:"file'<img src=x>.txt",size:bytes.length,lastModified:0,arrayBuffer:async()=>bytes.buffer};
 await w.processFileScan(file);assert.equal(w.document.getElementById('scanHash').textContent,createHash('sha256').update(bytes).digest('hex'));assert.match(w.document.getElementById('scanVerdict').textContent,/NOT A SAFETY VERDICT/);
 await w.addToBaseline({files:[file]});assert.equal(w.document.querySelector('#baselineList img'),null);assert.match(w.document.getElementById('baselineList').textContent,/file'/);
 await w.verifyBaseline();assert.match(w.document.getElementById('changeLog').textContent,/Select the current files/);
 let picker; const create=w.document.createElement.bind(w.document);
 w.document.createElement=(tag)=>{const el=create(tag);if(tag==='input'){picker=el;el.click=()=>{};}return el;};
 await w.verifyBaseline();Object.defineProperty(picker,'files',{value:[file],configurable:true});await picker.onchange();assert.match(w.document.getElementById('changeLog').textContent,/: MATCH/);
 Object.defineProperty(picker,'files',{value:[{...file,arrayBuffer:async()=>new TextEncoder().encode('changed').buffer}],configurable:true});await picker.onchange();assert.match(w.document.getElementById('changeLog').textContent,/: CHANGED/);
 w.document.querySelector('.remove-baseline').click();assert.equal(w.document.getElementById('baselineCount').textContent,'0');assert.deepEqual(errors,[]);
 } finally {dom.window.close();}
});
