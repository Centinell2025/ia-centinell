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

test('overlapping scans preserve the newest file, hash, verdict and operation count', async () => {
 const {dom,w}=dashboard();try {
 let resolveA;const a=w.processFileScan({name:'a.txt',size:1,lastModified:0,arrayBuffer:()=>new Promise(r=>resolveA=r)});
 const bBytes=new TextEncoder().encode('b');
 await w.processFileScan({name:'b.txt',size:1,lastModified:0,arrayBuffer:async()=>bBytes.buffer});
 resolveA(new TextEncoder().encode('a').buffer);await a;
 assert.equal(w.document.getElementById('scanFileName').textContent,'b.txt');
 assert.equal(w.document.getElementById('scanHash').textContent,createHash('sha256').update('b').digest('hex'));
 assert.equal(w.document.getElementById('shieldOps').textContent,'1');
 let rejectOld;const old=w.processFileScan({name:'old.txt',size:1,lastModified:0,arrayBuffer:()=>new Promise((_,r)=>rejectOld=r)});
 assert.equal(w.document.getElementById('scanHash').textContent,'');assert.equal(w.document.getElementById('scanVerdict').textContent,'SCANNING');
 await w.processFileScan({name:'new.txt',size:1,lastModified:0,arrayBuffer:async()=>bBytes.buffer});rejectOld(new Error('old read failed'));await old;
 assert.equal(w.document.getElementById('scanFileName').textContent,'new.txt');assert.match(w.document.getElementById('scanVerdict').textContent,/NOT A SAFETY VERDICT/);
 await w.processFileScan({name:'bad.txt',size:1,lastModified:0,arrayBuffer:async()=>{throw Error('unreadable');}});assert.equal(w.document.getElementById('scanHash').textContent,'');assert.match(w.document.getElementById('scanVerdict').textContent,/SCAN FAILED/);
 } finally {dom.window.close();}
});
test('overlapping file hashes are latest-wins per output, including late read failures', async () => {
 const {dom,w}=dashboard();try {
 for(const id of ['testHash','testInfo','secondHash','secondInfo']) {const el=w.document.createElement('div');el.id=id;w.document.body.appendChild(el);}
 const makeFile=(name,read)=>({name,size:1,arrayBuffer:read});let resolveA;
 const a=w.hashFile({files:[makeFile('a.txt',()=>new Promise(r=>resolveA=r))]},'testHash','testInfo');
 const bytes=new TextEncoder().encode('b');
 await w.hashFile({files:[makeFile('b.txt',async()=>bytes.buffer)]},'testHash','testInfo');
 await w.hashFile({files:[makeFile('other.txt',async()=>new TextEncoder().encode('c').buffer)]},'secondHash','secondInfo');
 resolveA(new TextEncoder().encode('a').buffer);await a;
 assert.match(w.document.getElementById('testInfo').textContent,/b.txt/);assert.equal(w.document.getElementById('testHash').textContent,'SHA-256: '+createHash('sha256').update('b').digest('hex'));
 assert.equal(w.document.getElementById('secondHash').textContent,'SHA-256: '+createHash('sha256').update('c').digest('hex'));
 let rejectA;const old=w.hashFile({files:[makeFile('old.txt',()=>new Promise((_,r)=>rejectA=r))]},'testHash','testInfo');
 assert.equal(w.document.getElementById('testHash').textContent,'COMPUTING SHA-256...');
 await w.hashFile({files:[makeFile('new.txt',async()=>bytes.buffer)]},'testHash','testInfo');rejectA(Error('old read failed'));await old;
 assert.match(w.document.getElementById('testInfo').textContent,/new.txt/);assert.equal(w.document.getElementById('testHash').textContent,'SHA-256: '+createHash('sha256').update('b').digest('hex'));
 } finally {dom.window.close();}
});
test('late digest completions cannot replace newer scan or hash results', async () => {
 const {dom,w}=dashboard();try {
 let pending=[];w.sha256=()=>new Promise(resolve=>pending.push(resolve));
 const file=name=>({name,size:1,lastModified:0,arrayBuffer:async()=>new ArrayBuffer(1)});
 const a=w.processFileScan(file('a.txt'));await new Promise(setImmediate);const resolveA=pending.shift();
 const b=w.processFileScan(file('b.txt'));await new Promise(setImmediate);pending.shift()('hash-b');await b;resolveA('hash-a');await a;
 assert.equal(w.document.getElementById('scanHash').textContent,'hash-b');assert.equal(w.document.getElementById('scanFileName').textContent,'b.txt');
 for(const id of ['lateHash','lateInfo']) {const el=w.document.createElement('div');el.id=id;w.document.body.appendChild(el);}
 const c=w.hashFile({files:[file('c.txt')]},'lateHash','lateInfo');await new Promise(setImmediate);const resolveC=pending.shift();
 const d=w.hashFile({files:[file('d.txt')]},'lateHash','lateInfo');await new Promise(setImmediate);pending.shift()('hash-d');await d;resolveC('hash-c');await c;
 assert.equal(w.document.getElementById('lateHash').textContent,'SHA-256: hash-d');assert.match(w.document.getElementById('lateInfo').textContent,/d.txt/);
 }finally{dom.window.close();}
});
