const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {webcrypto,createHash}=require('node:crypto');
const {File}=require('node:buffer');
const vm=require('node:vm');
const html=readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];

// Run the shipped script without boot timers or external requests. Each test
// receives fresh state and invokes the actual shipped handlers.
function workspace(){
  const elements=new Map();
  function element(){return {value:'',textContent:'',innerHTML:'',disabled:false,style:{},children:[],classList:{add(){},remove(){},toggle(){}},appendChild(child){this.children.push(child);}};}
  const document={getElementById(id){if(!elements.has(id))elements.set(id,element());return elements.get(id);},createElement:element};
  let networkCalls=0;
  const context={document,crypto:webcrypto,TextEncoder,Uint8Array,ArrayBuffer,console,setTimeout(){return 0;},setInterval(){return 0;},clearTimeout(){},clearInterval(){},cancelAnimationFrame(){},fetch(){networkCalls++;throw Error('Unexpected external request');},alert(){throw Error('Unexpected alert');}};
  context.window=context;vm.createContext(context);vm.runInContext(source,context);
  return {context,get:document.getElementById.bind(document),get networkCalls(){return networkCalls;}};
}
const expected=bytes=>createHash('sha256').update(bytes).digest('hex');

test('the inline script loads and the visible remediation control has a handler',()=>{
  const w=workspace();assert.equal(typeof w.context.runRemediation,'function');assert.match(html,/id="remBtn" onclick="runRemediation\(\)"/);assert.equal(w.networkCalls,0);
});
test('known SHA-256 vectors preserve UTF-8 text hashing',async()=>{
  const {context:c}=workspace();
  assert.equal(await c.sha256(''),'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(await c.sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await c.sha256('León 海'),expected(Buffer.from('León 海','utf8')));
});
test('two distinct files produce their actual, different hashes in the scanner',async()=>{
  const w=workspace(),a=new File(['first distinct file'],'first.txt'),b=new File(['second distinct file'],'second.txt');
  await w.context.processFileScan(a);const first=w.get('scanHash').textContent;
  await w.context.processFileScan(b);const second=w.get('scanHash').textContent;
  assert.equal(first,expected('first distinct file'));assert.equal(second,expected('second distinct file'));assert.notEqual(first,second);assert.equal(w.networkCalls,0);
});
test('the baseline stores original binary content instead of an ArrayBuffer string',async()=>{
  const w=workspace(),a=new File([Uint8Array.of(0,255,128,1)],'binary-a.bin'),b=new File([Uint8Array.of(1,128,255,0)],'binary-b.bin');
  await w.context.addToBaseline({files:[a,b]});
  assert.equal(vm.runInContext("baselineFiles.get('binary-a.bin').hash",w.context),expected(Buffer.from([0,255,128,1])));
  assert.equal(vm.runInContext("baselineFiles.get('binary-b.bin').hash",w.context),expected(Buffer.from([1,128,255,0])));
});
test('typed-array slices hash only their visible bytes and invalid objects are rejected',async()=>{
  const {context:c}=workspace(),bytes=Uint8Array.of(99,97,98,99,88),view=bytes.subarray(1,4);
  assert.equal(await c.sha256(view),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await c.sha256(new DataView(bytes.buffer,1,3)),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  await assert.rejects(()=>c.sha256({}),/ArrayBuffer|BufferSource|ArrayBufferView|TypedArray/);
});
test('the guide rejects blank descriptions and demo keys without calling a provider',async()=>{
  const w=workspace();await w.context.runRemediation();assert.match(w.get('remOut').textContent,/Describe the threat/);
  w.get('remediationInput').value='Fictional incident for review.';
  for(const key of ['', 'demo-key','demo-key-for-sales']){w.get('globalKey').value=key;await w.context.runRemediation();assert.match(w.get('remOut').textContent,/No request was sent/);}
  assert.equal(w.networkCalls,0);assert.equal(w.get('remBtn').disabled,false);
});
test('the guide uses the existing AI helper, displays text and leaves quarantine unchanged',async()=>{
  const w=workspace();w.get('globalKey').value='test-key-not-a-real-credential';w.get('remediationInput').value='Fictional incident for review.';let request;
  w.context.iaAsk=async(key,system,description)=>{request={key,system,description};assert.equal(w.get('remBtn').disabled,true);return '<script>untrusted provider text</script> Review evidence before proceeding.';};
  await w.context.runRemediation();assert.equal(request.description,'Fictional incident for review.');assert.match(request.system,/cannot execute remediation/);assert.match(w.get('remOut').textContent,/GUIDANCE ONLY/);assert.equal(w.get('remOut').innerHTML,'');assert.equal(w.get('remBtn').disabled,false);assert.equal(w.get('remBtn').textContent,'GET GUIDE');
  assert.equal(vm.runInContext('quarantineItems.length',w.context),0);assert.equal(vm.runInContext('qCleaned',w.context),0);assert.equal(w.networkCalls,0);
});
test('provider errors and empty answers recover the guide button without claiming action',async()=>{
  const w=workspace();w.get('globalKey').value='test-key-not-a-real-credential';w.get('remediationInput').value='Fictional incident.';
  for(const answer of [null,'']){w.context.iaAsk=async()=>{if(answer===null)throw Error('Provider unavailable');return answer;};await w.context.runRemediation();assert.match(w.get('remOut').textContent,/Unable to generate a guide/);assert.match(w.get('remOut').textContent,/No remediation actions were executed/);assert.equal(w.get('remBtn').disabled,false);}
});

test('all existing analyzers reject both demo markers before any external request',async()=>{
  const analyzers=['runBehavior','runReputation','runNetAnalysis','runFirewall','runFileBehavior','runSysInt','askAI11','runForensic','runEthics','runBias','runCompliance','runThreat','generatePlaybook','runIR','sendMain','runAlgo','runDebate','runOptimize'];
  for(const key of ['demo-key','demo-key-for-sales']){
    const w=workspace();let alerts=0;w.context.alert=()=>alerts++;w.get('globalKey').value=key;
    for(const name of analyzers)await w.context[name]();assert.equal(alerts,analyzers.length);
    await w.context.processFileScan(new File(['abc'],'local-only.txt'));
    assert.match(w.get('scanAnalysis').textContent,/Enter AI key/);assert.equal(w.networkCalls,0);
  }
});
test('both AI helpers reject demo markers and preserve the real-key request path',async()=>{
  const w=workspace();for(const key of ['demo-key','demo-key-for-sales',' demo-key-for-sales ','']){
    await assert.rejects(()=>w.context.iaAsk(key,'system','message'),/No request was sent/);
    await assert.rejects(()=>w.context.iaChat(key,'system',[{role:'user',content:'message'}]),/No request was sent/);
  }assert.equal(w.networkCalls,0);
  const calls=[];w.context.fetch=async(url,options)=>{calls.push({url,options});return {json:async()=>({content:[{text:'Stubbed provider response'}]})};};
  assert.equal(await w.context.iaAsk('test-key-not-a-real-credential','system','message'),'Stubbed provider response');
  assert.equal(await w.context.iaChat('test-key-not-a-real-credential','system',[{role:'user',content:'message'}]),'Stubbed provider response');
  assert.equal(calls.length,2);for(const call of calls){assert.equal(call.url,'https://api.anthropic.com/v1/messages');assert.equal(call.options.headers['x-api-key'],'test-key-not-a-real-credential');assert.equal(JSON.parse(call.options.body).model,'claude-sonnet-4-20250514');}
});
test('frontend scanner does not label empty bytes or plain text as EICAR or WannaCry',async()=>{
  const w=workspace();for(const [name,content] of [['empty.txt',''],['sentence.txt','The quick brown fox jumps over the lazy dog']]){
    await w.context.processFileScan(new File([content],name));assert.equal(w.get('scanHash').textContent,expected(content));assert.doesNotMatch(w.get('scanVerdict').textContent,/THREAT DETECTED/);assert.doesNotMatch(w.get('scanAnalysis').textContent,/EICAR|WannaCry/);
  }assert.equal(vm.runInContext('quarantineItems.length',w.context),0);assert.equal(w.networkCalls,0);
});

function backendScanHandler(){
  const routes=new Map(),app={use(){},post(path,...handlers){routes.set('POST '+path,handlers);},get(){},put(){},listen(){}};
  const express=()=>app;express.json=express.urlencoded=express.static=()=>()=>{};
  const multer=()=>({single:()=>()=>{}});multer.memoryStorage=()=>({});
  const modules={dotenv:{config(){}},express,cors:()=>()=>{},path:require('node:path'),jsonwebtoken:{},bcryptjs:{},multer,uuid:{v4:()=> 'test-local-id'},crypto:require('node:crypto')};
  const c={require(name){assert(Object.hasOwn(modules,name),'Unexpected dependency '+name);return modules[name];},process:{env:{}},__dirname:require('node:path').join(__dirname,'../Backend'),console,Buffer};
  vm.runInNewContext(readFileSync(require('node:path').join(__dirname,'../Backend/server.js'),'utf8'),c);
  return routes.get('POST /api/shield/scan').at(-1);
}
test('backend scanner does not classify empty bytes or the plain sentence as threats',async()=>{
  const handler=backendScanHandler();for(const content of ['', 'The quick brown fox jumps over the lazy dog']){
    const buffer=Buffer.from(content);let result;await handler({file:{originalname:'synthetic-regression.txt',buffer,size:buffer.length}},{json(value){result=value;}});
    assert.equal(result.hash,expected(content));assert.equal(result.isMalicious,false);assert.equal(result.signature,null);assert.notEqual(result.verdict,'THREAT_DETECTED');
  }
});
