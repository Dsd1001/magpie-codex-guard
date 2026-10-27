import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {JSDOM} from 'jsdom';

const html=await readFile(new URL('../internal/check/web/index.html',import.meta.url),'utf8');
const js=await readFile(new URL('../internal/check/web/assets/app.js',import.meta.url),'utf8');

function fixture({modelsError='',apiUpstream=false}={}){
 const calls=[];
 const state={
  state:{
   config:{gateway_url:'http://127.0.0.1:3425',daily_limit:600},
   route:{schedule_enabled:false,auto_apply:false,expected_codex_count:2,probe_key_id:'probe'},
   holds:{},
   account_targets:{},
   account_results:[],
   auto_prompt_policy:{configured:false,rotate:true,prompt_ids:['milk'],fingerprint_mode:'off'},
   timing_policy:{
    normal_seconds:1800,suspect_seconds:120,quarantine_first_seconds:21600,
    quarantine_repeat_seconds:86400,recovery_seconds:120,unavailable_seconds:1800,
    request_timeout_seconds:180,scan_seconds:60
   },
   custom_prompts:[],
  },
  health:'',
  gateway_configured:false,
  accounts:[
   {id:'aaa',user:'a@example.com'},
   {id:'bbb',user:'<img src=x onerror=alert(1)>@example.com'},
  ],
  keys:[{id:'probe',name:'Detection'}, {id:'prod',name:'Business'}],
  prompts:[{id:'model-fingerprint',kind:'fingerprint',name:'模型指纹检测',automatic:false},{id:'milk',name:'牛奶推理',kind:'objective',automatic:true}],
 };
 if(apiUpstream)state.accounts.push({id:'api-test',user:'Example · API',provider:'example'});
 const dom=new JSDOM(html,{url:'http://127.0.0.1:3344/',runScripts:'outside-only'});
 const w=dom.window;
 w.HTMLElement.prototype.scrollIntoView=()=>{};
 w.confirm=()=>true;
 w.prompt=()=>''; // emergency restore refused without explicit typed phrase
 w.fetch=async (path,options={})=>{
  calls.push({path,options});
  let payload;
  const method=options.method||'GET';
  if(path==='/api/state')payload=state;
  else if(path==='/api/models'){
   if(modelsError)return {ok:false,status:503,text:async()=>modelsError};
   payload=[{id:'codex/gpt-6.1-sol',group:'codex'}];
   if(apiUpstream)payload.push({id:'example/gpt-6.1-sol',group:'example'});
  }
  else if(path==='/api/fingerprint-models')payload=[{id:'gpt-6-astra',name:'gpt-6-astra/6.1-sol'},{id:'gpt-6-sol',name:'gpt-6-sol'}];
  else if(path==='/api/timing'&&method==='POST'){
   const req=JSON.parse(options.body);
   if(req.account){
    const t=state.state.account_targets[req.account+'\x1f'+req.model];
    t.timing_override=req.inherit?null:req.policy;
   }else state.state.timing_policy=req.policy;
   payload={ok:true};
  }
  else if(path==='/api/fingerprint-expected'&&method==='POST'){
   const req=JSON.parse(options.body);
   const target=state.state.account_targets[req.account+'\x1f'+req.model];
   if(target)target.fingerprint_expected=req.expected;
   payload={ok:true};
  }
  else if(path==='/api/account-targets/sync'&&method==='POST'){
   state.state.account_targets['aaa\x1fcodex/gpt-6.1-sol']??={account:'aaa',model:'codex/gpt-6.1-sol',enabled:true,state:'passed'};
   payload={live_count:2,added:0,missing:0,restored:0};
  }
  else if(path==='/api/account-targets/auto-sync'&&method==='POST'){
   state.state.route.auto_sync_accounts=Boolean(JSON.parse(options.body).enabled);
   payload={enabled:state.state.route.auto_sync_accounts};
  }
  else if(path==='/api/routing/adopt-current'&&method==='POST'){
   state.state.route.last_error='';
   payload={mode:'active',keys:[],quarantined:[]};
  }
  else if(path==='/api/config'&&method==='POST'){
   state.gateway_configured=true;
   state.state.config.gateway_url=JSON.parse(options.body).gateway_url;
   payload={ok:true};
  }
  else if(path==='/api/account-target'&&method==='POST'){
   const t=JSON.parse(options.body);
   state.state.account_targets[t.account+'\x1f'+t.model]={...t,state:'unverified',consecutive_fails:0,consecutive_passes:0};
   payload={ok:true};
  }else if(path==='/api/auto-prompts'&&method==='POST'){
   const selected=JSON.parse(options.body);
   state.state.auto_prompt_policy={...selected,configured:true};
   payload=state.state.auto_prompt_policy;
  }else if(path==='/api/routing/preview') {
   payload={mode:'observe_only',quarantined:[],keys:[
    {key_id:'probe',before:[],after:[],is_probe:true,off_before:false,off_after:false},
    {key_id:'prod',before:[],after:[],is_probe:false,off_before:false,off_after:true},
   ]};
  }else payload={ok:true};
  return {ok:true,status:200,json:async()=>payload,text:async()=>JSON.stringify(payload)};
 };
 w.eval(js);
 return {dom,w,calls,state};
}
async function waitFor(fn,attempts=60){
 for(let i=0;i<attempts;i++){
  if(fn())return;
  await new Promise(r=>setTimeout(r,10));
 }
 assert.fail('UI was not updated');
}
test('dashboard renders safely and triggers account-scoped APIs',async()=>{
 const {dom,w,calls,state}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="codex/gpt-6.1-sol"]'));
  assert.equal(w.document.querySelector('#statAccounts').textContent,'0');
  assert.match(w.document.querySelector('#modelHelp').textContent,/已读取 Magpie 的 1 个检测模型/);
  assert.match(w.document.querySelector('#modelHelp').textContent,/独立检测 Gateway Key/);
  assert.equal(w.document.querySelector('#addAccount').disabled,false);
  const selects=w.document.querySelector('#accountSelect');
  assert.equal(selects.options[2].text,'<img src=x onerror=alert(1)>@example.com');
  assert.equal(w.document.querySelector('img'),null,'untrusted account name MUST remain text, not HTML');

  selects.value='aaa';
  w.document.querySelector('#modelSelect').value='codex/gpt-6.1-sol';
  w.document.querySelector('#addAccount').click();
  await waitFor(()=>w.document.querySelector('#statAccounts').textContent==='1');
  assert.equal(Object.values(state.state.account_targets).length,1);
  assert.equal(w.document.querySelector('#accountRows tr td').textContent,'a@example.com');
  assert.ok(calls.some(c=>c.path==='/api/account-target'&&c.options.method==='POST'));
  w.document.querySelector('[data-tab="history"]').click();
  assert.equal(w.document.querySelector('#history').hidden,false);
  assert.equal(w.document.querySelector('#accounts').hidden,true);
  w.document.querySelector('[data-tab="rules"]').click();
  assert.equal(w.document.querySelector('#rules').hidden,false);
  w.document.querySelector('#saveAutoPrompts').click();
  await waitFor(()=>calls.some(c=>c.path==='/api/auto-prompts'));
  await new Promise(resolve=>setTimeout(resolve,65));
 }finally{dom.window.close()}
});
test('route preview reports disabled keys and never serializes raw secrets',async()=>{
 const {dom,w}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#liveStatus').textContent.includes('观察'));
  w.document.querySelector('[data-tab="settings"]').click();
  w.document.querySelector('#previewRoute').click();
  await waitFor(()=>w.document.querySelector('#routePreview').hidden===false);
  assert.match(w.document.querySelector('#routePreview').textContent,/Business/);
  assert.doesNotMatch(w.document.querySelector('#routePreview').textContent,/SECRET/);
  assert.match(w.document.querySelector('#routePreview').textContent,/暂时停用/);
  await new Promise(resolve=>setTimeout(resolve,65));
 }finally{dom.window.close()}
});

test('API upstream enrollment uses the selected provider model and stable identity',async()=>{
 const {dom,w,calls}=fixture({apiUpstream:true});
 try{
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="example/gpt-6.1-sol"]'));
  assert.equal(w.document.querySelector('#accountSelect option[value="api-test"]').textContent,'Example · API');
  w.document.querySelector('#accountSelect').value='api-test';
  w.document.querySelector('#modelSelect').value='example/gpt-6.1-sol';
  w.document.querySelector('#addAccount').click();
  await waitFor(()=>w.document.querySelector('#accountRows').textContent.includes('Example · API'));
  const request=calls.find(c=>c.path==='/api/account-target'&&c.options.method==='POST');
  assert.deepEqual(JSON.parse(request.options.body),{account:'api-test',model:'example/gpt-6.1-sol',enabled:true});
  assert.match(w.document.querySelector('#accountRows').textContent,/example\/gpt-6\.1-sol/);
 }finally{dom.window.close()}
});

test('model loading errors are visible, not silently replaced with a gateway placeholder',async()=>{
 const {dom,w,calls}=fixture({modelsError:'本机 Magpie 模型目录查询失败'});
 try{
  const help=w.document.querySelector('#modelHelp');
  await waitFor(()=>help.textContent.includes('本机 Magpie 模型目录查询失败'));
  assert.match(help.textContent,/模型加载失败/);
  assert.equal(help.classList.contains('error'),true);
  assert.equal(w.document.querySelector('#addAccount').disabled,true);
  assert.equal(w.document.querySelector('#modelSelect').options.length,1);
  assert.doesNotMatch(w.document.querySelector('#modelSelect').textContent,/先保存网关/);
  w.document.querySelector('#refresh').click();
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('模型加载失败'));
  assert.ok(calls.filter(c=>c.path==='/api/models').length>=2,'refresh must retry the model catalog');
 }finally{dom.window.close()}
});

test('saving the connection reports catalog failure instead of a false success',async()=>{
 const {dom,w,calls}=fixture({modelsError:'Magpie 模型列表 HTTP 502'});
 try{
  await waitFor(()=>w.document.querySelector('#modelHelp').textContent.includes('HTTP 502'));
  w.document.querySelector('[data-tab="settings"]').click();
  w.document.querySelector('#gatewayKey').value='test-hidden-probe-key';
  w.document.querySelector('#saveConfig').click();
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('已保存，但模型加载失败'));
  assert.equal(w.document.querySelector('#notice').classList.contains('error'),true);
  assert.equal(w.document.querySelector('#gatewayKey').value,'');
  assert.ok(calls.some(c=>c.path==='/api/config'&&c.options.method==='POST'));
  assert.doesNotMatch(w.document.querySelector('#notice').textContent,/操作已完成/);
 }finally{dom.window.close()}
});

test('fingerprint as objective is optional; old periodic and risk-specific controls are removed',async()=>{
 const {dom,w,calls,state}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#fingerprintExpected option[value="gpt-6-astra"]'));
  assert.equal(w.document.querySelector('#fingerprintAutomatic').checked,false);
  assert.equal(w.document.querySelector('#fingerprintMode'),null);
  assert.deepEqual([...w.document.querySelectorAll('#promptOptions input')].map(x=>x.value),['milk']);
  const checkbox=w.document.querySelector('#fingerprintAutomatic');
  checkbox.checked=true;
  checkbox.dispatchEvent(new w.Event('change'));
  assert.equal(w.document.querySelector('#rotatePrompts').checked,true);
  w.document.querySelector('#saveAutoPrompts').click();
  await waitFor(()=>state.state.auto_prompt_policy.fingerprint_mode==='objective_rotation');
  const req=JSON.parse(calls.findLast(c=>c.path==='/api/auto-prompts').options.body);
  assert.deepEqual(req,{prompt_ids:['milk'],rotate:true,fingerprint_mode:'objective_rotation'});
  assert.match(w.document.querySelector('#rules .fingerprint-policy .hint').textContent,/一次判分/);
  checkbox.checked=false;
  w.document.querySelector('#saveAutoPrompts').click();
  await waitFor(()=>state.state.auto_prompt_policy.fingerprint_mode==='off');
 }finally{dom.window.close()}
});

test('manual fingerprint selects account, saves bank reference, then runs independent detection',async()=>{
 const {dom,w,calls,state}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="codex/gpt-6.1-sol"]'));
  await waitFor(()=>w.document.querySelector('#fingerprintExpected option[value="gpt-6-astra"]'));
  w.document.querySelector('#accountSelect').value='aaa';
  w.document.querySelector('#modelSelect').value='codex/gpt-6.1-sol';
  w.document.querySelector('#addAccount').click();
  await waitFor(()=>w.document.querySelector('#manualTarget').value.includes('aaa'));
  w.document.querySelector('[data-tab="rules"]').click();
  const prompt=w.document.querySelector('#manualPrompt');
  prompt.value='model-fingerprint';
  prompt.dispatchEvent(new w.Event('change'));
  assert.equal(w.document.querySelector('#fingerprintExpectation').hidden,false);
  const expected=w.document.querySelector('#fingerprintExpected');
  expected.value='gpt-6-astra';
  w.document.querySelector('#saveFingerprintExpected').click();
  await waitFor(()=>calls.some(c=>c.path==='/api/fingerprint-expected'));
  assert.equal(Object.values(state.state.account_targets)[0].fingerprint_expected,'gpt-6-astra');
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('操作已完成'));
  w.document.querySelector('#runManualTest').click();
  await waitFor(()=>calls.some(c=>c.path==='/api/account-test'));
  const body=JSON.parse(calls.findLast(c=>c.path==='/api/account-test').options.body);
  assert.deepEqual(body,{account:'aaa',model:'codex/gpt-6.1-sol',prompt:'model-fingerprint'});
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('不改变隔离状态'));
  assert.equal(state.state.route.auto_apply,false);
  // Never inject external reference labels as markup in the history UI.
  state.state.account_results.push({
   account:'aaa',model:'codex/gpt-6.1-sol',prompt:'model-fingerprint',
   prompt_name:'手动模型指纹检测',verdict:'mismatch',
   time:new Date().toISOString(),fingerprint:{
    verdict:'mismatch',version:'local-test',used_outputs:3,
    candidates:[{model:'test',name:'<img src=x onerror=alert(1)>',probability:.93}]
   }
  });
  w.document.querySelector('#refresh').click();
  await waitFor(()=>w.document.querySelector('#historyRows summary')?.textContent.includes('指纹不一致'));
  assert.equal(w.document.querySelector('#historyRows img'),null);
  await new Promise(resolve=>setTimeout(resolve,65));
 }finally{dom.window.close()}
});

test('deleted monitored login is archived, never probeable, and excluded from live count',async()=>{
 const {dom,w,state}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="codex/gpt-6.1-sol"]'));
  state.state.account_targets={
   'aaa\x1fcodex/gpt-6.1-sol':{account:'aaa',model:'codex/gpt-6.1-sol',enabled:true,state:'passed'},
   'deleted-hex-id\x1fcodex/gpt-6.1-sol':{account:'deleted-hex-id',model:'codex/gpt-6.1-sol',enabled:true,missing:true,state:'quarantined_high'},
  };
  state.state.holds={'deleted-hex-id':{risk:'high'}};
  w.document.querySelector('#refresh').click();
  await waitFor(()=>w.document.querySelector('#accountRows').textContent.includes('账号已删除'));
  assert.equal(w.document.querySelector('#statAccounts').textContent,'1');
  assert.equal(w.document.querySelector('#statIsolated').textContent,'1');
  const archived=[...w.document.querySelectorAll('#accountRows tr')].find(tr=>tr.textContent.includes('账号已删除'));
  assert.ok(archived);
  assert.match(archived.textContent,/隔离留档/);
  assert.ok([...archived.querySelectorAll('button')].every(b=>b.disabled));
  assert.equal(w.document.querySelector('#accountRows img'),null);
 }finally{dom.window.close()}
});

test('roster sync and explicitly approved production allowlist never send raw credentials',async()=>{
 const {dom,w,calls,state}=fixture();
 try{
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="codex/gpt-6.1-sol"]'));
  w.document.querySelector('#syncAccountRoster').click();
  await waitFor(()=>calls.some(c=>c.path==='/api/account-targets/sync'));
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('账号已同步'));
  const auto=w.document.querySelector('#autoSyncAccountRoster');
  auto.checked=true;
  w.document.querySelector('#saveAutoSyncAccountRoster').click();
  await waitFor(()=>state.state.route.auto_sync_accounts===true);
  const req=calls.findLast(c=>c.path==='/api/account-targets/auto-sync');
  assert.deepEqual(JSON.parse(req.options.body),{enabled:true,confirm:'AUTO_SYNC_CODEX_ACCOUNTS'});
  assert.doesNotMatch(JSON.stringify(req.options.body),/Bearer |secret|token/i);
  w.document.querySelector('[data-tab="settings"]').click();
  w.document.querySelector('#approveLiveScopes').click();
  await waitFor(()=>calls.some(c=>c.path==='/api/routing/adopt-current'));
  assert.deepEqual(JSON.parse(calls.findLast(c=>c.path==='/api/routing/adopt-current').options.body),{confirm:'APPROVE_CURRENT_PRODUCTION_SCOPES'});
  assert.equal(state.state.route.last_error,'');
  assert.equal(w.document.querySelector('#restoreRoute').disabled,false);
  await new Promise(resolve=>setTimeout(resolve,80));
 }finally{dom.window.close()}
});

test('fingerprint-only question mode is permitted, while mixed unrotated mode is refused',async()=>{
 const {dom,w,calls,state}=fixture();
 try {
  await waitFor(()=>w.document.querySelector('#promptOptions input[value="milk"]'));
  w.document.querySelector('[data-tab="rules"]').click();
  const checkbox=w.document.querySelector('#fingerprintAutomatic');
  checkbox.checked=true;
  checkbox.dispatchEvent(new w.Event('change'));
  const rotate=w.document.querySelector('#rotatePrompts');
  rotate.checked=false;
  const save=w.document.querySelector('#saveAutoPrompts');
  const before=calls.filter(c=>c.path==='/api/auto-prompts').length;
  save.click();
  await waitFor(()=>w.document.querySelector('#notice').textContent.includes('请勾选按轮次顺序轮换'));
  assert.equal(calls.filter(c=>c.path==='/api/auto-prompts').length,before);
  for(const el of w.document.querySelectorAll('#promptOptions input'))el.checked=false;
  save.click();
  await waitFor(()=>state.state.auto_prompt_policy.fingerprint_mode==='objective_rotation');
  assert.deepEqual(JSON.parse(calls.findLast(c=>c.path==='/api/auto-prompts').options.body).prompt_ids,[]);
 }finally{dom.window.close()}
});

test('time policy edits persist global defaults and per-target overrides without automatic rescheduling',async()=>{
 const {dom,w,calls,state}=fixture();
 try {
  await waitFor(()=>w.document.querySelector('#modelSelect option[value="codex/gpt-6.1-sol"]'));
  w.document.querySelector('[data-tab="settings"]').click();
  assert.equal(w.document.querySelector('#timingNormal').value,'30');
  assert.equal(w.document.querySelector('#timingNormalUnit').value,'60');
  w.document.querySelector('#timingNormal').value='45';
  w.document.querySelector('#saveTiming').click();
  await waitFor(()=>state.state.timing_policy.normal_seconds===2700);
  assert.equal(JSON.parse(calls.findLast(c=>c.path==='/api/timing').options.body).reschedule,false);
  await waitFor(()=>w.document.querySelector('#notice').textContent==='操作已完成');
  // Separate add-account behavior is covered above; inject an enrolled target
  // here so this test isolates timing-policy form behavior from async model loading.
  state.state.account_targets['aaa\x1fcodex/gpt-6.1-sol']={
   account:'aaa',model:'codex/gpt-6.1-sol',enabled:true,state:'passed'
  };
  w.document.querySelector('#refresh').click();
  await waitFor(()=>w.document.querySelector('#timingScope option').length>1);
  w.document.querySelector('#timingScope').value='aaa\x1fcodex/gpt-6.1-sol';
  w.document.querySelector('#timingScope').dispatchEvent(new w.Event('change'));
  assert.equal(w.document.querySelector('#timingInherit').checked,true);
  assert.equal(w.document.querySelector('#timingNormal').disabled,true);
  w.document.querySelector('#timingInherit').checked=false;
  w.document.querySelector('#timingInherit').dispatchEvent(new w.Event('change'));
  assert.equal(w.document.querySelector('#timingNormal').disabled,false);
  assert.equal(w.document.querySelector('#timingScan').disabled,true);
  w.document.querySelector('#timingNormal').value='10';
  w.document.querySelector('#saveTiming').click();
  await waitFor(()=>Object.values(state.state.account_targets)[0].timing_override?.normal_seconds===600);
  assert.equal(state.state.timing_policy.normal_seconds,2700);
  const body=JSON.parse(calls.findLast(c=>c.path==='/api/timing').options.body);
  assert.equal(body.account,'aaa');
  assert.equal(body.policy.normal_seconds,600);
  assert.equal(body.inherit,false);
  assert.equal(body.reschedule,false);
  assert.equal(state.state.route.auto_apply,false);
 }finally{dom.window.close()}
});
