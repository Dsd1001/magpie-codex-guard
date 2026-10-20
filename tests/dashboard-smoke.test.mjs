import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {JSDOM} from 'jsdom';

const html=await readFile(new URL('../internal/check/web/index.html',import.meta.url),'utf8');
const js=await readFile(new URL('../internal/check/web/assets/app.js',import.meta.url),'utf8');

function fixture({modelsError=''}={}){
 const calls=[];
 const state={
  state:{
   config:{gateway_url:'http://127.0.0.1:3425',daily_limit:600},
   route:{schedule_enabled:false,auto_apply:false,expected_codex_count:2,probe_key_id:'probe'},
   holds:{},
   account_targets:{},
   account_results:[],
   auto_prompt_policy:{configured:false,rotate:true,prompt_ids:['milk']},
   custom_prompts:[],
  },
  health:'',
  gateway_configured:false,
  accounts:[
   {id:'aaa',user:'a@example.com'},
   {id:'bbb',user:'<img src=x onerror=alert(1)>@example.com'},
  ],
  keys:[{id:'probe',name:'Detection'}, {id:'prod',name:'Business'}],
  prompts:[{id:'milk',name:'牛奶推理',automatic:true}],
 };
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
  assert.match(w.document.querySelector('#modelHelp').textContent,/已读取 Magpie 的 1 个 Codex 模型/);
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
