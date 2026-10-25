const $=id=>document.getElementById(id);
let current=null;
let models=[];
let modelsLoading=true;
let modelsError='';
let editingPrompt='';
let fingerprintModels=[];
let fingerprintModelsError='';
const stateLabels={
 passed:['正常','ok'], suspect:['疑似异常','low'], checking:['检测中','pending'],
 unverified:['待检测','pending'], unavailable:['不可用','pending'],
 fingerprint_pending:['指纹复核中','pending'], quarantined_high:['高风险隔离','high'],
 quarantined_low:['低风险隔离','low'], recovery_confirm:['恢复确认','low']
};
function labelFor(t,hold){
 if(hold){
  const x=hold.risk==='high'?['高风险隔离','high']:hold.risk==='low'?['低风险隔离','low']:['待指纹复核','pending'];
  return `<span class="pill ${x[1]}">${x[0]}</span>`;
 }
 const x=stateLabels[t.state]||['未检测','pending'];
 return `<span class="pill ${x[1]}">${x[0]}</span>`;
}
function elem(tag,cls,text){
 const e=document.createElement(tag);
 if(cls)e.className=cls;
 if(text!==undefined)e.textContent=String(text);
 return e;
}
function fmtTime(raw){
 if(!raw||raw.startsWith('0001-'))return '待调度';
 const d=new Date(raw);
 if(!Number.isFinite(d.getTime()))return '待调度';
 const left=Math.ceil((d-Date.now())/60000);
 if(left>60)return `${Math.floor(left/60)}小时${left%60}分后`;
 if(left>0)return `${left}分钟后`;
 return '等待调度';
}
function stamp(raw){
 if(!raw)return '';
 const d=new Date(raw);
 if(!Number.isFinite(d.getTime()))return '';
 return d.toLocaleString('zh-CN',{hour12:false});
}
function notice(message,error=false){
 const el=$('notice');el.textContent=message;el.hidden=!message;el.classList.toggle('error',error);
 if(message)el.scrollIntoView({block:'nearest',behavior:'smooth'});
}
async function api(path,method='GET',data){
 const res=await fetch(path,{
  method,credentials:'same-origin',
  headers:data===undefined?{}:{'Content-Type':'application/json'},
  body:data===undefined?undefined:JSON.stringify(data)
 });
 if(!res.ok)throw Error((await res.text()).trim()||`HTTP ${res.status}`);
 return res.status===204?null:res.json();
}
async function action(fn){
 try{await fn();notice('操作已完成');await refresh()}catch(e){notice(e?.message||String(e),true)}
}
const accounts=()=>current?.accounts||[];
function email(id){return accounts().find(a=>a.id===id||a.user===id)?.user||'账号已从 Magpie 删除（隔离留档）'}
function option(select,entries,placeholder){
 const last=select.value;
 select.replaceChildren(new Option(placeholder,''));
 for(const [value,label] of entries)select.add(new Option(label,value));
 if(entries.some(([v])=>v===last))select.value=last;
}
function renderSummary(){
 const s=current?.state;
 if(!s)return;
 const live=new Set(accounts().map(a=>a.id));
 const targets=Object.values(s.account_targets||{}).filter(t=>t.enabled&&live.has(t.account));
 const held=s.holds||{};
 const ids=[...new Set(targets.map(t=>t.account))];
 $('statAccounts').textContent=String(ids.length);
 $('statIsolated').textContent=String(Object.keys(held).length);
 $('statPending').textContent=String(Object.values(held).filter(h=>h.risk==='pending').length);
 $('statHealthy').textContent=String(ids.filter(id=>!held[id]&&targets.some(t=>t.account===id&&t.state==='passed')).length);
 const active=s.route?.auto_apply;
 $('liveStatus').textContent=s.route?.pending?'路由事务待确认':s.route?.last_error?'路由同步异常':active?'自动隔离已启用':'仅观察 · 未修改生产路由';
 $('liveStatus').title=s.route?.last_error||'';
}
function renderSelectors(){
 option($('accountSelect'),accounts().map(a=>[a.id,a.user]),'选择账号邮箱');
 option($('historyAccount'),accounts().map(a=>[a.id,a.user]),'全部账号');
 option($('modelSelect'),models.map(m=>[m.id,m.id]),models.length?'选择检测模型':modelsLoading?'正在从 Magpie 读取模型…':'没有可选模型');
 option($('probeKey'),(current.keys||[]).map(k=>[k.id,k.name||'未命名检测 Key']),'选择专用检测 Key');
 const help=$('modelHelp');
 help.textContent=modelsLoading?'正在从 Magpie 本机读取 Codex 模型…':modelsError?'模型加载失败：'+modelsError+'。请检查 Magpie 的模型配置后点击右上角「刷新」。':models.length?`已读取 Magpie 的 ${models.length} 个 Codex 模型。${current?.gateway_configured?'检测连接已配置。':'可以先添加监测目标；实际检测前还需在「设置与路由」配置独立检测 Gateway Key。'}`:'没有找到可用的 Codex 模型。';
 help.classList.toggle('error',Boolean(modelsError));
 $('addAccount').disabled=!models.length;
 $('addAll').disabled=!models.length;
}
function accountButton(label,cb,cls='small'){
 const b=elem('button',cls,label);
 b.onclick=cb;
 return b;
}
function renderAccounts(){
 const tbody=$('accountRows');
 tbody.replaceChildren();
 const s=current.state;
 const targets=Object.values(s.account_targets||{}).sort((a,b)=>email(a.account).localeCompare(email(b.account)));
 const holds=s.holds||{};
 if(!targets.length){
  const td=elem('td','empty','尚未添加 Codex 监测目标。先选择账号和模型，再点击「添加监测」。');
  td.colSpan=5;const tr=elem('tr');tr.append(td);tbody.append(tr);return;
 }
 for(const t of targets){
  const tr=elem('tr');
  const hold=holds[t.account];
  const missing=t.missing||!accounts().some(a=>a.id===t.account);
  const mail=elem('td','email',email(t.account));
  const model=elem('td','mono',t.model);
  const st=elem('td');
  // Only static markup is injected. Account/user content is always textContent.
  const label=elem('span',`pill ${(hold?.risk==='high'?'high':hold?.risk==='low'||t.state==='suspect'?'low':t.state==='passed'&&!hold?'ok':'pending')}`,
   hold?(hold.risk==='high'?'高风险隔离':hold.risk==='low'?'低风险隔离':'指纹复核中'):(stateLabels[t.state]?.[0]||t.state));
  st.append(label);
  if(missing)st.append(elem('div','hint','账号已删除 · 停止检测 · 隔离留档保留'));
  if(hold&&s.route?.auto_apply&&!s.route?.quarantined?.[t.account]){
   const warning=elem('div','hint','路由尚未确认排除');st.append(warning);
  }
  const due=elem('td','mono',fmtTime(hold?.next_check_at||t.next_check_at));
  const ops=elem('td');
  const bar=elem('div','actions-inline');
  const test=accountButton('手动测试',()=>submitManualTest(t.account,t.model,chosenPrompt()));
  const toggle=accountButton(t.enabled?'暂停检测':'启用检测',()=>action(async()=>{
   await api('/api/account-target','POST',{account:t.account,model:t.model,enabled:!t.enabled})
  }));
  const del=accountButton('移除',()=>action(async()=>{
   if(!confirm('确定移除该账号的监测目标？历史记录不会删除。'))return;
   await api('/api/account-target','DELETE',{account:t.account,model:t.model});
  }));
  if(hold||missing){toggle.disabled=true;del.disabled=true}
  if(missing)test.disabled=true
  bar.append(test,toggle,del);ops.append(bar);
  tr.append(mail,model,st,due,ops);
  tbody.append(tr);
 }
}
function chosenPrompt(){
 return $('manualPrompt').value||'milk';
}
function renderRules(){
 const s=current.state;
 const opts=$('promptOptions');opts.replaceChildren();
 const all=current.prompts||[];
 const policy=s.auto_prompt_policy||{};
 const chosen=new Set(policy.configured?policy.prompt_ids:all.filter(p=>p.automatic&&p.kind!=='fingerprint').map(p=>p.id));
 for(const p of all.filter(p=>p.automatic&&p.kind!=='fingerprint')){
  const l=elem('label','check');
  const input=elem('input');input.type='checkbox';input.value=p.id;input.checked=chosen.has(p.id);
  l.append(input,elem('span','',p.name));
  opts.append(l);
 }
 $('rotatePrompts').checked=Boolean(policy.rotate||!policy.configured);
 const mode=policy.fingerprint_mode||'after_failures';
 $('fingerprintAutomatic').checked=mode!=='off';
 $('fingerprintMode').value=['after_failures','periodic_24h','objective_rotation'].includes(mode)?mode:'after_failures';
 $('fingerprintMode').disabled=mode==='off';
 const list=$('customList');list.replaceChildren();
 for(const p of (s.custom_prompts||[])){
  const wrap=elem('div','sub-row');
  const name=elem('div','',p.name);
  name.append(elem('small','',p.automatic?' · 自动判分':' · 仅手动'));
  const actions=elem('div','actions-inline');
  actions.append(accountButton('编辑',()=>{
   editingPrompt=p.id;
   $('customName').value=p.name;$('customText').value=p.text;$('customGuidance').value=p.guidance||'';
   $('customAutomatic').checked=Boolean(p.automatic);$('customAnswers').value=(p.expected_answers||[]).join('\n');
   $('saveCustom').textContent='保存修改';
   $('customName').focus();
  }));
  actions.append(accountButton('删除',()=>action(async()=>{
   if(!confirm('确认删除自定义题目？历史记录不会删除。'))return;
   await api('/api/custom-prompts/'+encodeURIComponent(p.id),'DELETE')
  }),'small danger'));
  wrap.append(name,actions);
  list.append(wrap);
 }
}
function chosenManualTarget(){
 const key=$('manualTarget').value;
 return key?(current?.state?.account_targets||{})[key]:null;
}
function renderManual(){
 const live=new Set(accounts().map(a=>a.id));
 const targets=Object.entries(current?.state?.account_targets||{}).filter(([,t])=>t.enabled&&live.has(t.account));
 option($('manualTarget'),targets.map(([key,t])=>[key,email(t.account)+' · '+t.model]),'选择已添加的监测目标');
 if(!$('manualTarget').value&&targets.length===1)$('manualTarget').value=targets[0][0];
 const promptList=(current?.prompts||[]).map(p=>[p.id,(p.kind==='fingerprint'?'指纹检测 · ':'客观题 · ')+p.name]);
 option($('manualPrompt'),promptList,'选择检测题目');
 if(!$('manualPrompt').value&&promptList.some(p=>p[0]==='milk'))$('manualPrompt').value='milk';
 updateFingerprintExpected();
}
function updateFingerprintExpected(){
 const t=chosenManualTarget();
 option($('fingerprintExpected'),fingerprintModels.map(m=>[m.id,m.name||m.id]),'自动匹配当前 Codex 模型');
 const desired=t?.fingerprint_expected||'';
 if(desired&&fingerprintModels.some(m=>m.id===desired))$('fingerprintExpected').value=desired;
 else if(!desired)$('fingerprintExpected').value='';
 $('fingerprintExpectation').hidden=$('manualPrompt').value!=='model-fingerprint';
 $('fingerprintModelHelp').textContent=fingerprintModelsError?
  '参考模型加载失败：'+fingerprintModelsError:
  '参考库提供 '+fingerprintModels.length+' 个候选模型。手动及周期检测可自动匹配；作为自动客观题参与轮换时，必须先明确保存该账号的预期参考模型。';
}
async function loadFingerprintModels(){
 try{
  const values=await api('/api/fingerprint-models');
  if(!Array.isArray(values))throw Error('参考模型列表格式无效');
  fingerprintModels=values.filter(m=>m&&typeof m.id==='string');
  fingerprintModelsError='';
 }catch(e){fingerprintModels=[];fingerprintModelsError=e?.message||String(e)}
 updateFingerprintExpected();
}
async function submitManualTest(account,model,prompt){
 if(!account||!model||!prompt){notice('请先选择监测账号、模型和检测题目',true);return}
 if(prompt==='model-fingerprint'&&!confirm('模型指纹检测将向指定账号发送 3 次请求，仅生成检测记录。确定执行？'))return;
 try{
  await api('/api/account-test','POST',{account,model,prompt});
  notice(prompt==='model-fingerprint'?'已开始手动指纹检测（3 次采样）；结果会显示在检测记录，不改变隔离状态。':'已提交手动客观题检测；结果稍后显示在检测记录。');
  await refresh();
 }catch(e){notice('手动检测失败：'+(e?.message||String(e)),true)}
}
function renderHistory(){
 const records=(current.state.account_results||[]).slice().reverse();
 const account=$('historyAccount').value;
 const filtered=records.filter(r=>!account||r.account===account);
 const root=$('historyRows');root.replaceChildren();
 if(!filtered.length){root.append(elem('div','card small-card muted','暂无符合条件的检测记录'));return}
 for(const r of filtered.slice(0,120)){
  const details=elem('details','history-item');
  const sum=elem('summary');
  sum.append(elem('span','mono muted',stamp(r.time)),elem('strong','',email(r.account)),elem('span','muted',r.prompt_name||r.prompt));
  const verdict=elem('span',`pill ${r.verdict==='high'||r.verdict==='failed'?'high':r.verdict==='passed'?'ok':r.verdict==='low'?'low':'pending'}`,
   ({passed:'通过',failed:'错误',unavailable:'不可用',high:'高风险',low:'低风险',manual:'人工评价',sampled:'已采样（未判分）',match:'指纹一致',mismatch:'指纹不一致',indeterminate:'指纹不可判'})[r.verdict]||r.verdict);
  sum.append(verdict);
  details.append(sum);
  if(r.error)details.append(elem('p','hint',r.error));
  if(r.answer)details.append(elem('pre','',r.answer));
  if(r.fingerprint){
   const fp=r.fingerprint;
   details.append(elem('p','hint',`指纹结论：${fp.verdict} · 参考库：${fp.version||'未知'} · 有效样本：${fp.used_outputs||0}/3 · ${fp.diagnostic||''}`));
   for(const c of fp.candidates||[]){
    details.append(elem('p','mono muted',`${c.name||c.model} · ${(c.probability*100).toFixed(1)}%（候选库内相对值）`));
   }
  }
  root.append(details);
 }
}
function renderSettings(){
 const s=current.state;
 if(document.activeElement!==$('autoSyncAccountRoster'))$('autoSyncAccountRoster').checked=Boolean(s.route?.auto_sync_accounts);
 if(document.activeElement!==$('gatewayURL'))$('gatewayURL').value=s.config?.gateway_url||'';
 if(document.activeElement!==$('dailyLimit'))$('dailyLimit').value=s.config?.daily_limit||600;
 if(document.activeElement!==$('expectedCount'))$('expectedCount').value=s.route?.expected_codex_count||0;
 if(document.activeElement!==$('probeKey') && s.route?.probe_key_id)$('probeKey').value=s.route.probe_key_id;
 $('enableSchedule').checked=Boolean(s.route?.schedule_enabled);
 $('enableRouting').checked=Boolean(s.route?.auto_apply);
}
async function refresh(){
 current=await api('/api/state');
 renderSummary();
 renderSelectors();
 renderAccounts();
 renderRules();
 renderManual();
 renderHistory();
 renderSettings();
}
async function loadModels(){
 modelsLoading=true;modelsError='';renderSelectors();
 try{
  const result=await api('/api/models');
  if(!Array.isArray(result))throw Error('模型列表响应格式错误');
  models=result.filter(m=>m&&typeof m.id==='string'&&/^codex\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(m.id));
  modelsError=models.length?'':'本机 Magpie 未提供可用的 Codex 模型';
 }catch(e){models=[];modelsError=e?.message||'未知错误'}
 modelsLoading=false;renderSelectors();
 return !modelsError;
}
function selectTab(tab){
 document.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
 for(const section of document.querySelectorAll('.page'))section.hidden=section.id!==tab;
}
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>selectTab(b.dataset.tab));
$('refresh').onclick=()=>action(async()=>{
 await refresh();
 if(!(await loadModels()))throw Error('模型加载失败：'+modelsError);
});
$('addAccount').onclick=()=>action(async()=>{
 const account=$('accountSelect').value,model=$('modelSelect').value;
 if(!account||!model)throw Error('请选择账号邮箱和检测模型');
 await api('/api/account-target','POST',{account,model,enabled:true});
});
$('addAll').onclick=()=>action(async()=>{
 const model=$('modelSelect').value;
 if(!model)throw Error('请选择检测模型');
 if(!confirm('将所有已经登录的 Codex 账号加入该模型的监测列表？'))return;
 await api('/api/account-targets/discover','POST',{model,confirm:'ADD_ALL_CODEX_ACCOUNTS'});
});
$('syncAccountRoster').onclick=async()=>{
 try{
  const result=await api('/api/account-targets/sync','POST',{confirm:'SYNC_LIVE_CODEX_TARGETS'});
  await refresh();
  notice('账号已同步：Magpie 当前 '+result.live_count+' 个账号；新增监测 '+result.added+' 项，已删除账号留档 '+result.missing+' 项。');
 }catch(e){notice('同步账号失败：'+(e?.message||String(e)),true)}
};
$('saveAutoSyncAccountRoster').onclick=async()=>{
 const enabled=$('autoSyncAccountRoster').checked;
 if(enabled&&!confirm('开启后自动监测 Magpie 新增加的 Codex 账号，将使用已有监测模型和独立检测 Key，消耗检测请求额度。不会自动扩大生产白名单。确认开启？'))return;
 try{
  await api('/api/account-targets/auto-sync','POST',{enabled,confirm:enabled?'AUTO_SYNC_CODEX_ACCOUNTS':''});
  if(enabled)await api('/api/account-targets/sync','POST',{confirm:'SYNC_LIVE_CODEX_TARGETS'});
  await refresh();
  notice(enabled?'账号自动同步已启用；已从 Magpie 更新监测目标。':'账号自动同步已关闭；原有监测目标保留。');
 }catch(e){notice('保存账号同步设置失败：'+(e?.message||String(e)),true)}
};
$('fingerprintAutomatic').onchange=()=>{$('fingerprintMode').disabled=!$('fingerprintAutomatic').checked};
$('fingerprintMode').onchange=()=>{
 if($('fingerprintMode').value==='objective_rotation'){
   $('fingerprintAutomatic').checked=true;
   $('rotatePrompts').checked=true;
 }
};
$('manualPrompt').onchange=updateFingerprintExpected;
$('manualTarget').onchange=updateFingerprintExpected;
$('runManualTest').onclick=()=>{
 const t=chosenManualTarget();
 submitManualTest(t?.account,t?.model,chosenPrompt());
};
$('saveFingerprintExpected').onclick=()=>action(async()=>{
 const t=chosenManualTarget();
 if(!t)throw Error('请选择监测目标');
 if(fingerprintModelsError)throw Error('参考库不可用，请刷新后重试：'+fingerprintModelsError);
 await api('/api/fingerprint-expected','POST',{
  account:t.account,model:t.model,expected:$('fingerprintExpected').value
 });
});
$('saveAutoPrompts').onclick=()=>action(async()=>{
 const prompt_ids=[...document.querySelectorAll('#promptOptions input:checked')].map(x=>x.value);
 const fingerprint_mode=$('fingerprintAutomatic').checked?$('fingerprintMode').value:'off';
 if(!prompt_ids.length&&fingerprint_mode!=='objective_rotation')throw Error('至少选择一道客观题');
 if(fingerprint_mode==='objective_rotation'&&prompt_ids.length&&!$('rotatePrompts').checked)throw Error('指纹参与客观题轮换时，请勾选按轮次顺序轮换');
 if(fingerprint_mode==='periodic_24h'&&!confirm('启用周期指纹检测后，每个正常监测目标每 24 小时会增加 3 次上游请求，确认继续？'))return;
 if(fingerprint_mode==='objective_rotation'&&!confirm('指纹将作为自动检测题：每轮发送 3 次请求；连续三次可靠的指纹不一致可触发生产隔离。必须先为各监测账号设置参考模型，否则该轮只记不可用。确定启用？'))return;
 await api('/api/auto-prompts','POST',{prompt_ids,rotate:$('rotatePrompts').checked,fingerprint_mode});
});
$('saveCustom').onclick=()=>action(async()=>{
 const body={
  name:$('customName').value,text:$('customText').value,
  automatic:$('customAutomatic').checked,
  expected_answers:$('customAnswers').value.split('\n').map(s=>s.trim()).filter(Boolean),
  guidance:$('customGuidance').value
 };
 if(!body.name.trim()||!body.text.trim())throw Error('题目名称和正文不能为空');
 if(body.automatic && !body.expected_answers.length)throw Error('自动判分题必须提供完整标准答案');
 if(body.automatic&&!confirm('确认将该题目作为可能触发账号隔离的客观题？'))return;
 if(editingPrompt){await api('/api/custom-prompts/'+encodeURIComponent(editingPrompt),'PUT',body)}
 else{await api('/api/custom-prompts','POST',body)}
 editingPrompt='';$('saveCustom').textContent='创建题目';
 for(const id of ['customName','customText','customGuidance','customAnswers'])$(id).value='';
});
$('saveConfig').onclick=async()=>{
 try{
  await api('/api/config','POST',{gateway_url:$('gatewayURL').value,gateway_key:$('gatewayKey').value,daily_limit:Number($('dailyLimit').value)});
  $('gatewayKey').value='';
  await refresh();
  const loaded=await loadModels();
  notice(loaded?'检测连接已保存，模型列表已刷新':'检测连接已保存，但模型加载失败：'+modelsError,!loaded);
 }catch(e){notice('保存检测连接失败：'+(e?.message||String(e)),true)}
};
$('saveRoute').onclick=()=>action(async()=>{
 const auto=$('enableRouting').checked;
 const body={
  probe_key_id:$('probeKey').value,auto_apply:auto,
  schedule_enabled:$('enableSchedule').checked,expected_count:Number($('expectedCount').value),
  confirm:auto?$('routeConfirm').value:''
 };
 if(auto&&!confirm('确认 Codex Guard 接管全部生产 Gateway Key 的账号隔离路由？'))return;
 await api('/api/routing/config','POST',body);
 $('routeConfirm').value='';
});
$('previewRoute').onclick=()=>action(async()=>{
 const plan=await api('/api/routing/preview');
 const keyNames=new Map((current.keys||[]).map(k=>[k.id,k.name]));
 const parts=[`路由模式：${plan.mode}`,`隔离账号数：${plan.quarantined?.length||0}`];
 for(const p of plan.keys||[]){
  const note=p.is_probe?'（检测专用）':p.off_after?' · 暂时停用':p.off_before&&!p.off_after?' · 恢复启用':'';
  parts.push(`${keyNames.get(p.key_id)||'Gateway Key'}：白名单 ${p.before?.length||0} → ${p.after?.length||0} 条${note}`);
 }
 $('routePreview').textContent=parts.join('\n');
 $('routePreview').hidden=false;
});
$('approveLiveScopes').onclick=()=>action(async()=>{
 const agreed=confirm('确认以 Magpie 当前的生产 Gateway Key 白名单为准？只接受已登录且未隔离的 Codex 账号新增；不得新增被隔离账号。此操作不会写入生产 Key 文件，只会更新 Codex Guard 内部基线及审计记录。以后新增账号若触发隔离，插件将按新基线自动移除其生产路由。');
 if(!agreed)return;
 const result=await api('/api/routing/adopt-current','POST',{confirm:'APPROVE_CURRENT_PRODUCTION_SCOPES'});
 notice('当前生产白名单已核对并采用，未修改 Gateway Key 文件，隔离记录保持不变。');
});
$('restoreRoute').onclick=()=>action(async()=>{
 const value=prompt('紧急恢复会清除全部隔离记录和自动隔离开关，请输入 RESTORE_ALL_PRODUCTION_KEYS');
 if(value!=='RESTORE_ALL_PRODUCTION_KEYS')return;
 await api('/api/routing/restore','POST',{confirm:value});
});
$('historyAccount').onchange=renderHistory;
(async()=>{
 try{await refresh();await loadModels();await loadFingerprintModels()}catch(e){notice('控制台加载失败：'+e.message,true)}
 setInterval(async()=>{try{await refresh()}catch{}},30000);
})();
