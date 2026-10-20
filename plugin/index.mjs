import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';

const root=fileURLToPath(new URL('../',import.meta.url));
let started,child;
function start(options={}){
 if(started)return started;
 started=new Promise((resolve,reject)=>{
  const platform=({win32:'windows',darwin:'darwin',linux:'linux'})[process.platform]||process.platform;
  const arch=({x64:'amd64',arm64:'arm64'})[process.arch]||process.arch;
  const ext=platform==='windows'?'.exe':'';
  const bundled=path.join(root,'bin',`codex-guard-${platform}-${arch}${ext}`);
  const binary=options.binaryPath||(existsSync(bundled)?bundled:path.join(root,'bin','codex-guard'+ext));
  const dataDir=options.dataDir||path.join(os.homedir(),'.config','magpie-codex-guard');
  const args=['-data',dataDir,'-gate',path.join(root,'plugin','gate.middleware.js'),'-owned'];
  const env={...process.env};
  if(options.magpieConfigDir)env.MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR=options.magpieConfigDir;
  child=spawn(binary,args,{stdio:['pipe','pipe','pipe'],env,windowsHide:true});
  let output='';
  const timer=setTimeout(()=>{child.kill();reject(new Error('Codex Guard 后台启动超时'))},15000);
  child.stdout.on('data',data=>{
   output+=data.toString('utf8');
   const n=output.indexOf('\n');
   if(n<0)return;
   clearTimeout(timer);
   try{resolve(JSON.parse(output.slice(0,n)))}
   catch{reject(new Error('Codex Guard 启动信息无效'))}
  });
  child.stderr.on('data',()=>{}); // Never log API secrets or raw auth error payloads.
  child.once('error',err=>{clearTimeout(timer);started=undefined;reject(err)});
  child.once('exit',()=>{clearTimeout(timer);started=undefined;});
 });
 return started;
}
process.once('exit',()=>child?.kill());
export default {
 id:'magpie-codex-guard',
 server:async(_input,options={})=>({
  auth:{
   provider:'magpie-codex-guard',
   methods:[{
    type:'oauth',label:'打开 Codex Guard 账号检测控制台',
    async authorize(){
     const v=await start(options);
     const response=await fetch(v.origin+'/api/open',{
      method:'POST',headers:{Authorization:'Bearer '+v.control,'Content-Type':'application/json'},body:'{}'
     });
     if(!response.ok)throw new Error('无法生成管理链接');
     const result=await response.json();
     return {url:result.url,instructions:'在本机浏览器打开一次性管理链接；不需要供应商授权。',method:'code',callback:async()=>({type:'failed'})};
    }
   }],
   async loader(){await start(options);return {}}
  },
  async config(cfg){
   await start(options);
   cfg.provider??={};
   cfg.provider['magpie-codex-guard']={name:'Codex Guard',models:{}};
  }
 })
};
