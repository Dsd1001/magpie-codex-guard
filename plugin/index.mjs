import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveBinary } from './runtime.mjs';
import { createRemoteConsole } from './remote-console.mjs';
import path from 'node:path';
import os from 'node:os';

const root=fileURLToPath(new URL('../',import.meta.url));
let started,child,remoteConsole;
function start(options={}){
 if(started)return started;
 started=(async()=>{
  const dataDir=options.dataDir||path.join(os.homedir(),'.config','magpie-codex-guard');
  const binary=await resolveBinary({root,dataDir,binaryPath:options.binaryPath});
  return new Promise((resolve,reject)=>{
   const args=['-data',dataDir,'-gate',path.join(root,'plugin','gate.middleware.js'),'-owned'];
   const env={...process.env};
   if(options.magpieConfigDir)env.MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR=options.magpieConfigDir;
   child=spawn(binary,args,{stdio:['pipe','pipe','pipe'],env,windowsHide:true});
   child.stdin.on('error',()=>{});
   let output='';
   const timer=setTimeout(()=>{child.kill();reject(new Error('Codex Guard 后台启动超时'))},15000);
   child.stdout.on('data',data=>{
    output+=data.toString('utf8');
    const n=output.indexOf('\n');
    if(n<0)return;
    clearTimeout(timer);
    try{resolve(JSON.parse(output.slice(0,n)))}
    catch{child.kill();reject(new Error('Codex Guard 启动信息无效'))}
   });
   child.stderr.on('data',()=>{}); // Do not log raw auth errors or secrets.
   child.once('error',err=>{clearTimeout(timer);started=undefined;reject(err)});
   child.once('exit',code=>{
    clearTimeout(timer);
    remoteConsole?.close();
    remoteConsole=undefined;
    started=undefined;
    reject(new Error(`Codex Guard 检测后台提前退出（exit ${code}）`));
   });
  });
 })();
 started.catch(()=>{started=undefined});
 return started;
}
process.once('exit',()=>{remoteConsole?.close();child?.kill()});
export default {
 id:'magpie-codex-guard',
 server:async(_input,options={})=>({
  auth:{
   provider:'magpie-codex-guard',
   methods:[true,false].map(remote=>({
    type:'oauth',
    label:remote?'打开临时远程控制台（Cloudflare）':'打开本机控制台（仅限服务器）',
    async authorize(){
     const v=await start(options);
     let url;
     if(remote){
      const dataDir=options.dataDir||path.join(os.homedir(),'.config','magpie-codex-guard');
      remoteConsole??=createRemoteConsole({localOrigin:v.origin,control:v.control,dataDir,options});
      url=await remoteConsole.open();
     } else {
      const response=await fetch(v.origin+'/api/open',{
       method:'POST',headers:{Authorization:'Bearer '+v.control,'Content-Type':'application/json'},body:'{}'
      });
      if(!response.ok)throw new Error('无法生成本机管理链接');
      url=(await response.json()).url;
     }
     return {
      url,
      instructions:remote?
       '请在浏览器中打开完整的 HTTPS 一次性链接；链接 10 分钟内有效且仅能使用一次。临时远程通道最长 30 分钟，不需要供应商授权。':
       '仅限 Magpie 所在服务器本机打开；远程部署请改用 Cloudflare 临时远程控制台。',
      method:'code',callback:async()=>({type:'failed'})
     };
    }
   })),
   async loader(){await start(options);return {}}
  },
  async config(cfg){
   await start(options);
   cfg.provider??={};
   cfg.provider['magpie-codex-guard']={name:'Codex Guard',models:{}};
  }
 })
};
