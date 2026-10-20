import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { resolveBinary } from './runtime.mjs';
import { resolveCloudflared } from './cloudflared-runtime.mjs';
import { waitForConsole } from './console-readiness.mjs';

const root = fileURLToPath(new URL('../',import.meta.url));
let started, child;
function start(options = {}) {
  if (started) return started;
  started = (async () => {
    const dataDir = options.dataDir || path.join(os.homedir(), '.config', 'magpie-codex-guard');
    const binary = await resolveBinary({root, dataDir, binaryPath:options.binaryPath});
    return new Promise((resolve,reject) => {
      const args = ['-data',dataDir,'-gate',path.join(root,'plugin','gate.middleware.js'),'-owned'];
      if (options.cloudflaredPath) args.push('-cloudflared',options.cloudflaredPath);
      const env = {...process.env};
      if (options.magpieConfigDir) env.MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR = options.magpieConfigDir;
      child = spawn(binary,args,{stdio:['pipe','pipe','pipe'],env,windowsHide:true});
      child.stdin.on('error',()=>{});
      let output='';
      const timer = setTimeout(()=>{child.kill();reject(new Error('Codex Guard 后台启动超时'));},15000);
      child.stdout.on('data',bytes => {
        output += bytes.toString('utf8');
        const index = output.indexOf('\n');
        if (index < 0) return;
        clearTimeout(timer);
        try { resolve(JSON.parse(output.slice(0,index))); }
        catch { child.kill(); reject(new Error('Codex Guard 后台启动信息无效')); }
      });
      child.stderr.on('data',()=>{}); // Never log raw API or auth payloads.
      child.once('error',error => {clearTimeout(timer);started=undefined;reject(error);});
      child.once('exit',code => {
        clearTimeout(timer);
        started=undefined;
        reject(new Error(`Codex Guard 检测后台退出（exit ${code}）`));
      });
    });
  })();
  started.catch(()=>{started=undefined});
  return started;
}
process.once('exit',()=>child?.kill());

export default {
  id:'magpie-codex-guard',
  server:async(_input,options={})=>({
    auth:{
      provider:'magpie-codex-guard',
    methods: [true,false].map(remote=>({ type: 'oauth', label: remote?'打开临时远程控制台（Cloudflare）':'打开本机 Codex Guard 控制台', async authorize() {
      const v = await start(options);
      const binary=remote?await resolveCloudflared(options,options.dataDir || path.join(os.homedir(), '.config', 'magpie-magpie-codex-guard')):undefined;
      const r=await fetch(v.origin+'/api/console',{method:'POST',headers:{authorization:'Bearer '+v.control,'content-type':'application/json'},body:JSON.stringify({remote,binary})});
      if(!r.ok)throw Error(await r.text());const {url}=await r.json();
      if(remote){
        try { await waitForConsole(url); }
        catch(error){
          await fetch(v.origin+'/api/console/close',{method:'POST',headers:{authorization:'Bearer '+v.control,'content-type':'application/json'},body:'{}'}).catch(()=>{});
          // The service delays tunnel shutdown to deliver its acknowledgement.
          await new Promise(resolve=>setTimeout(resolve,350));
          throw error;
        }
      }
      return { url, instructions: `完整管理链接：${url}\n复制链接后在浏览器打开。链接十分钟内有效且只能使用一次。此入口不是供应商登录，无需提交验证码；使用后可以取消此窗口。${remote ? '临时通道最长 30 分钟。' : ''}`, method: 'code', callback: async () => ({ type: 'failed' }) };
    } })),
      async loader(){await start(options);return {};}
    },
    async config(cfg){
      await start(options);
      cfg.provider??={};
      cfg.provider['magpie-codex-guard']={name:'Codex Guard',models:{}};
    }
  })
};
