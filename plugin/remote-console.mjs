import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { resolveCloudflared } from './cloudflared-runtime.mjs';
import { startRemoteProxy } from './remote-proxy.mjs';

const TUNNEL_LIFETIME = 30 * 60 * 1000;
const TUNNEL_START_TIMEOUT = 90 * 1000;
const TUNNEL_READY_TIMEOUT = 60 * 1000;
const URL_PATTERN = /https:\/\/[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com(?=$|[\s/])/;

export function extractTunnelOrigin(line) {
  const match = line.match(URL_PATTERN);
  return match ? match[0] : '';
}

async function waitForConsole(origin, maxWait = TUNNEL_READY_TIMEOUT) {
  const deadline = Date.now() + maxWait;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(origin + '/health', {
        redirect: 'error',
        signal: AbortSignal.timeout(Math.min(5000, Math.max(1, deadline - Date.now()))),
      });
      const ready = response.status === 204 &&
        response.headers.get('x-codex-guard') === 'ready';
      await response.body?.cancel();
      if (ready) return;
    } catch {
      // Cloudflare may need several seconds for DNS propagation/edge readiness.
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(1000, Math.max(1, deadline - Date.now()))));
  }
  throw new Error('Cloudflare 临时控制台未能通过外网就绪检查，请检查服务器网络');
}

async function issueLocalTicket(localOrigin, control) {
  const response = await fetch(localOrigin + '/api/open', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + control, 'Content-Type': 'application/json' },
    body: '{}',
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error('Codex Guard 后端无法签发管理链接');
  const result = await response.json();
  const link = new URL(result.url);
  if (link.origin !== localOrigin || !/^\/open\/[a-f0-9]{48}$/.test(link.pathname) ||
      link.search || link.hash) {
    throw new Error('Codex Guard 后端签发的链接无效');
  }
  return link.pathname;
}

// Encapsulates only the optional, on-demand remote console. The Go backend
// keeps its loopback origin and full authorization checks intact.
export function createRemoteConsole({ localOrigin, control, dataDir, options = {} }) {
  let active = null;
  let starting = null;

  function close() {
    const current = active;
    active = null;
    if (!current) return;
    clearTimeout(current.timer);
    current.child.kill();
    current.proxy.close();
    void rm(current.directory, { recursive: true, force: true });
  }

  async function launch() {
    await mkdir(dataDir, { recursive: true, mode: 0o700 });
    const directory = await mkdtemp(path.join(dataDir, 'tunnel-'));
    let proxy;
    let child;
    try {
      proxy = await startRemoteProxy(localOrigin);
      const binary = await resolveCloudflared(options, dataDir);
      const configFile = path.join(directory, 'config.yaml');
      await writeFile(configFile, '{}\n', { mode: 0o600, flag: 'wx' });

      // A random quick tunnel, not a named Cloudflare tunnel. Never use the
      // host's permanent Cloudflare tunnel token or existing credentials.
      const env = Object.fromEntries(Object.entries(process.env)
        .filter(([key]) => !key.startsWith('TUNNEL_') && !key.startsWith('CLOUDFLARED_')));
      child = spawn(binary, [
        'tunnel', '--config', configFile, '--no-autoupdate',
        '--url', proxy.url, '--protocol', 'http2',
        '--edge-ip-version', '4', '--metrics', '127.0.0.1:0',
      ], { cwd: directory, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });

      const origin = await new Promise((resolve, reject) => {
        let identified = '';
        let registered = false;
        let buffer = '';
        const timeout = setTimeout(() => reject(new Error('Cloudflare 临时通道启动超时')), TUNNEL_START_TIMEOUT);
        function finish(error, url) {
          clearTimeout(timeout);
          if (error) reject(error);
          else resolve(url);
        }
        function handle(data) {
          buffer += data.toString('utf8');
          if (buffer.length > 32768) buffer = buffer.slice(-8192);
          const lines = buffer.split(/\r?\n/);
          buffer = lines.pop() || '';
          for (const line of lines) {
            identified ||= extractTunnelOrigin(line);
            if (line.includes('Registered tunnel connection')) registered = true;
          }
          if (identified && registered) finish(null, identified);
        }
        child.stderr.on('data', handle);
        child.stdout.on('data', handle);
        child.once('error', () => finish(new Error('Cloudflare 客户端无法启动')));
        child.once('exit', () => finish(new Error('Cloudflare 临时通道启动失败')));
      });

      proxy.setRemoteOrigin(origin);
      await waitForConsole(origin);
      const session = { origin, child, proxy, directory, timer: undefined };
      active = session;
      session.timer = setTimeout(() => {
        if (active === session) close();
      }, TUNNEL_LIFETIME);
      session.timer.unref?.();
      child.once('exit', () => {
        if (active === session) close();
      });
      return session;
    } catch (error) {
      child?.kill();
      proxy?.close();
      await rm(directory, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  }

  async function open() {
    if (!active) {
      if (!starting) starting = launch().finally(() => { starting = null; });
      await starting;
    } else {
      try {
        await waitForConsole(active.origin, 8000);
      } catch {
        close();
        if (!starting) starting = launch().finally(() => { starting = null; });
        await starting;
      }
    }
    if (!active) throw new Error('远程控制台已经关闭，请重新生成链接');
    const ticketPath = await issueLocalTicket(localOrigin, control);
    return active.origin + ticketPath;
  }

  return { open, close };
}
