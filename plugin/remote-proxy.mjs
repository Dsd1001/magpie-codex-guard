import http from 'node:http';

const MAX_BODY = 64 * 1024;
const SAFE_METHODS = new Set(['GET', 'HEAD']);

function fail(response, status, message) {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(message);
}

function secureCookies(cookies) {
  if (!cookies) return cookies;
  const values = Array.isArray(cookies) ? cookies : [cookies];
  return values.map(value => /(?:^|;)\s*Secure(?:;|$)/i.test(value) ? value : value + '; Secure');
}

// The Go service deliberately accepts only its own loopback Host and Origin.
// Only the private Cloudflare tunnel, with the exact registered HTTPS hostname,
// can reach this bridge. Do not expose the bridge on 0.0.0.0.
export async function startRemoteProxy(localOrigin) {
  const local = new URL(localOrigin);
  if (local.protocol !== 'http:' || local.hostname !== '127.0.0.1') {
    throw new Error('远程控制台只能代理 Codex Guard 的本机监听地址');
  }

  let remoteOrigin = '';
  let remoteHost = '';
  const server = http.createServer((req, res) => {
    if (!remoteHost || req.headers.host !== remoteHost) {
      fail(res, 403, '管理域名不匹配');
      return;
    }
    if (!req.url || !req.url.startsWith('/') || req.url.startsWith('//') ||
        /[\r\n]/.test(req.url)) {
      fail(res, 400, '请求路径无效');
      return;
    }
    if (req.url === '/api/open' || req.url.startsWith('/api/open?') ||
        !['GET', 'HEAD', 'POST', 'PUT', 'DELETE'].includes(req.method)) {
      fail(res, 404, '接口不可用');
      return;
    }
    if (!SAFE_METHODS.has(req.method) && req.headers.origin !== remoteOrigin) {
      fail(res, 403, 'Origin 不匹配');
      return;
    }
    const bodyLength = Number(req.headers['content-length'] || '0');
    if (!Number.isFinite(bodyLength) || bodyLength < 0 || bodyLength > MAX_BODY) {
      fail(res, 413, '请求正文过大');
      return;
    }

    const headers = {
      host: local.host,
      accept: req.headers.accept || '*/*',
    };
    for (const name of ['content-type', 'content-length', 'cookie', 'accept-language',
      'user-agent', 'if-none-match', 'if-modified-since']) {
      if (req.headers[name] !== undefined) headers[name] = req.headers[name];
    }
    if (!SAFE_METHODS.has(req.method)) headers.origin = localOrigin;

    const upstream = http.request({
      hostname: local.hostname,
      port: Number(local.port),
      method: req.method,
      path: req.url,
      headers,
      timeout: 15000,
    }, reply => {
      if (res.destroyed) {
        reply.destroy();
        return;
      }
      const responseHeaders = { ...reply.headers };
      delete responseHeaders.connection;
      delete responseHeaders['transfer-encoding'];
      if (responseHeaders['set-cookie']) {
        responseHeaders['set-cookie'] = secureCookies(responseHeaders['set-cookie']);
      }
      responseHeaders['Strict-Transport-Security'] = 'max-age=1800';
      res.writeHead(reply.statusCode || 502, responseHeaders);
      reply.pipe(res);
    });

    upstream.on('error', () => fail(res, 502, '本机检测后台暂不可用'));
    upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
    req.on('aborted', () => upstream.destroy());
    let bytes = 0;
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_BODY) {
        upstream.destroy();
        fail(res, 413, '请求正文过大');
        req.pause();
        return;
      }
      if (!upstream.write(chunk)) req.pause();
    });
    upstream.on('drain', () => req.resume());
    req.on('end', () => {
      if (bytes <= MAX_BODY) upstream.end();
    });
    req.on('error', () => upstream.destroy());
  });

  server.requestTimeout = 20000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  return {
    url: 'http://127.0.0.1:' + server.address().port,
    setRemoteOrigin(origin) {
      const parsed = new URL(origin);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
          parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash ||
          !/^[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com$/.test(parsed.hostname)) {
        throw new Error('临时控制台域名验证失败');
      }
      remoteOrigin = parsed.origin;
      remoteHost = parsed.host;
    },
    close() {
      server.close();
      server.closeAllConnections?.();
    },
  };
}
