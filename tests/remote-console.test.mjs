import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startRemoteProxy } from '../plugin/remote-proxy.mjs';
import { extractTunnelOrigin } from '../plugin/remote-console.mjs';
import { cloudflaredRelease } from '../plugin/cloudflared-runtime.mjs';

const REMOTE = 'https://fixture-remote.trycloudflare.com';
const HOST = 'fixture-remote.trycloudflare.com';

async function serve(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    origin: 'http://127.0.0.1:' + server.address().port,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

async function request(origin, method, route, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const address = new URL(origin);
    const client = http.request({
      hostname: address.hostname,
      port: address.port,
      path: route,
      method,
      headers: { host: HOST, ...headers },
    }, response => {
      const buffers = [];
      response.on('data', buf => buffers.push(buf));
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(buffers).toString('utf8'),
      }));
    });
    client.once('error', reject);
    if (body) client.write(body);
    client.end();
  });
}

test('Cloudflare origin parser and pinned releases reject irrelevant hosts', () => {
  assert.equal(extractTunnelOrigin('hello https://fixture-remote.trycloudflare.com connection'),
    REMOTE);
  assert.equal(extractTunnelOrigin('https://evil.trycloudflare.com.attacker.invalid'), '');
  assert.equal(extractTunnelOrigin('https://attacker.invalid'), '');
  assert.equal(cloudflaredRelease('linux', 'x64').target, 'linux-x64');
  assert.equal(cloudflaredRelease('linux', 'arm64').target, 'linux-arm64');
});

test('loopback proxy enforces registered Host, Origin and Go session, with secure HTTPS cookie', async t => {
  const captured = [];
  const backend = await serve((req, res) => {
    captured.push({ host: req.headers.host, origin: req.headers.origin, authorization: req.headers.authorization, path: req.url });
    if (req.url === '/health') {
      res.writeHead(204, { 'X-Codex-Guard': 'ready' }); res.end();
    } else if (req.url === '/open/example') {
      res.writeHead(303, {
        Location: '/',
        'Set-Cookie': 'guard_session=fake-session; Path=/; HttpOnly; SameSite=Strict',
      });
      res.end();
    } else if (req.url === '/api/state' && req.headers.cookie !== 'guard_session=fake-session') {
      res.writeHead(401); res.end('session missing');
    } else if (req.url === '/api/state') {
      res.writeHead(200); res.end('{"ok":true}');
    } else {
      res.writeHead(200); res.end('upstream=' + String(req.headers.origin));
    }
  });
  const proxy = await startRemoteProxy(backend.origin);
  t.after(() => proxy.close());
  t.after(() => backend.close());

  assert.equal((await request(proxy.url, 'GET', '/health')).status, 403);
  assert.throws(() => proxy.setRemoteOrigin('https://attacker.invalid'), /域名/);
  proxy.setRemoteOrigin(REMOTE);

  assert.equal((await request(proxy.url, 'GET', '/health', {host:'attacker.invalid'})).status, 403);
  assert.equal((await request(proxy.url, 'POST', '/api/config', {'origin':'https://attacker.invalid'})).status, 403);
  assert.equal((await request(proxy.url, 'POST', '/api/config')).status, 403);
  assert.equal((await request(proxy.url, 'GET', '/api/open')).status, 404);

  const health = await request(proxy.url, 'GET', '/health');
  assert.equal(health.status, 204);
  assert.equal(health.headers['x-codex-guard'], 'ready');

  const link = await request(proxy.url, 'GET', '/open/example');
  assert.equal(link.status, 303);
  assert.match(link.headers['set-cookie'][0], /HttpOnly/);
  assert.match(link.headers['set-cookie'][0], /SameSite=Strict/);
  assert.match(link.headers['set-cookie'][0], /;\s*Secure/);
  assert.equal(link.headers.location, '/');

  const unauthed = await request(proxy.url, 'GET', '/api/state');
  assert.equal(unauthed.status, 401);
  const authed = await request(proxy.url, 'GET', '/api/state', {cookie:'guard_session=fake-session'});
  assert.equal(authed.status, 200);
  assert.equal(authed.body, '{"ok":true}');

  const mutation = await request(proxy.url, 'POST', '/api/config', {
    origin: REMOTE,
    'content-type': 'application/json',
    authorization:'Bearer must-never-be-proxied',
  }, '{}');
  assert.equal(mutation.status, 200);
  assert.equal(mutation.body, 'upstream=' + backend.origin);

  const post = captured.at(-1);
  assert.equal(post.host, new URL(backend.origin).host);
  assert.equal(post.origin, backend.origin);
  assert.equal(post.authorization, undefined);
});

test('refuses non-loopback Go endpoint and oversized request bodies', async t => {
  await assert.rejects(startRemoteProxy('http://localhost:3425'), /本机监听地址/);
  const backend = await serve((req,res) => { res.writeHead(200); res.end('ok'); });
  const proxy = await startRemoteProxy(backend.origin);
  t.after(() => proxy.close());
  t.after(() => backend.close());
  proxy.setRemoteOrigin(REMOTE);
  const result = await request(proxy.url, 'POST', '/api/config', {
    origin:REMOTE,
    'content-length':'70000',
  });
  assert.equal(result.status, 413);
});
