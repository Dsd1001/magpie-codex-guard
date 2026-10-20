import test from 'node:test';
import assert from 'node:assert/strict';
import { waitForConsole } from '../plugin/console-readiness.mjs';

test('remote readiness retries 502 without consuming the management ticket', async () => {
  let calls = 0;
  await waitForConsole('https://example.trycloudflare.com/open/private-ticket', {
    timeout: 1000, interval: 1,
    fetch: async (url, options) => {
      assert.equal(url.pathname, '/health');
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers, undefined);
      return ++calls === 1 ? new Response('<html>502</html>', { status: 502 }) :
        new Response(null, { status: 204, headers: { 'x-codex-guard': 'ready' } });
    },
  });
  assert.equal(calls, 2);
});
test('unavailable tunnel fails with a readable message rather than HTML', async () => {
  await assert.rejects(waitForConsole('https://example.trycloudflare.com/open/ticket', {
    timeout: 20, interval: 1, fetch: async () => new Response('<html>bad gateway</html>', { status: 502 }),
  }), /尚不可用（HTTP 502）/);
});
