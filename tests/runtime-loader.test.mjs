import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { resolveBinary } from '../plugin/runtime.mjs';

test('explicit binary override never accesses GitHub', async () => {
  const binary = '/tmp/guard-test-custom-binary';
  const chosen = await resolveBinary({
    root: '/does-not-exist',
    dataDir: '/does-not-exist',
    binaryPath: binary,
    fetcher: () => { throw new Error('network unexpectedly called'); },
  });
  assert.equal(chosen, binary);
});

test('a corrupted download never becomes an executable', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'guard-empty-package-'));
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'guard-runtime-cache-'));
  try {
    await assert.rejects(
      resolveBinary({
        root,
        dataDir,
        fetcher: async () => ({
          ok: true,
          headers: { get: () => null },
          arrayBuffer: async () => Uint8Array.from([0, 1, 2, 3]).buffer,
        }),
      }),
      /SHA-256 校验失败/,
    );
    const runtime = path.join(dataDir, 'runtime', 'v0.1.0-alpha.26');
    assert.deepEqual(await readdir(runtime), []);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(dataDir, { recursive: true, force: true });
  }
});
