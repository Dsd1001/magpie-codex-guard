import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, mkdir, copyFile, readFile, writeFile } from 'node:fs/promises';
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
    const runtimeRoot = path.join(dataDir, 'runtime');
    const versions = await readdir(runtimeRoot);
    assert.equal(versions.length, 1);
    assert.deepEqual(await readdir(path.join(runtimeRoot, versions[0])), []);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(dataDir, { recursive: true, force: true });
  }
});


test('release pinning uses the newly published package version and is idempotent', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'guard-pin-release-'));
  try {
    await mkdir(path.join(root, 'plugin'));
    await mkdir(path.join(root, 'scripts'));
    await copyFile(new URL('../plugin/runtime.mjs', import.meta.url), path.join(root, 'plugin/runtime.mjs'));
    await copyFile(new URL('../scripts/pin-runtime-checksums.py', import.meta.url), path.join(root, 'scripts/pin.py'));
    const version = '9.8.7-test';
    await writeFile(path.join(root, 'package.json'), JSON.stringify({version}));
    const checksums = [
      ['1'.repeat(64), `magpie-codex-guard-${version}.tgz`],
      ['2'.repeat(64), 'codex-guard-linux-amd64'],
      ['3'.repeat(64), 'codex-guard-linux-arm64'],
      ['4'.repeat(64), 'codex-guard-darwin-arm64'],
    ].map(([hash, file]) => `${hash}  dist/${file}`).join('\n').replaceAll('\\n', '\n');
    const shaFile = path.join(root, 'SHA256SUMS.txt');
    await writeFile(shaFile, checksums);
    const run = () => spawnSync('python3', [path.join(root, 'scripts/pin.py'), shaFile], {encoding:'utf8'});
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const file = path.join(root, 'plugin/runtime.mjs');
    const first = await readFile(file, 'utf8');
    assert.ok(first.includes(`const RELEASE = 'v${version}'`));
    assert.ok(first.includes(`const RELEASE_FILE = 'magpie-codex-guard-${version}.tgz'`));
    assert.ok(first.includes(`'User-Agent': 'magpie-codex-guard/${version}'`));
    assert.ok(first.includes(`const ARCHIVE_SHA256 = '${'1'.repeat(64)}'`));
    result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await readFile(file, 'utf8'), first);
  } finally {
    await rm(root, {recursive:true, force:true});
  }
});
