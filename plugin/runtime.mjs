import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { chmod, mkdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';

const RELEASE = 'v0.1.0-alpha.24';
const RELEASE_FILE = 'magpie-codex-guard-0.1.0-alpha.24.tgz';
const ARCHIVE_URL =
  `https://github.com/Dsd1001/magpie-codex-guard/releases/download/${RELEASE}/${RELEASE_FILE}`;
const ARCHIVE_SHA256 = '7674137080acfe8ce9a2535ccf4b40d38d55452ed5358b4a86c2f920a74827bf';
const MAX_ARCHIVE_BYTES = 60 * 1024 * 1024;
const BINARIES = Object.freeze({
  'linux-amd64': '11c7125d5e27cb1573679f77a1ca13aa83af4cf40a8b5219e9c2aeb47d8bc2f1',
  'linux-arm64': 'ed02a446acdc35237c78fc60b4c5f0e091533161d349f234aaf5dbcf03fd42af',
  'darwin-arm64': '841666f86aa7932ba57d7e33f9cac8ee7c2c8d339f3cd6f99056b25588d7867a',
});

async function fileDigest(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function verified(file, expected) {
  try {
    return (await stat(file)).isFile() && (await fileDigest(file)) === expected;
  } catch {
    return false;
  }
}

async function unpackBinary(archive, binaryName, destination) {
  const member = `package/bin/${binaryName}`;
  const child = spawn('tar', ['-xzOf', archive, member], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (bytes) => {
    if (stderr.length < 2048) stderr += bytes.toString('utf8').slice(0, 2048);
  });
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`tar 解包失败（${code}）：${stderr.slice(0, 256)}`));
    });
  });
  await Promise.all([
    pipeline(child.stdout, createWriteStream(destination, { flags: 'wx', mode: 0o700 })),
    exit,
  ]);
}

export async function resolveBinary({ root, dataDir, binaryPath, fetcher = fetch }) {
  if (binaryPath) return binaryPath;
  const platform = process.platform === 'win32' ? 'windows' : process.platform;
  const arch = process.arch === 'x64' ? 'amd64' : process.arch;
  const target = `${platform}-${arch}`;
  const checksum = BINARIES[target];
  if (!checksum) {
    throw new Error(`Codex Guard 暂不支持 ${platform}/${arch}，请使用 Linux AMD64/ARM64 或 macOS ARM64`);
  }
  const binaryName = `codex-guard-${target}`;
  const bundled = path.join(root, 'bin', binaryName);
  if (existsSync(bundled)) return bundled;

  // A github: installation contains source only. Magpie's Bun install does
  // NOT run postinstall, so obtain the published, SHA-pinned helper at runtime.
  const runtimeDir = path.join(dataDir, 'runtime', RELEASE);
  const destination = path.join(runtimeDir, binaryName);
  if (await verified(destination, checksum)) return destination;
  await mkdir(runtimeDir, { recursive: true, mode: 0o700 });

  const id = `${process.pid}-${randomBytes(8).toString('hex')}`;
  const archive = path.join(runtimeDir, `.${id}.tgz`);
  const temporaryBinary = path.join(runtimeDir, `.${id}.bin`);
  try {
    const response = await fetcher(ARCHIVE_URL, {
      redirect: 'follow',
      headers: { 'User-Agent': 'magpie-codex-guard/0.1.0-alpha.25' },
    });
    if (!response.ok) throw new Error(`下载失败：HTTP ${response.status}`);
    const length = Number(response.headers?.get?.('content-length') || 0);
    if (length > MAX_ARCHIVE_BYTES) throw new Error('安装包超过大小上限');
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_ARCHIVE_BYTES) throw new Error('安装包超过大小上限');
    const archiveDigest = createHash('sha256').update(bytes).digest('hex');
    if (archiveDigest !== ARCHIVE_SHA256) throw new Error('Release 安装包 SHA-256 校验失败');
    await writeFile(archive, bytes, { flag: 'wx', mode: 0o600 });
    await unpackBinary(archive, binaryName, temporaryBinary);
    if (!(await verified(temporaryBinary, checksum))) {
      throw new Error('后端可执行文件 SHA-256 校验失败');
    }
    await chmod(temporaryBinary, 0o700);
    await rename(temporaryBinary, destination);
    return destination;
  } catch (error) {
    throw new Error(`Codex Guard 无法准备本机检测后端，请检查 GitHub Release 下载：${error.message}`);
  } finally {
    await Promise.all([rm(archive, { force: true }), rm(temporaryBinary, { force: true })]);
  }
}
