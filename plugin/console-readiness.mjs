export async function waitForConsole(url, options = {}) {
  const fetcher = options.fetch || fetch;
  const timeout = options.timeout ?? 60000;
  const interval = options.interval ?? 1000;
  const deadline = Date.now() + timeout;
  const health = new URL('/health', url);
  let lastStatus, networkCode;
  while (Date.now() < deadline) {
    try {
      const r = await fetcher(health, {
        redirect: 'error',
        signal: AbortSignal.timeout(Math.max(1, Math.min(5000, deadline - Date.now()))),
      });
      lastStatus = r.status;
      const ready = r.status === 204 && r.headers.get('x-codex-guard') === 'ready';
      await r.body?.cancel();
      if (ready) return;
    } catch (error) {
      const code = error.cause?.code || error.code;
      if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ETIMEDOUT', 'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(code)) networkCode = code;
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(interval, Math.max(0, deadline - Date.now()))));
  }
  throw Error(`临时远程控制台尚不可用${lastStatus ? `（HTTP ${lastStatus}）` : networkCode ? `（${networkCode}）` : ''}，请检查服务器网络后重新打开。`);
}
