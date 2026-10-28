import { chromium } from '../../../web/node_modules/playwright/index.mjs';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, writeFile, appendFile, chmod, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const root = process.cwd();
const runDir = resolve(process.env.SOFTBLOCK_RUN_DIR || 'runtime/softblock/demo-local');
await mkdir(runDir, { recursive: true });
const cert = join(runDir, 'demo-cert.pem');
const key = join(runDir, 'demo-key.pem');
const binary = join(runDir, 'challenge-demo-fixture');
const chrome = process.env.CHROME_PATH || '/usr/bin/google-chrome';
const headless = process.env.SOFTBLOCK_DEMO_HEADLESS === '1';

execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key, '-out', cert, '-subj', '/CN=example.test', '-addext', 'subjectAltName=DNS:example.test'], { stdio: 'ignore' });
execFileSync('go', ['build', '-o', binary, './tests/integration/softblock/challenge_fixture.go'], { cwd: root, env: process.env, stdio: 'inherit' });
const portServer = createServer();
await new Promise(resolvePort => portServer.listen(0, '127.0.0.1', resolvePort));
const port = portServer.address().port;
await new Promise(resolvePort => portServer.close(resolvePort));
const fixture = spawn(binary, [cert, key], { cwd: root, env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'] });
let fixtureOutput = '';
fixture.stderr.setEncoding('utf8');
fixture.stderr.on('data', chunk => { fixtureOutput += chunk; void appendFile(join(runDir, 'demo-fixture.log'), chunk); });
const waitReady = async () => {
  const until = Date.now() + 10000;
  while (Date.now() < until) {
    if (fixture.exitCode !== null) throw new Error(`fixture exited ${fixture.exitCode}: ${fixtureOutput}`);
    if (fixtureOutput.includes('READY')) return;
    await new Promise(resolveWait => setTimeout(resolveWait, 25));
  }
  throw new Error(`fixture did not start: ${fixtureOutput}`);
};

let browser;
let finished;
const stopped = new Promise(resolveStop => { finished = resolveStop; });
const stop = () => finished();
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
try {
  await waitReady();
  browser = await chromium.launch({ executablePath: chrome, headless, args: ['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP example.test 127.0.0.1', '--ignore-certificate-errors'] });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto(`https://example.test:${port}/__antiddos/challenge`, { waitUntil: 'domcontentloaded' });
  await page.locator('altcha-widget').waitFor();
  console.log(`Demo URL: https://example.test:${port}/__antiddos/challenge`);
  console.log('Chrome открыт с локальной ALTCHA-страницей. Дождитесь Verified и нажмите Continue.');
  console.log('Для завершения demo нажмите Ctrl+C. Внешние HTTP(S)-запросы запрещены.');
  await stopped;
} finally {
  process.removeListener('SIGINT', stop);
  process.removeListener('SIGTERM', stop);
  if (browser) await browser.close();
  if (fixture.exitCode === null) {
    fixture.kill('SIGTERM');
    await new Promise(resolveExit => fixture.once('exit', resolveExit));
  }
  await rm(key, { force: true });
}
