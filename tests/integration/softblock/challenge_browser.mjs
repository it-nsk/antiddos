import { chromium } from '../../../web/node_modules/playwright/index.mjs';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, writeFile, appendFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';

const root = process.cwd();
const runDir = process.env.SOFTBLOCK_RUN_DIR;
if (!runDir) throw new Error('SOFTBLOCK_RUN_DIR is required');
await mkdir(runDir, { recursive: true });
const cert = join(runDir, 'browser-cert.pem');
const key = join(runDir, 'browser-key.pem');
const binary = join(runDir, 'challenge-fixture');
const chromeWrapper = join(runDir, 'chrome-one-cpu.sh');
await writeFile(chromeWrapper, '#!/bin/sh\nexec /usr/bin/taskset -c 0 /usr/bin/google-chrome "$@"\n');
await chmod(chromeWrapper, 0o700);
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key, '-out', cert, '-subj', '/CN=example.test', '-addext', 'subjectAltName=DNS:example.test'], { stdio: 'ignore' });
execFileSync('go', ['build', '-o', binary, './tests/integration/softblock/cmd/challenge-fixture'], { cwd: root, env: process.env, stdio: 'inherit' });
const portServer = createServer();
await new Promise(resolve => portServer.listen(0, '127.0.0.1', resolve));
const port = portServer.address().port;
await new Promise(resolve => portServer.close(resolve));
const fixture = spawn(binary, [cert, key], { cwd: root, env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'] });
await writeFile(join(runDir, 'pids.txt'), `${fixture.pid}\n`);
let fixtureOutput = '';
fixture.stderr.setEncoding('utf8');
fixture.stderr.on('data', chunk => { fixtureOutput += chunk; void appendFile(join(runDir, 'fixture.log',), chunk); });
const waitReady = async () => {
  const until = Date.now() + 10000;
  while (Date.now() < until) {
    if (fixture.exitCode !== null) throw new Error(`fixture exited ${fixture.exitCode}: ${fixtureOutput}`);
    if (fixtureOutput.includes('READY')) return;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`fixture did not start: ${fixtureOutput}`);
};
let browser;
try {
  await waitReady();
  browser = await chromium.launch({ executablePath: chromeWrapper, headless: true, args: ['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP example.test 127.0.0.1', '--ignore-certificate-errors'] });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const externalRequests = [];
  const samples = [];
  let page;
  for (let iteration = 0; iteration < 10; iteration++) {
    page = await context.newPage();
    page.on('request', request => { const url = request.url(); if ((url.startsWith('http://') || url.startsWith('https://')) && !url.startsWith(`https://example.test:${port}/`)) externalRequests.push(url); });
    const start = performance.now();
    const response = await page.goto(`https://example.test:${port}/__antiddos/challenge`, { waitUntil: 'domcontentloaded' });
    if (response.status() !== 200) throw new Error(`challenge GET returned ${response.status()}`);
    await page.locator('altcha-widget').waitFor();
    await page.getByText('Verified', { exact: true }).waitFor({ timeout: 20000 });
    const verifyResponsePromise = page.waitForResponse(response => response.url().includes('/__antiddos/verify'));
    await page.locator('button[type=submit]').click();
    const verifyResponse = await verifyResponsePromise;
    if (verifyResponse.status() !== 303) throw new Error(`verify returned ${verifyResponse.status()}: ${(await verifyResponse.text()).slice(0, 300)}`);
    await page.waitForURL(url => url.pathname === '/protected' && url.searchParams.get('q') === 'browser-e2e', { timeout: 20000 });
    if (!(await page.locator('body').innerText()).includes('protected fixture')) throw new Error('pass cookie did not reach the protected fixture');
    samples.push(Math.round(performance.now() - start));
    await page.close();
  }
  if (externalRequests.length) throw new Error(`widget attempted external requests: ${externalRequests.join(', ')}`);
  const cookies = await context.cookies();
  const session = cookies.find(cookie => cookie.name === '__Host-antiddos_challenge');
  const pass = cookies.find(cookie => cookie.name === '__Host-antiddos_pass');
  if (!session?.secure || !session.httpOnly || !pass?.secure || !pass.httpOnly) throw new Error('Secure/HttpOnly browser or pass cookie missing');
  const sortedSamples = [...samples].sort((a, b) => a - b);
  const p95 = sortedSamples[Math.ceil(sortedSamples.length * 0.95) - 1];
  const report = { browser: await browser.version(), samples_ms: samples, p95_ms: p95, external_requests: externalRequests, cookies: cookies.map(({ name, secure, httpOnly, sameSite, path }) => ({ name, secure, httpOnly, sameSite, path })) };
  await writeFile(join(runDir, 'browser-results.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  if (browser) await browser.close();
  if (fixture.exitCode === null) {
    fixture.kill('SIGTERM');
    await new Promise(resolve => fixture.once('exit', resolve));
  }
  await rm(key, { force: true });
}
