import { chromium } from '../../../web/node_modules/playwright/index.mjs';
import { chmod, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
const [base, output] = process.argv.slice(2);
const chromePidFile = join(dirname(output), 'chrome.pid');
const chromeWrapper = join(dirname(output), 'chrome-wrapper.sh');
await writeFile(chromeWrapper, '#!/bin/sh\necho $$ > "$CHROME_PID_FILE"\nexec /usr/bin/google-chrome "$@"\n');
await chmod(chromeWrapper, 0o700);
const browser = await chromium.launch({executablePath:chromeWrapper, env:{...process.env, CHROME_PID_FILE:chromePidFile}, headless:true, args:['--no-sandbox','--no-proxy-server','--host-resolver-rules=MAP example.test 127.0.0.1','--ignore-certificate-errors']});
try {
  const external = [];
  const solve = async (path, expectedBody) => {
    const context = await browser.newContext({ignoreHTTPSErrors:true});
    const page = await context.newPage();
    page.on('request', req => { if (/^https?:/.test(req.url()) && !req.url().startsWith(base + '/')) external.push(req.url()); });
    const response = await page.goto(base + path, {waitUntil:'domcontentloaded'});
    if (response.status() !== 429) throw Error(`challenge status ${response.status()} for ${path}`);
    await page.locator('altcha-widget').waitFor();
    await page.getByText('Verified', {exact:true}).waitFor({timeout:30000});
    const verification = page.waitForResponse(r => r.url().includes('/__antiddos/verify'));
    await page.locator('button[type=submit]').click();
    const verified = await verification;
    if (verified.status() !== 303) throw Error(`verify status ${verified.status()} for ${path}`);
    await page.waitForURL(base + path, {timeout:15000});
    const body = await page.locator('body').innerText();
    if (!body.includes(expectedBody)) throw Error(`protected upstream not reached for ${path}: ${body}`);
    const cookies = await context.cookies();
    const pass = cookies.find(c => c.name === '__Host-antiddos_pass');
    if (!pass?.secure || !pass.httpOnly) throw Error(`pass cookie flags invalid for ${path}`);
    const result = {status:response.status(), verify:verified.status(), final:page.url(), pass_secure:pass.secure, pass_httpOnly:pass.httpOnly};
    await context.close();
    return result;
  };
  const protectedResult = await solve('/protected?q=browser', '"uri": "/protected?q=browser"');
  const rewriteResult = await solve('/rewrite', '"uri": "/protected?rewritten=1"');
  if (external.length) throw Error('external requests: '+JSON.stringify(external));
  await writeFile(output, JSON.stringify({protected:protectedResult, rewrite:rewriteResult, external}, null, 2)+'\n');
} finally { await browser.close(); }
