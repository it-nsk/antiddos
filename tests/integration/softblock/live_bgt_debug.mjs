import { chromium } from '../../../web/node_modules/playwright/index.mjs';

const browser = await chromium.launch({
  executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome',
  headless: true,
  args: ['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP bgt.my 127.0.0.1', '--ignore-certificate-errors'],
});

try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on('console', message => console.log(`console ${message.type()}: ${message.text()}`));
  page.on('response', async response => {
    if (!response.url().includes('/__antiddos/verify')) return;
    console.log(`verify response status=${response.status()} url=${response.url()}`);
    const headers = await response.allHeaders();
    console.log(`verify location=${headers.location || ''} pass_cookie=${headers['set-cookie']?.startsWith('__Host-antiddos_pass=') || false}`);
    if (response.status() < 300 || response.status() >= 400) {
      console.log(`verify body=${(await response.text()).slice(0, 500)}`);
    }
  });
  const initial = await page.goto('https://bgt.my/captcha-demo', { waitUntil: 'domcontentloaded' });
  console.log(`initial status=${initial.status()} url=${page.url()}`);
  await page.locator('altcha-widget').waitFor();
  await page.getByText('Verified', { exact: true }).waitFor({ timeout: 30000 });
  const request = await page.locator('form').evaluate(form => Object.fromEntries(new FormData(form)));
  console.log(`form fields=${JSON.stringify(Object.keys(request))}`);
  await page.locator('button[type=submit]').click();
  await page.waitForURL('https://bgt.my/captcha-demo', { timeout: 15000 });
  console.log(`final url=${page.url()}`);
  const cookies = await context.cookies();
  const pass = cookies.find(cookie => cookie.name === '__Host-antiddos_pass');
  if (!pass?.secure || !pass.httpOnly) throw new Error('valid pass cookie was not issued');
  console.log('pass cookie flags: Secure HttpOnly');
} finally {
  await browser.close();
}
