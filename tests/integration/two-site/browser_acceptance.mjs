import {chromium} from '../../../web/node_modules/playwright/index.mjs';

const host=process.env.SITE_HOST;
if (!host) throw new Error('SITE_HOST is required');
const path=process.env.SITE_PATH||'/captcha-demo';
const browser=await chromium.launch({
  executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',headless:true,
  args:['--no-sandbox','--no-proxy-server',`--host-resolver-rules=MAP ${host} 127.0.0.1`,'--ignore-certificate-errors']
});
try {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  const first=await page.goto(`https://${host}${path}`,{waitUntil:'domcontentloaded',timeout:15000});
  const triggerStatuses=[first.status()];
  for(let i=0;i<8;i++){
    const status=await page.evaluate(async p=>(await fetch(p,{cache:'no-store'})).status,path);
    triggerStatuses.push(status);
    await new Promise(resolve=>setTimeout(resolve,1100));
  }
  const challenged=await page.goto(`https://${host}${path}`,{waitUntil:'domcontentloaded',timeout:15000});
  if(challenged.status()!==429) throw new Error(`expected challenge HTTP 429, got ${challenged.status()}`);
  await page.locator('altcha-widget').waitFor({timeout:10000});
  await page.getByText('Verified',{exact:true}).waitFor({timeout:30000});
  await Promise.all([
    page.waitForNavigation({waitUntil:'domcontentloaded',timeout:15000}),
    page.locator('button[type=submit]').click()
  ]);
  const cookies=await context.cookies();
  const pass=cookies.find(c=>c.name==='__Host-antiddos_pass');
  if(!pass?.secure||!pass.httpOnly) throw new Error('valid Secure/HttpOnly pass cookie was not set');
  const bypass=[];
  for(let i=0;i<10;i++){
    bypass.push(await page.evaluate(async p=>(await fetch(p,{cache:'no-store'})).status,path));
    await new Promise(resolve=>setTimeout(resolve,550));
  }
  if(bypass.some(status=>status===429||status===0)) throw new Error(`cookie bypass failed: ${bypass.join(',')}`);
  console.log(JSON.stringify({host,path,trigger_statuses:triggerStatuses,challenge_status:challenged.status(),verified:true,cookie:{secure:pass.secure,httpOnly:pass.httpOnly,sameSite:pass.sameSite,path:pass.path},bypass_statuses:bypass},null,2));
} finally {
  await browser.close();
}
