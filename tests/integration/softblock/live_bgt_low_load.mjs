// Deliberately bounded local demonstration: one browser, 20 requests at 2/s.
// The hostname is always mapped to loopback. Never print or persist cookies.
import {chromium} from '../../../web/node_modules/playwright/index.mjs';

const browser = await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--no-proxy-server','--host-resolver-rules=MAP bgt.my 127.0.0.1','--ignore-certificate-errors']});
try {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  await page.goto('https://bgt.my/captcha-demo',{waitUntil:'domcontentloaded',timeout:15000});
  const triggers = await page.evaluate(async()=>Promise.all(Array.from({length:4},async()=>{const r=await fetch('/captcha-demo',{cache:'no-store'});return r.status})));
  await new Promise(resolve=>setTimeout(resolve,3000));
  const response = await page.goto('https://bgt.my/captcha-demo',{waitUntil:'domcontentloaded',timeout:15000});
  if (response.status()!==429) throw new Error(`expected challenge HTTP 429, got ${response.status()}`);
  if (await page.locator('altcha-widget').count()===0) throw new Error(`challenge page is unavailable after triggering: ${(await page.locator('body').innerText()).slice(0,120)}`);
  await page.getByText('Verified',{exact:true}).waitFor({timeout:30000});
  await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded',timeout:15000}),page.locator('button[type=submit]').click()]);
  if (page.url() !== 'https://bgt.my/captcha-demo') throw new Error(`unexpected return URL ${page.url()}`);
  const cookies = await context.cookies();
  if (!cookies.some(c=>c.name==='__Host-antiddos_pass'&&c.secure&&c.httpOnly)) throw new Error('no valid pass cookie');
  const results = await page.evaluate(async()=>{
    const samples=[];
    for(let i=0;i<20;i++){
      const start=performance.now();
      try {const r=await fetch('/captcha-demo',{cache:'no-store'}); await r.arrayBuffer();samples.push({status:r.status,ms:performance.now()-start})}
      catch {samples.push({status:0,ms:performance.now()-start})}
      if(i<19)await new Promise(resolve=>setTimeout(resolve,500));
    }
    return samples;
  });
  const latencies=results.map(r=>r.ms).sort((a,b)=>a-b);
  const percentile=p=>Number(latencies[Math.ceil(latencies.length*p)-1].toFixed(2));
  const statuses={};for(const r of results)statuses[r.status]=(statuses[r.status]||0)+1;
  console.log(JSON.stringify({target:'https://bgt.my/captcha-demo -> 127.0.0.1',trigger_statuses:triggers,challenge_status:response.status(),verified:true,requests:results.length,interval_ms:500,statuses,latency_ms:{p50:percentile(.5),p95:percentile(.95),p99:percentile(.99),max:percentile(1)}},null,2));
} finally {await browser.close()}
