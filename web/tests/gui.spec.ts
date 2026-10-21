import {test,expect} from '@playwright/test';
import {readFileSync,writeFileSync,appendFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const password='test-only-long-password';
async function login(page:any,user='admin'){await page.goto('/');await page.getByLabel('Пользователь',{exact:true}).fill(user);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('heading',{name:/Обзор трафика/})).toBeVisible()}
test('admin: real daemon stats, graphs, whitelist, restart and users',async({page})=>{
 test.setTimeout(60000);
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
 await login(page);await expect(page.getByText('Режим наблюдения',{exact:true})).toBeVisible();
 const localInput=(time:number)=>{const date=new Date(time);return new Date(time-date.getTimezoneOffset()*60000).toISOString().slice(0,16)};
 const rangeEnd=Date.now();await page.getByLabel('Начало периода',{exact:true}).fill(localInput(rangeEnd-61*60*1000));await page.getByLabel('Конец периода',{exact:true}).fill(localInput(rangeEnd));await expect(page.locator('.metric strong').first()).toHaveText(String(fixture.expectedRequests));
 await page.getByRole('button',{name:'15 мин',exact:true}).click();await expect(page.getByRole('button',{name:'15 мин',exact:true})).toHaveClass(/active/);
 const chart=page.locator('.chart svg').first();const bounds=(await chart.boundingBox())!;await page.mouse.move(bounds.x+bounds.width*.3,bounds.y+bounds.height*.5);await page.mouse.down();await page.mouse.move(bounds.x+bounds.width*.7,bounds.y+bounds.height*.5);await page.mouse.up();await expect(page.getByLabel('Сейчас',{exact:true})).not.toBeChecked();
 await page.getByRole('button',{name:'1 час',exact:true}).click();await page.screenshot({path:'../runtime/web-e2e/dashboard.png',fullPage:true});
 await page.getByRole('button',{name:'Срабатывания и блокировки'}).click();await expect(page.getByRole('cell',{name:'192.0.2.10',exact:true}).first()).toBeVisible();await expect(page.getByRole('cell',{name:'login',exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:/Пользователи/}).click();await expect(page.getByRole('cell',{name:'viewer',exact:true})).toBeVisible();
 await page.getByRole('button',{name:/Правила и фильтры/}).click();
 await page.getByLabel('Глобальный IP 1',{exact:true}).fill('203.0.113.10');await page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true}).click();await page.getByLabel('Глобальный IP 2',{exact:true}).fill('203.0.113.20');
 await page.getByRole('button',{name:'Удалить глобальный IP 2',exact:true}).click();await page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true}).click();await page.getByLabel('Глобальный IP 2',{exact:true}).fill('2001:db8::1');
 await page.getByRole('button',{name:'Добавить IP в whitelist homepage',exact:true}).click();await page.getByRole('button',{name:'Добавить IP в whitelist homepage',exact:true}).click();
 await page.getByLabel('IP homepage 1',{exact:true}).fill('192.0.2.10');await page.getByLabel('IP homepage 2',{exact:true}).fill('192.0.2.20');await page.getByRole('button',{name:'Удалить IP homepage 2',exact:true}).click();
 await page.getByLabel('Регулярное выражение homepage',{exact:true}).fill('^/landing$');await page.getByLabel('Режим блокировки',{exact:true}).selectOption('nftables');page.once('dialog',async dialog=>{expect(dialog.message()).toContain('Включить реальные блокировки?');await dialog.accept()});await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();await expect(page.getByRole('status')).toContainText('Сохранено');
 let config=JSON.parse(readFileSync(fixture.config,'utf8'));expect(config.block_mode).toBe('nftables');expect(config.engine.ignore_ips).toEqual(['203.0.113.10','2001:db8::1']);expect(config.engine.rules[0].ignore_ips).toEqual(['192.0.2.10']);expect(config.engine.rules[0].path_regex).toEqual('^/landing$');expect(config.engine.rules[1].ignore_ips).toEqual(['198.51.100.7/32']);
 await expect(page.getByText('Настройки сохранены, но демон пока работает со старой конфигурацией.',{exact:false})).toBeVisible();await page.screenshot({path:'../runtime/web-e2e/whitelist.png',fullPage:true});
 await page.getByLabel('Режим блокировки',{exact:true}).selectOption('dry_run');await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();await expect(page.getByRole('status')).toContainText('Сохранено');config=JSON.parse(readFileSync(fixture.config,'utf8'));expect(config.block_mode).toBe('dry_run');
 process.kill(fixture.harnessPID,'SIGUSR1');await expect(page.getByText('Настройки сохранены, но демон пока работает со старой конфигурацией.',{exact:false})).toHaveCount(0,{timeout:20000});
 await page.getByRole('button',{name:'Выйти',exact:true}).click();await expect(page.getByRole('heading',{name:'Вход в AntiDDoS'})).toBeVisible();expect(errors).toEqual([]);
});
test('viewer: no mutation controls or user list; CLI password change revokes session',async({page})=>{
 test.setTimeout(60000);
 await login(page,'viewer');await expect(page.getByRole('button',{name:/Пользователи/})).toHaveCount(0);
 await page.getByRole('button',{name:/Правила и фильтры/}).click();await expect(page.getByLabel('Глобальный IP 1',{exact:true})).toHaveAttribute('readonly','');await expect(page.getByLabel('Регулярное выражение homepage',{exact:true})).toHaveAttribute('readonly','');await expect(page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Сохранить изменения',exact:true})).toHaveCount(0);
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));execFileSync(fixture.bin,['user','password','--users-db',fixture.users,'--password-stdin','viewer'],{input:'replacement-test-password\n'});
 await expect(page.getByRole('heading',{name:'Вход в AntiDDoS'})).toBeVisible({timeout:20000});
});
test('mobile login and invalid credentials',async({page})=>{await page.setViewportSize({width:390,height:844});await page.goto('/');await page.getByLabel('Пользователь',{exact:true}).fill('admin');await page.getByLabel('Пароль',{exact:true}).fill('incorrect-password');await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Неверное имя пользователя или пароль');await page.screenshot({path:'../runtime/web-e2e/login-mobile.png',fullPage:true})});


test('validation errors never show saved or modify the config; conflicting edits are rejected',async({page})=>{
 test.setTimeout(60000);
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
 const original=readFileSync(fixture.config,'utf8');
 await login(page);
 await page.getByRole('button',{name:/Правила и фильтры/}).click();
 for(const [label,value] of [['Регулярное выражение homepage','['],['Глобальный IP 1','not-an-ip']]){
  await page.getByLabel(label,{exact:true}).fill(value);
  const response=page.waitForResponse(r=>r.url().endsWith('/api/config/rules')&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
  expect((await response).status()).toBe(400);
  await expect(page.getByRole('status')).toHaveCount(0);
  await expect(page.getByRole('alert').last()).toBeVisible();
  expect(readFileSync(fixture.config,'utf8')).toBe(original);
  await page.getByRole('button',{name:'Отменить изменения',exact:true}).click();
 }
 await page.getByLabel('Регулярное выражение homepage',{exact:true}).fill('^/draft$');
 const external=JSON.parse(original);external.engine.rules[0].path_regex='^/external$';
 try{
  writeFileSync(fixture.config,JSON.stringify(external));
  const response=page.waitForResponse(r=>r.url().endsWith('/api/config/rules')&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
  expect((await response).status()).toBe(409);
  await expect(page.getByRole('status')).toHaveCount(0);
  expect(JSON.parse(readFileSync(fixture.config,'utf8')).engine.rules[0].path_regex).toBe('^/external$');
 }finally{writeFileSync(fixture.config,original)}
});

test('nftables confirmation can be cancelled without saving',async({page})=>{
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
 const original=readFileSync(fixture.config,'utf8');
 await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();
 await page.getByLabel('Режим блокировки',{exact:true}).selectOption('nftables');
 let writes=0;page.on('request',r=>{if(r.method()==='PUT')writes++});
 page.once('dialog',dialog=>dialog.dismiss());
 await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
 expect(writes).toBe(0);expect(readFileSync(fixture.config,'utf8')).toBe(original);
 await expect(page.getByRole('status')).toHaveCount(0);
});

test('live multi-source traffic and applied rule whitelists; graphs and pagination',async({page})=>{
 test.setTimeout(90000);
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
 const config=JSON.parse(readFileSync(fixture.config,'utf8'));
 expect(config.block_mode).toBe('dry_run');
 await login(page);
 await page.getByText('Графики по отдельным источникам (2)',{exact:true}).click();
 const groups=page.locator('.source-graphs');await expect(groups).toHaveCount(2);
 for(const group of await groups.all()){
  await group.locator('summary').click();await expect(group.locator('svg')).toHaveCount(4);
 }
 await page.screenshot({path:'../runtime/web-e2e/sources.png',fullPage:true});
 await page.getByRole('button',{name:/Срабатывания и блокировки/}).click();
 await expect(page.getByRole('columnheader',{name:'Источник лога',exact:true})).toBeVisible();
 const first=await page.locator('tbody tr').first().innerText();
 await page.getByRole('button',{name:'Ранее →',exact:true}).click();
 await expect.poll(()=>page.locator('tbody tr').first().innerText()).not.toBe(first);
 await page.getByRole('button',{name:'К последним',exact:true}).click();
 await expect.poll(()=>page.locator('tbody tr').first().innerText()).toBe(first);
 const now=new Date(), start=Math.floor(now.getTime()/15000)*15-15, end=start+60;
 const endpoint=`/api/dashboard?from=${start}&to=${end}`;
 const before=await (await page.request.get(endpoint)).json();
 const sum=(points:any[])=>points.reduce((total,p)=>total+p.requests,0);
 const stamp=`${String(now.getUTCDate()).padStart(2,'0')}/${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][now.getUTCMonth()]}/${now.getUTCFullYear()}:${now.toISOString().slice(11,19)} +0000`;
 const lines=(ip:string,path:string)=>Array.from({length:6},()=>`${ip} - - [${stamp}] "GET ${path} HTTP/1.1" 200 256 "-" "web-live-check"\n`).join('');
 appendFileSync(config.log_sources.main,lines('192.0.2.50','/landing')+lines('192.0.2.10','/landing')+lines('192.0.2.60','/'));
 appendFileSync(config.log_sources.admin,lines('198.51.100.50','/login')+lines('198.51.100.7','/login'));
 await expect.poll(async()=>sum((await (await page.request.get(endpoint)).json()).points),{timeout:45000}).toBe(sum(before.points)+30);
 const after=await (await page.request.get(endpoint)).json();
 for(const [source,added] of [['main',18],['admin',12]] as const){
  const previous=before.source_points.find((s:any)=>s.source_id===source)?.points??[];
  expect(sum(after.source_points.find((s:any)=>s.source_id===source).points)).toBe(sum(previous)+added);
 }
 const added=after.detections.filter((d:any)=>d.user_agent==='web-live-check');
 expect(added.length).toBeGreaterThan(0);
 expect([...new Set(added.map((d:any)=>d.ip))].sort()).toEqual(['192.0.2.50','198.51.100.50']);
 expect([...new Set(added.map((d:any)=>d.source_id))].sort()).toEqual(['admin','main']);
 expect(after.block_count).toBe(0);
 await page.getByRole('button',{name:/Обзор трафика/}).click();
 await page.getByRole('button',{name:'Обновить',exact:true}).click();
 await page.screenshot({path:'../runtime/web-e2e/live-dashboard.png',fullPage:true});
});

test('active block source and expiry are visible without touching the firewall',async({page})=>{
 test.setTimeout(40000);
 const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
 const config=JSON.parse(readFileSync(fixture.config,'utf8'));
 // Seed a storage fixture only: this exercises the dashboard, not nftables enforcement.
 execFileSync('python3',['-c',
  'import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); n=int(time.time()*1000); c.execute("INSERT OR REPLACE INTO active_blocks(ip,rule_id,started_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?)",("192.0.2.99","homepage",n,n+15000)); c.commit(); c.close()',
  config.database_path]);
 try{
  await login(page);
  const block=page.getByRole('row').filter({hasText:'192.0.2.99'});
  await expect(block).toBeVisible();await expect(block).toContainText('main');await expect(block).toContainText('homepage');
  await expect(block).toHaveCount(0,{timeout:30000});
 }finally{
  execFileSync('python3',['-c','import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("DELETE FROM active_blocks WHERE ip=?",("192.0.2.99",)); c.commit(); c.close()',config.database_path]);
 }
});
