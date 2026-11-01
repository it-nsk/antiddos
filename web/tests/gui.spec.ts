import {test,expect} from '@playwright/test';
import {readFileSync,writeFileSync,appendFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const password='test-only-long-password';
const artifact=process.env.ANTIDDOS_E2E_ARTIFACT||'../runtime/web-e2e';
const fixturePath=`${artifact}/fixture.json`;
async function login(page:any,user='admin'){await page.goto('/');await page.getByLabel('Пользователь',{exact:true}).fill(user);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('heading',{name:/Обзор трафика/})).toBeVisible()}
test('soft-block checker metrics are separate from detections',async({page})=>{
 await page.route('**/api/config',async route=>{const response=await route.fetch();const body=await response.json();body.config.block_mode='soft_block';body.config.soft_block={cookie_ttl:'30m',sites:{bgt:{hosts:['bgt.my'],log_sources:['web']}}};body.daemon.block_mode='soft_block';await route.fulfill({response,json:body})});
 await page.route('**/api/challenge/status',route=>route.fulfill({json:{health:'ready',metrics_health:'ready',metrics_dropped:0,sites:1}}));
 await page.route('**/api/challenge/metrics**',route=>route.fulfill({json:[{bucket:Math.floor(Date.now()/1000)-30,site:'bgt',reason:'issued',count:5}]}));
 await page.route('**/api/soft-blocks',route=>route.fulfill({json:[{site_id:'bgt',rule_id:'demo',source_id:'web',ip:'192.0.2.4',created_at:new Date().toISOString(),expires_at:new Date(Date.now()+60000).toISOString()}]}));
 await login(page,'viewer');await expect(page.getByText('Проверки CAPTCHA',{exact:true})).toBeVisible();await expect(page.getByRole('listitem').filter({hasText:'bgt · Выдано · 5'})).toBeVisible();await expect(page.getByText('Soft-block включён',{exact:true})).toBeVisible();
 await expect(page.getByRole('heading',{name:'Активные проверки soft-block'})).toBeVisible();await expect(page.getByRole('cell',{name:'192.0.2.4'})).toBeVisible();
 await page.getByRole('button',{name:/Правила и фильтры/}).click();await expect(page.getByLabel('Режим блокировки',{exact:true})).toHaveValue('soft_block');await expect(page.getByLabel('Время действия cookie')).toHaveValue('30m');await expect(page.getByLabel('Время действия cookie')).toHaveAttribute('readonly','');await expect(page.getByText('bgt.my',{exact:false})).toBeVisible();
});
test('admin edits independent hybrid rule actions',async({page})=>{
 let saved:any=null;
 await page.route('**/api/config/rules',async route=>{
  saved=route.request().postDataJSON();
  const current=await page.request.get('/api/config');const body=await current.json();
  body.config.block_mode='hybrid';body.daemon.block_mode='dry_run';body.restart_required=true;
  body.config.rules=body.config.rules.map((rule:any)=>({...rule,action:saved.rules[rule.id].action}));
  await route.fulfill({json:body});
 });
 await page.route('**/api/config',async route=>{
  const response=await route.fetch();const body=await response.json();
  body.config.block_mode='hybrid';body.daemon.block_mode='hybrid';
  body.config.rules=body.config.rules.map((rule:any)=>({...rule,action:'dry_run'}));
  await route.fulfill({response,json:body});
 });
 await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();await page.getByRole('button',{name:/^homepage/}).click();
 const action=page.getByLabel('Действие homepage',{exact:true});await expect(action).toHaveValue('dry_run');
 await action.selectOption('nftables');page.once('dialog',dialog=>dialog.accept());
 await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Сохранено');
 expect(saved.rules.homepage.action).toBe('nftables');expect(saved.confirm_real_blocks).toBe(true);
});
test('admin can configure cardinality presets in the rule wizard',async({page})=>{
 await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();
 await page.getByRole('button',{name:'Добавить правило',exact:true}).click();
 const wizard=page.locator('.rule-wizard');await expect(wizard).toBeVisible();
 const preset=wizard.getByRole('combobox').first();await preset.selectOption('port-scan');
 await expect(wizard.getByRole('combobox').nth(2)).toHaveValue('cardinality');
 await expect(wizard.getByRole('combobox').nth(3)).toHaveValue('destination_port');
 await expect(wizard.getByLabel('Окно',{exact:true})).toHaveValue('30s');
 await expect(wizard.getByLabel('Порог',{exact:true})).toHaveValue('8');
 await preset.selectOption('web-unique-paths');
 await expect(wizard.getByRole('combobox').nth(3)).toHaveValue('path');
 await expect(wizard.getByLabel('Порог',{exact:true})).toHaveValue('20');
});
test('SQLi preset fills a high-confidence query signature and explains its scope',async({page})=>{
 await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();
 await page.getByRole('button',{name:'Добавить правило',exact:true}).click();
 const wizard=page.locator('.rule-wizard');await wizard.getByRole('combobox').first().selectOption('web-sqli');
 await expect(wizard.getByLabel('ID',{exact:true})).toHaveValue('web-sqli');
 await expect(wizard.locator('label').filter({hasText:'Regex path'}).locator('input')).toHaveValue('.*');
 await expect(wizard.locator('label').filter({hasText:'Regex query'}).locator('input')).toHaveValue(/union.*extractvalue.*benchmark/i);
 await expect(wizard.getByText('проверяет все URL',{exact:false})).toBeVisible();
 await expect(wizard.getByText('исходная query-строка из access.log',{exact:false})).toBeVisible();
 await expect(wizard.getByText('Обычный ORDER BY',{exact:false})).toHaveCount(0);
});
test('admin adds an explicit readable log source with a safe dry-run preset',async({page})=>{
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
 const original=readFileSync(fixture.config,'utf8');
 const logPath=fixture.config.replace(/\/[^/]+$/,'/ssh-source.log');
 writeFileSync(logPath,'');
 try{
  await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();
  await page.getByRole('button',{name:'Добавить источник',exact:true}).click();
  await page.getByLabel('Имя нового источника').fill('ssh_auth');
  await page.getByLabel('Путь нового источника').fill(logPath);
  await page.getByLabel('Формат нового источника').selectOption('syslog_sshd');
  await page.getByRole('button',{name:'Добавить с базовым правилом',exact:true}).click();
  await expect(page.getByRole('row').filter({hasText:'ssh_auth'})).toContainText('Ожидает сохранения');
  await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('Сохранено');
  await page.getByRole('button',{name:/^ssh_auth-ssh-password/}).click();
  await expect(page.getByLabel('Источник ssh_auth-ssh-password',{exact:true})).toHaveValue('ssh_auth');
  const config=JSON.parse(readFileSync(fixture.config,'utf8'));
  expect(config.log_sources.ssh_auth).toEqual({path:logPath,format:'syslog_sshd'});
  expect(config.engine.rules.find((rule:any)=>rule.id==='ssh_auth-ssh-password')).toMatchObject({enabled:true,action:'dry_run',log_source:'ssh_auth',path_regex:'^/ssh/failed$'});
 }finally{
  writeFileSync(fixture.config,original);
  process.kill(fixture.harnessPID,'SIGUSR1');
 }
});
test('admin: real daemon stats, graphs, whitelist, restart and users',async({page})=>{
 test.setTimeout(60000);
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
 await login(page);await expect(page.getByText('Режим наблюдения',{exact:true})).toBeVisible();
 const localInput=(time:number)=>{const date=new Date(time);return new Date(time-date.getTimezoneOffset()*60000).toISOString().slice(0,16)};
 const rangeEnd=Date.now()+60*1000;await page.getByLabel('Начало периода',{exact:true}).fill(localInput(rangeEnd-2*60*60*1000));await page.getByLabel('Конец периода',{exact:true}).fill(localInput(rangeEnd));await expect(page.locator('.metric strong').first()).toHaveText(String(fixture.expectedRequests));
 await page.getByRole('button',{name:'15 мин',exact:true}).click();await expect(page.getByRole('button',{name:'15 мин',exact:true})).toHaveClass(/active/);
 const chart=page.locator('.chart svg').first();const bounds=(await chart.boundingBox())!;await page.mouse.move(bounds.x+bounds.width*.3,bounds.y+bounds.height*.5);await page.mouse.down();await page.mouse.move(bounds.x+bounds.width*.7,bounds.y+bounds.height*.5);await page.mouse.up();await expect(page.getByLabel('Сейчас',{exact:true})).not.toBeChecked();
 await page.getByRole('button',{name:'1 час',exact:true}).click();await page.screenshot({path:`${artifact}/dashboard.png`,fullPage:true});
 await page.getByRole('button',{name:'Срабатывания и блокировки'}).click();await expect(page.getByRole('cell',{name:'192.0.2.10',exact:true}).first()).toBeVisible();await expect(page.getByRole('cell',{name:'login',exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:/Пользователи/}).click();await expect(page.getByRole('cell',{name:'viewer',exact:true})).toBeVisible();
 await page.getByRole('button',{name:/Правила и фильтры/}).click();await page.getByRole('button',{name:/^homepage/}).click();
 await page.getByLabel('Глобальный IP 1',{exact:true}).fill('203.0.113.10');await page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true}).click();await page.getByLabel('Глобальный IP 2',{exact:true}).fill('203.0.113.20');
 await page.getByRole('button',{name:'Удалить глобальный IP 2',exact:true}).click();await page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true}).click();await page.getByLabel('Глобальный IP 2',{exact:true}).fill('2001:db8::1');
 await page.getByRole('button',{name:'Добавить IP в whitelist homepage',exact:true}).click();await page.getByRole('button',{name:'Добавить IP в whitelist homepage',exact:true}).click();
 await page.getByLabel('IP homepage 1',{exact:true}).fill('192.0.2.10');await page.getByLabel('IP homepage 2',{exact:true}).fill('192.0.2.20');await page.getByRole('button',{name:'Удалить IP homepage 2',exact:true}).click();
 await page.getByLabel('Регулярное выражение homepage',{exact:true}).fill('^/landing$');await page.getByLabel('Режим блокировки',{exact:true}).selectOption('nftables');page.once('dialog',async dialog=>{expect(dialog.message()).toContain('Включить реальные блокировки?');await dialog.accept()});await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();await expect(page.getByRole('status')).toContainText('Сохранено');
 let config=JSON.parse(readFileSync(fixture.config,'utf8'));expect(config.block_mode).toBe('nftables');expect(config.engine.ignore_ips).toEqual(['203.0.113.10','2001:db8::1']);expect(config.engine.rules[0].ignore_ips).toEqual(['192.0.2.10']);expect(config.engine.rules[0].path_regex).toEqual('^/landing$');expect(config.engine.rules[1].ignore_ips).toEqual(['198.51.100.7/32']);
 await expect(page.getByText('Настройки сохранены, но демон пока работает со старой конфигурацией.',{exact:false})).toBeVisible();await page.screenshot({path:`${artifact}/whitelist.png`,fullPage:true});
 await page.getByLabel('Режим блокировки',{exact:true}).selectOption('dry_run');await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();await expect(page.getByRole('status')).toContainText('Сохранено');config=JSON.parse(readFileSync(fixture.config,'utf8'));expect(config.block_mode).toBe('dry_run');
 process.kill(fixture.harnessPID,'SIGUSR1');await expect(page.getByText('Настройки сохранены, но демон пока работает со старой конфигурацией.',{exact:false})).toHaveCount(0,{timeout:20000});
 await page.getByRole('button',{name:'Выйти',exact:true}).click();await expect(page.getByRole('heading',{name:'Вход в AntiDDoS'})).toBeVisible();expect(errors).toEqual([]);
});
test('viewer: no mutation controls or user list; CLI password change revokes session',async({page})=>{
 test.setTimeout(60000);
 await login(page,'viewer');await expect(page.getByRole('button',{name:/Пользователи/})).toHaveCount(0);
 await page.getByRole('button',{name:/Правила и фильтры/}).click();await page.getByRole('button',{name:/^homepage/}).click();await expect(page.getByLabel('Глобальный IP 1',{exact:true})).toHaveAttribute('readonly','');await expect(page.getByLabel('Регулярное выражение homepage',{exact:true})).toHaveAttribute('readonly','');await expect(page.getByRole('button',{name:'Добавить IP в глобальный whitelist',exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Сохранить изменения',exact:true})).toHaveCount(0);
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));execFileSync(fixture.bin,['user','password','--users-db',fixture.users,'--password-stdin','viewer'],{input:'replacement-test-password\n'});
 await expect(page.getByRole('heading',{name:'Вход в AntiDDoS'})).toBeVisible({timeout:20000});
});
test('mobile login and invalid credentials',async({page})=>{await page.setViewportSize({width:390,height:844});await page.goto('/');await page.getByLabel('Пользователь',{exact:true}).fill('admin');await page.getByLabel('Пароль',{exact:true}).fill('incorrect-password');await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Неверное имя пользователя или пароль');await page.screenshot({path:`${artifact}/login-mobile.png`,fullPage:true})});


test('validation errors never show saved or modify the config; conflicting edits are rejected',async({page})=>{
 test.setTimeout(60000);
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
 const original=readFileSync(fixture.config,'utf8');
 await login(page);
 await page.getByRole('button',{name:/Правила и фильтры/}).click();await page.getByRole('button',{name:/^homepage/}).click();
 for(const [label,value] of [['Регулярное выражение homepage','['],['Глобальный IP 1','not-an-ip']]){
  await page.getByLabel(label,{exact:true}).fill(value);
  const response=page.waitForResponse(r=>r.url().endsWith('/api/config/rules')&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
  expect((await response).status()).toBe(400);
  await expect(page.getByRole('status')).toHaveCount(0);
  await expect(page.getByRole('alert').last()).toBeVisible();
  expect(readFileSync(fixture.config,'utf8')).toBe(original);
  await page.getByRole('button',{name:'Отменить',exact:true}).click();
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
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
 const original=readFileSync(fixture.config,'utf8');
 await login(page);await page.getByRole('button',{name:/Правила и фильтры/}).click();
 await page.getByLabel('Режим блокировки',{exact:true}).selectOption('nftables');
 let writes=0;page.on('request',r=>{if(r.method()==='PUT')writes++});
 page.once('dialog',dialog=>dialog.dismiss());
 await page.getByRole('button',{name:'Сохранить изменения',exact:true}).click();
 expect(writes).toBe(0);expect(readFileSync(fixture.config,'utf8')).toBe(original);
 await expect(page.getByRole('status')).toHaveCount(0);
});

test('live multi-source traffic, rule matching, graphs and pagination',async({page})=>{
 test.setTimeout(90000);
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
 const config=JSON.parse(readFileSync(fixture.config,'utf8'));
 expect(config.block_mode).toBe('dry_run');
 await login(page);
 await page.getByText('Графики по отдельным источникам (2)',{exact:true}).click();
 const groups=page.locator('.source-graphs');await expect(groups).toHaveCount(2);
 for(const group of await groups.all()){
  await group.locator('summary').click();await expect(group.locator('svg')).toHaveCount(4);
 }
 await page.screenshot({path:`${artifact}/sources.png`,fullPage:true});
 await page.getByRole('button',{name:/Срабатывания и блокировки/}).click();
 await page.getByRole('button',{name:'1 час',exact:true}).click();
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
 const lines=(ip:string,path:string)=>Array.from({length:6},(_,i)=>{const d=new Date(now.getTime()+10000+i*500);const stamp=`${String(d.getUTCDate()).padStart(2,'0')}/${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()]}/${d.getFullYear()}:${d.toISOString().slice(11,19)} +0000`;return `${ip} - - [${stamp}] "GET ${path} HTTP/1.1" 200 256 "-" "web-live-check"\n`}).join('');
 const homepagePath=config.engine.rules.find((rule:any)=>rule.id==='homepage').path_regex==='^/$'?'/?probe=full-request':'/landing?probe=full-request';
 appendFileSync(config.log_sources.main,lines('192.0.2.50',homepagePath)+lines('192.0.2.10','/landing')+lines('192.0.2.60','/'));
 appendFileSync(config.log_sources.admin,lines('198.51.100.50','/login')+lines('198.51.100.7','/login'));
 await expect.poll(async()=>sum((await (await page.request.get(endpoint)).json()).points),{timeout:45000}).toBe(sum(before.points)+30);
 const after=await (await page.request.get(endpoint)).json();
 for(const [source,added] of [['main',18],['admin',12]] as const){
  const previous=before.source_points.find((s:any)=>s.source_id===source)?.points??[];
  const next=after.source_points.find((s:any)=>s.source_id===source).points;
  expect(sum(next)).toBe(sum(previous)+added);
  const sumMatched=(points:any[])=>points.reduce((total,p)=>total+p.matched,0);
  const expectedMatches=12;
  expect(sumMatched(next)).toBe(sumMatched(previous)+expectedMatches);
 }
 expect(after.block_count).toBe(0);
 // The fixture writes event timestamps 10–12.5 seconds ahead of wall clock so
 // they are never rejected as late after the seeded stream. Wait until the
 // live dashboard range includes them before asserting their rendered detail.
 await page.waitForTimeout(13000);
 await page.getByLabel('Сейчас',{exact:true}).check();
 await page.getByRole('button',{name:'Обновить',exact:true}).click();
 await expect(page.getByRole('columnheader',{name:'Причина срабатывания',exact:true})).toBeVisible();
 await expect(page.getByText(`GET ${homepagePath} HTTP/1.1`,{exact:true}).first()).toBeVisible({timeout:15000});
 await expect(page.locator('.detection-reason').first()).toContainText(/Частота HTTP-запросов превысила порог/);
 await page.getByRole('button',{name:/Обзор трафика/}).click();
 await page.getByRole('button',{name:'Обновить',exact:true}).click();
 await page.screenshot({path:`${artifact}/live-dashboard.png`,fullPage:true});
});

test('active block source and expiry are visible without touching the firewall',async({page})=>{
 test.setTimeout(40000);
 const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
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
