import {readFileSync,writeFileSync} from 'node:fs';
import {test,expect} from '@playwright/test';
async function login(page:any,user='admin') {
 await page.goto('/');
 await page.getByLabel('Пользователь',{exact:true}).fill(user);
 await page.getByLabel('Пароль',{exact:true}).fill('test-only-long-password');
 await page.getByRole('button',{name:'Войти',exact:true}).click();
 await expect(page.locator('body')).toBeVisible();
 await expect(page.locator('#dashboard-title')).toBeVisible();
 await expect(page.locator('[data-session-login]').first()).toHaveText(user);
}
test('original LogBan layout, real data, navigation, theme and mobile',async({page})=>{
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page);
 await expect(page.getByText('Системные показатели сервера')).toHaveCount(0);
 await expect(page.locator('#hit-chart canvas').first()).toBeVisible();
 for(const section of ['incidents','logs','blocks','sources','rules','actions','allowlist']) {
   await page.goto('/#'+section);
   await expect(page.locator('#'+section)).toBeVisible();
 }
 await page.goto('/#logs');
 await page.locator('#log-source').selectOption('main');
 await expect(page.locator('#log-list')).toContainText('192.0.2.10');
 await page.locator('.log-disclosure').first().click();
 await expect(page.locator('.log-raw').first()).toBeVisible();
 await page.goto('/#dashboard');
 await page.screenshot({path:'../runtime/web-e2e/logban-dashboard.png',fullPage:true});
 await page.emulateMedia({colorScheme:'dark'});
 await expect(page.locator('html')).toHaveAttribute('data-bs-theme','dark');
 await page.screenshot({path:'../runtime/web-e2e/logban-dark.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:'../runtime/web-e2e/logban-mobile.png',fullPage:true});
 expect(errors).toEqual([]);
});
test('rule edits persist on backend and after reload; server validation stays visible',async({page})=>{
 await login(page);await page.goto('/#rules');
 await page.getByRole('button',{name:'Редактировать homepage',exact:true}).click();
 await page.locator('#rule-path').fill('^/persisted$');
 await page.locator('#rule-save').click();
 await expect(page.locator('#rule-modal')).not.toBeVisible();
 let config=await (await page.request.get('/api/config')).json();
 expect(config.config.rules.find((r:any)=>r.id==='homepage').path_regex).toBe('^/persisted$');
 await page.reload();
 await page.getByRole('button',{name:'Редактировать homepage',exact:true}).click();
 await expect(page.locator('#rule-path')).toHaveValue('^/persisted$');
 await page.locator('#rule-path').fill('[');
 await page.locator('#rule-save').click();
 await expect(page.locator('#rule-error')).toBeVisible();
 config=await (await page.request.get('/api/config')).json();
 expect(config.config.rules.find((r:any)=>r.id==='homepage').path_regex).toBe('^/persisted$');
});
test('allowlist persists and a stale revision is rejected',async({page})=>{
 await login(page);await page.goto('/#allowlist');
 await expect(page.locator('#allow-addresses')).toBeVisible();
 await page.locator('#allow-addresses').fill('192.0.2.100\n203.0.113.7');
 await page.locator('#allow-save').click();
 await expect(page.locator('#allow-status')).toContainText('сохранены на сервере');
 await page.reload();
 await expect(page.locator('#allow-addresses')).toHaveValue('192.0.2.100/32\n203.0.113.7/32');
 const session=await (await page.request.get('/api/session')).json();
 const config=await (await page.request.get('/api/config')).json();
 const result=await page.request.put('/api/config/rules',{headers:{'X-CSRF-Token':session.csrf,Origin:new URL(page.url()).origin},data:{revision:config.config.revision,ignore_ips:['192.0.2.100']}});
 expect(result.ok()).toBeTruthy();
 await page.locator('#allow-addresses').fill('203.0.113.9');
 await page.locator('#allow-save').click();
 await expect(page.locator('#allow-status')).toContainText('другим пользователем');
});
test('viewer cannot mutate and logout invalidates session',async({page})=>{
 await login(page,'viewer');await page.goto('/#rules');
 await expect(page.locator('#rule-add')).toBeHidden();
 await expect(page.locator('#rule-list input').first()).toBeDisabled();
 await page.goto('/#allowlist');
 await expect(page.locator('#allow-addresses')).toHaveAttribute('readonly','');
 await page.locator('#logout').click();
 await expect(page.locator('#login-form')).toBeVisible();
 expect((await page.request.get('/api/session')).status()).toBe(401);
});
test('create, toggle and delete rule use the daemon configuration',async({page})=>{
 await login(page);await page.goto('/#rules');
 await page.locator('#rule-add').click();
 await page.locator('#rule-id').fill('ui-created');
 await page.locator('#rule-source').selectOption('main');
 await page.locator('#rule-save').click();
 await expect(page.locator('#rule-modal')).not.toBeVisible();
 const toggle=page.getByRole('switch',{name:'Включено — ui-created',exact:true});
 await toggle.uncheck();
 await expect.poll(async()=>{
   const cfg=await (await page.request.get('/api/config')).json();
   return cfg.config.rules.find((r:any)=>r.id==='ui-created')?.enabled;
 }).toBe(false);
 page.once('dialog',dialog=>dialog.accept());
 await page.getByRole('button',{name:'Удалить ui-created',exact:true}).click();
 await expect(toggle).toHaveCount(0);
 const cfg=await (await page.request.get('/api/config')).json();
 expect(cfg.config.rules.some((r:any)=>r.id==='ui-created')).toBe(false);
});

test('new source is persisted with a disabled monitor rule',async({page})=>{
 const artifact=process.env.ANTIDDOS_E2E_ARTIFACT || '../runtime/web-e2e';
 const fixture=JSON.parse(readFileSync(artifact+'/fixture.json','utf8'));
 const path=fixture.dir+'/added.log';writeFileSync(path,'');
 await login(page);await page.goto('/#sources');
 await page.locator('#source-add').click();
 await page.locator('#source-name').fill('ui-source');
 await page.locator('#source-path').fill(path);
 await page.locator('#source-save').click();
 await expect(page.locator('#source-modal')).not.toBeVisible();
 const config=await (await page.request.get('/api/config')).json();
 expect(config.config.sources.find((s:any)=>s.id==='ui-source')?.path).toBe(path);
 expect(config.config.rules.find((r:any)=>r.id==='ui-source-monitor')?.enabled).toBe(false);
});
