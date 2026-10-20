import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const password='test-only-long-password';
async function login(page:any,user='admin'){await page.goto('/');await page.getByLabel('Пользователь',{exact:true}).fill(user);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('heading',{name:'Обзор трафика',exact:true})).toBeVisible()}
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
