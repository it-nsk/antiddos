import {StrictMode,useCallback,useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {api,APIError} from './api';
import type {Session,ConfigState,Config,Dashboard,User,Detection} from './api';
import {Chart} from './Chart';
import './style.css';
const fmt=new Intl.NumberFormat('ru',{maximumFractionDigits:2});
const dt=(n:number)=>new Date(n*1000).toLocaleString('ru');
const local=(n:number)=>{const d=new Date(n*1000);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16)};
const errorTranslations:Record<string,string>={
 'Invalid username or password':'Неверное имя пользователя или пароль',
 'Too many login attempts; wait one minute':'Слишком много попыток входа. Повторите через минуту',
 'Login busy; try again shortly':'Сервис входа занят. Повторите чуть позже',
 'Session expired':'Сессия завершена. Войдите снова',
};
const errText=(e:unknown)=>e instanceof Error?(errorTranslations[e.message]||e.message):'Не удалось выполнить запрос';
function App(){
 const [session,setSession]=useState<Session|null>(null),[checking,setChecking]=useState(true),[error,setError]=useState('');
 useEffect(()=>{api<Session>('session').then(setSession).catch(e=>{if(!(e instanceof APIError&&e.status===401))setError(errText(e))}).finally(()=>setChecking(false))},[]);
 if(checking)return <div className="login"><p>Подключение к AntiDDoS…</p></div>;
 return session?<Workspace session={session} onLogout={()=>setSession(null)}/>:<Login initialError={error} onLogin={setSession}/>;
}
function Login({onLogin,initialError}:{onLogin:(s:Session)=>void;initialError:string}){
 const [name,setName]=useState(''),[password,setPassword]=useState(''),[error,setError]=useState(initialError),[busy,setBusy]=useState(false);
 return <main className="login"><div className="login-brand">A<span>AntiDDoS</span></div><form className="login-card" onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{onLogin(await api<Session>('login',{method:'POST',body:JSON.stringify({username:name,password})}))}catch(e){setError(errText(e))}finally{setBusy(false)}}}>
 <p className="eyebrow">ПАНЕЛЬ УПРАВЛЕНИЯ</p><h1>Вход в AntiDDoS</h1><p className="muted">Статистика, срабатывания и разрешённые адреса.</p>
 <label>Пользователь<input autoComplete="username" required value={name} onChange={e=>setName(e.target.value)}/></label>
 <label>Пароль<input type="password" autoComplete="current-password" required value={password} onChange={e=>setPassword(e.target.value)}/></label>
 {error&&<div className="error" role="alert">{error}</div>}<button className="primary" disabled={busy}>{busy?'Проверяем…':'Войти'}</button>
 <p className="muted small">Учётную запись создаёт администратор через консоль.</p></form></main>
}
type Page='dashboard'|'detections'|'whitelist'|'users';
function Workspace({session,onLogout}:{session:Session;onLogout:()=>void}){
 const [page,setPage]=useState<Page>('dashboard'),[data,setData]=useState<Dashboard|null>(null),[config,setConfig]=useState<ConfigState|null>(null),[users,setUsers]=useState<User[]>([]);
 const [range,setRange]=useState({from:Math.floor(Date.now()/1000)-3600,to:Math.floor(Date.now()/1000)}),[live,setLive]=useState(true),[error,setError]=useState(''),[refresh,setRefresh]=useState(0),[before,setBefore]=useState(0);
 const admin=session.user.role==='admin';
 const report=useCallback((e:unknown)=>{if(e instanceof APIError&&e.status===401)onLogout();else setError(errText(e))},[onLogout]);
 useEffect(()=>{let active=true;let busy=false;
 const load=async()=>{if(busy)return;busy=true;try{
 const end=live?Math.floor(Date.now()/1000):range.to,start=live?end-(range.to-range.from):range.from;
 const [d,c]=await Promise.all([api<Dashboard>(`dashboard?from=${start}&to=${end}&before=${before}`),api<ConfigState>('config')]);if(active){setData(d);setConfig(c);setError('')}
 }catch(e){if(active)report(e)}finally{busy=false}};void load();const id=window.setInterval(load,10000);return()=>{active=false;clearInterval(id)};
 },[range,live,before,refresh,report]);
 useEffect(()=>{if(page==='users'&&admin)api<User[]>('users').then(setUsers).catch(report)},[page,admin,report]);
 const zoom=(from:number,to:number)=>{setRange({from,to});setLive(false);setBefore(0)};
 const preset=(seconds:number)=>{const to=Math.floor(Date.now()/1000);setRange({from:to-seconds,to});setLive(true);setBefore(0)};
 const titles={dashboard:'Обзор трафика',detections:'Срабатывания и блокировки',whitelist:'Правила и фильтры',users:'Пользователи'};
 const totals=data?.points.reduce((a,p)=>({requests:a.requests+p.requests,matched:a.matched+p.matched,bytes:a.bytes+p.bytes,known:a.known+p.known_rows}),{requests:0,matched:0,bytes:0,known:0});
 const sourceCharts=data&&config?[
  ...config.config.sources.map(source=>({id:source.id,path:source.path,points:data.source_points.find(item=>item.source_id===source.id)?.points??data.points.map(point=>({...point,requests:0,matched:0,bytes:0,known_rows:0,detections:0}))})),
  ...data.source_points.filter(item=>!config.config.sources.some(source=>source.id===item.source_id)).map(item=>({id:item.source_id||'unknown',path:item.source_id?'Источник больше не настроен':'Старые объединённые данные: источник неизвестен',points:item.points})),
 ]:[];
 return <div className="app"><aside><a className="brand" href="/">A<span>AntiDDoS<small>МОНИТОРИНГ И ЗАЩИТА</small></span></a><nav>
 {(['dashboard','detections','whitelist',...(admin?['users']:[])] as Page[]).map((p,i)=><button className={page===p?'selected':''} key={p} onClick={()=>setPage(p)}><span className="nav-mark">{['◫','≋','✓','♙'][i]}</span>{titles[p]}</button>)}
 </nav><div className="sidebar-bottom"><strong>{session.user.username}</strong><span>{admin?'Администратор':'Только просмотр'}</span><button onClick={async()=>{try{await api('logout',{method:'POST',headers:{'X-CSRF-Token':session.csrf},body:'{}'});onLogout()}catch(e){report(e)}}}>Выйти</button></div></aside>
 <main className="workspace"><header><div><p className="eyebrow">ANTI DDOS / {page==='whitelist'?'НАСТРОЙКИ':'НАБЛЮДЕНИЕ'}</p><h1>{titles[page]}</h1></div><div className={'status '+(config?.daemon_available?'online':'')}><i/>{config?.daemon_available?(config.daemon.block_mode==='nftables'?'Блокировка включена':'Режим наблюдения'):'Статус демона недоступен'}</div></header>
 {error&&<div className="error" role="alert">{error} <button onClick={()=>setRefresh(v=>v+1)}>Повторить</button></div>}
 {config?.restart_required===true&&<div className="notice">Настройки сохранены, но демон пока работает со старой конфигурацией. Применить: <code>sudo systemctl restart antiddos</code></div>}
 {config&&config.restart_required===null&&<div className="notice subtle">Статистика доступна из базы. Не удалось проверить применённый whitelist: нет связи с локальным сокетом демона.</div>}
 {(page==='dashboard'||page==='detections')&&<>
 <section className="toolbar"><div className="presets">{[[900,'15 мин'],[3600,'1 час'],[21600,'6 часов'],[86400,'24 часа'],[604800,'7 дней']].map(([n,label])=><button key={n} className={live&&range.to-range.from===n?'active':''} onClick={()=>preset(Number(n))}>{label}</button>)}</div>
 <div className="period"><label>С<input aria-label="Начало периода" type="datetime-local" value={local(range.from)} onChange={e=>{if(e.target.value)zoom(Math.floor(new Date(e.target.value).getTime()/1000),range.to)}}/></label><label>По<input aria-label="Конец периода" type="datetime-local" value={local(range.to)} onChange={e=>{if(e.target.value)zoom(range.from,Math.floor(new Date(e.target.value).getTime()/1000))}}/></label></div>
 <button onClick={()=>{const end=live?Math.floor(Date.now()/1000):range.to;const span=Math.min((range.to-range.from)*2,31*86400-30);zoom(end-span,end)}}>− Масштаб</button><button onClick={()=>{const end=live?Math.floor(Date.now()/1000):range.to;const span=Math.max((range.to-range.from)/2,30);zoom(Math.floor(end-span),end)}}>+ Масштаб</button>
 <label className="toggle"><input type="checkbox" checked={live} onChange={e=>{setLive(e.target.checked);setBefore(0)}}/>Сейчас</label><button onClick={()=>setRefresh(v=>v+1)}>Обновить</button></section>
 <div className="subline"><span>{data?`${dt(data.from)} — ${dt(data.to)}`:'Загрузка…'}</span><span>Обновление каждые 10 с · {data?dt(data.updated_at):'—'}</span></div>
 </>}
 {page==='dashboard'&&data&&totals&&<>
 <div className="cards">{[['Всего запросов',fmt.format(totals.requests),'Все источники, включая whitelist'],['Подходят правилам',fmt.format(totals.matched),'До исключения по whitelist'],['Передано',fmt.format(totals.bytes/1048576)+' MiB','Байты ответа из access log'],['Срабатывания',fmt.format(data.detection_count),'Количество detections за период']].map(([label,value,note])=><section className="panel metric" key={label}><span>{label}</span><strong>{value}</strong><small>{note}</small></section>)}</div>
 <div className="charts"><Chart title="Запросы" unit="запросов/с" points={data.points} onZoom={zoom} series={[{label:'Все',color:'#3866df',value:p=>p.requests/p.interval},{label:'Подходят правилам',color:'#16a48b',value:p=>p.matched/p.interval}]}/><Chart title="Исходящий трафик" unit="байт/с" points={data.points} onZoom={zoom} series={[{label:'Байты ответа',color:'#3866df',value:p=>p.bytes/p.interval}]}/><Chart title="Средний ответ" unit="байт" points={data.points} onZoom={zoom} series={[{label:'Из ответов с известным размером',color:'#8b5ac7',value:p=>p.known_rows?p.bytes/p.known_rows:0}]}/><Chart title="Срабатывания правил" unit="за интервал" points={data.points} onZoom={zoom} series={[{label:'Detections',color:'#df8445',value:p=>p.detections}]}/></div>
 {sourceCharts.length>1&&<section className="panel source-breakdown"><details><summary>Графики по отдельным источникам ({sourceCharts.length})</summary><p className="muted small">Каждая строка — отдельный лог. Разбивка собирается после обновления; более ранние интервалы доступны только в общей статистике.</p>{sourceCharts.map(source=><details className="source-graphs" key={source.id}><summary><strong>{source.id}</strong> · <code>{source.path}</code></summary><div className="charts"><Chart title="Запросы" unit="запросов/с" points={source.points} onZoom={zoom} series={[{label:'Все',color:'#3866df',value:p=>p.requests/p.interval},{label:'Подходят правилам',color:'#16a48b',value:p=>p.matched/p.interval}]}/><Chart title="Исходящий трафик" unit="байт/с" points={source.points} onZoom={zoom} series={[{label:'Байты ответа',color:'#3866df',value:p=>p.bytes/p.interval}]}/><Chart title="Средний ответ" unit="байт" points={source.points} onZoom={zoom} series={[{label:'Из ответов с известным размером',color:'#8b5ac7',value:p=>p.known_rows?p.bytes/p.known_rows:0}]}/><Chart title="Срабатывания правил" unit="за интервал" points={source.points} onZoom={zoom} series={[{label:'Срабатывания',color:'#df8445',value:p=>p.detections}]}/></div></details>)}</details></section>}
 <p className="muted small">Верхние графики суммируют все источники. В раскрывающемся разделе — отдельные графики каждого лога. Исходный интервал — 15 с; на больших периодах точки объединяются. Ноль означает отсутствие записанных запросов и сам по себе не подтверждает работу демона.</p>
 <Blocks data={data} rules={config?.config.rules??[]}/><section className="panel"><details><summary>Все показатели трафика по интервалам</summary><div className="table-wrap"><table><thead><tr>{['Начало','Интервал, с','Запросы','Подходят','Запросов/с','Байты','Байт/с','Известных размеров','Средний ответ'].map(v=><th key={v}>{v}</th>)}</tr></thead><tbody>{data.points.map(p=><tr key={p.time}><td>{dt(p.time)}</td><td>{p.interval}</td><td>{p.requests}</td><td>{p.matched}</td><td>{fmt.format(p.requests/p.interval)}</td><td>{p.bytes}</td><td>{fmt.format(p.bytes/p.interval)}</td><td>{p.known_rows}</td><td>{p.known_rows?fmt.format(p.bytes/p.known_rows):'—'}</td></tr>)}</tbody></table></div></details></section>
 </>}
 {page==='detections'&&data&&<><Blocks data={data} rules={config?.config.rules??[]}/><section className="panel"><div className="panel-head"><h2>Срабатывания <span className="badge">{data.detection_count}</span></h2><span>Detection не означает применённую блокировку</span></div><DetectionTable rows={data.detections}/><div className="pagination"><button disabled={!before} onClick={()=>setBefore(0)}>К последним</button><button disabled={!data.next_before} onClick={()=>{setLive(false);setRange({from:data.from,to:data.to});setBefore(data.next_before)}}>Ранее →</button><span>До 100 записей на странице</span></div></section></>}
 {page==='whitelist'&&config&&<Whitelist state={config} session={session} onSaved={next=>{setConfig(next);setRefresh(v=>v+1)}} report={report}/>}
 {page==='users'&&admin&&<section className="panel"><div className="panel-head"><h2>Доступ к интерфейсу</h2><span>{users.length} пользователей</span></div><div className="table-wrap"><table><thead><tr><th>Пользователь</th><th>Роль</th><th>Создан</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><strong>{u.username}</strong></td><td>{u.role==='admin'?'Администратор':'Просмотр'}</td><td>{dt(u.created_at)}</td></tr>)}</tbody></table></div><p className="panel-note">Создание, смена пароля и удаление — через <code>antiddos user</code> на сервере. Администратор меняет регулярные выражения и whitelist; viewer доступен только для просмотра.</p></section>}
 </main></div>
}
function Blocks({data,rules}:{data:Dashboard;rules:Config['rules']}){const sourceByRule=new Map(rules.map(rule=>[rule.id,rule.log_source]));return <section className="panel"><div className="panel-head"><h2>Активные блокировки <span className="badge">{data.block_count}</span></h2><span>На текущий момент · до 1000 адресов</span></div>{data.blocks.length?<div className="table-wrap"><table><thead><tr><th>IP</th><th>Источник лога</th><th>Правило</th><th>Заблокирован</th><th>Истекает</th><th>Осталось</th></tr></thead><tbody>{data.blocks.map(b=><tr key={b.ip}><td><code>{b.ip}</code></td><td>{sourceByRule.get(b.rule)||'источник неизвестен'}</td><td>{b.rule}</td><td>{dt(b.started_at)}</td><td>{dt(b.expires_at)}</td><td>{Math.max(0,b.expires_at-data.updated_at)} с</td></tr>)}</tbody></table></div>:<div className="empty"><span>✓</span>Активных блокировок нет</div>}</section>}
function DetectionTable({rows}:{rows:Detection[]}){return rows.length?<div className="table-wrap"><table><thead><tr>{['Время события','Источник лога','Правило','Группировка','Группа','IP запроса','Число / порог','Окно','User-Agent','Записано'].map(s=><th key={s}>{s}</th>)}</tr></thead><tbody>{rows.map(d=><tr key={d.id}><td>{new Date(d.event_time).toLocaleString('ru')}</td><td>{d.source_id||'источник не сохранён'}</td><td>{d.rule}</td><td>{d.group_by}</td><td className="long" title={d.group}>{d.group}</td><td><code>{d.ip}</code></td><td>{d.count} / {d.threshold}</td><td>{d.window_ms/1000} с</td><td className="long" title={d.user_agent}>{d.user_agent}</td><td>{new Date(d.recorded_at).toLocaleString('ru')}</td></tr>)}</tbody></table></div>:<div className="empty">За выбранный период срабатываний нет</div>}
function Whitelist({state,session,onSaved,report}:{state:ConfigState;session:Session;onSaved:(state:ConfigState)=>void;report:(e:unknown)=>void}){
 const [doc,setDoc]=useState<Config>(state.config);
 const [global,setGlobal]=useState<string[]>([...state.config.ignore_ips]);
 const [rules,setRules]=useState<Record<string,string[]>>(Object.fromEntries(state.config.rules.map(r=>[r.id,[...r.ignore_ips]])));
 const [regexes,setRegexes]=useState<Record<string,string>>(Object.fromEntries(state.config.rules.map(r=>[r.id,r.path_regex])));
 const [blockMode,setBlockMode]=useState<'dry_run'|'nftables'>(state.config.block_mode);
 const [dirty,setDirty]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[saved,setSaved]=useState(false);
 const readOnly=session.user.role!=='admin';
 function reset(c:Config){setDoc(c);setGlobal([...c.ignore_ips]);setRules(Object.fromEntries(c.rules.map(r=>[r.id,[...r.ignore_ips]])));setRegexes(Object.fromEntries(c.rules.map(r=>[r.id,r.path_regex])));setBlockMode(c.block_mode);setDirty(false);setMessage('');setSaved(false)}
 useEffect(()=>{if(!dirty&&state.config.revision!==doc.revision)reset(state.config)},[state.config,dirty,doc.revision]);
 const parse=(items:string[])=>items.map(v=>v.trim()).filter(Boolean);
 const setGlobalIP=(index:number,value:string)=>{setGlobal(items=>items.map((item,i)=>i===index?value:item));setDirty(true)};
 const addGlobalIP=()=>{setGlobal(items=>[...items,'']);setDirty(true)};
 const removeGlobalIP=(index:number)=>{setGlobal(items=>items.filter((_,i)=>i!==index));setDirty(true)};
 const setRuleIP=(id:string,index:number,value:string)=>{setRules(items=>({...items,[id]:(items[id]||[]).map((item,i)=>i===index?value:item)}));setDirty(true)};
 const addRuleIP=(id:string)=>{setRules(items=>({...items,[id]:[...(items[id]||[]),'']}));setDirty(true)};
 const removeRuleIP=(id:string,index:number)=>{setRules(items=>({...items,[id]:(items[id]||[]).filter((_,i)=>i!==index)}));setDirty(true)};
 async function save(){
  const modeChanged=blockMode!==doc.block_mode;
  const confirmRealBlocks=modeChanged&&blockMode==='nftables';
  if(confirmRealBlocks&&!window.confirm('Включить реальные блокировки? После сохранения и перезапуска AntiDDoS будет блокировать IP в firewall через nftables. Продолжить?'))return;
  setBusy(true);setMessage('');setSaved(false);
  try{
   const result=await api<ConfigState>('config/rules',{method:'PUT',headers:{'X-CSRF-Token':session.csrf},body:JSON.stringify({revision:doc.revision,ignore_ips:parse(global),rules:Object.fromEntries(doc.rules.map(r=>[r.id,{ignore_ips:parse(rules[r.id]||[]),path_regex:regexes[r.id]??r.path_regex}])),...(modeChanged?{block_mode:blockMode}:{}),confirm_real_blocks:confirmRealBlocks})});
   reset(result.config);onSaved(result);setSaved(true);setMessage('Сохранено. Перезапустите antiddos для применения.');
  }catch(e){report(e);setMessage(errText(e))}finally{setBusy(false)}
 }
 return <>
  <p className="muted">Настройте URL-путь и whitelist каждого правила. Путь проверяется для GET-запросов без query-параметров; используется синтаксис Go (RE2). Например, <code>^/login$</code> — точный путь, <code>^/admin(/|$)</code> — раздел admin.</p>
  {dirty&&doc.revision!==state.config.revision&&<div className="notice">Конфигурация изменилась на сервере. Перезагрузите форму перед сохранением.</div>}
  <section className="panel editor"><div><h2>Режим блокировки</h2><p>Сейчас демон работает в режиме: <strong>{state.daemon.block_mode==='nftables'?'Реальные блокировки':'Наблюдение (dry-run)'}</strong>.</p><p className="muted small">Переключение сохраняется в конфиге. Новый режим начнёт действовать после перезапуска службы.</p></div><label>Режим<select aria-label="Режим блокировки" disabled={readOnly} value={blockMode} onChange={e=>{setBlockMode(e.target.value as 'dry_run'|'nftables');setDirty(true)}}><option value="dry_run">Наблюдение — только фиксировать detections</option><option value="nftables">Реальные блокировки через nftables</option></select><p className="muted small">Для реальных блокировок служба использует системное право CAP_NET_ADMIN и заданные в конфиге порты.</p></label></section>
  <section className="panel editor"><div><h2>Глобальный whitelist</h2><p>Действует для всех правил.</p><p className="muted small">IPv4, IPv6 или CIDR.<br/>Например: 192.0.2.10 или 2001:db8::/32.</p></div><div className="ip-list" aria-label="Глобальные разрешённые адреса">
   {global.map((ip,index)=><div className="ip-row" key={index}><input aria-label={`Глобальный IP ${index+1}`} readOnly={readOnly} value={ip} placeholder="IPv4, IPv6 или CIDR" onChange={e=>setGlobalIP(index,e.target.value)}/>{!readOnly&&<button type="button" aria-label={`Удалить глобальный IP ${index+1}`} onClick={()=>removeGlobalIP(index)}>Удалить</button>}</div>)}
   {global.length===0&&<p className="ip-list-empty">Список пуст</p>}{!readOnly&&<button type="button" onClick={addGlobalIP}>Добавить IP в глобальный whitelist</button>}
  </div></section>
  {doc.rules.map(r=><section className="panel editor" key={r.id}>
   <div><h2>{r.id}</h2><p>Источник: <code>{r.log_source}</code></p><p className="muted small">{r.threshold} запросов за {r.window} · группировка {r.group_by}</p></div>
   <label>Регулярное выражение пути<input aria-label={'Регулярное выражение '+r.id} readOnly={readOnly} value={regexes[r.id]??r.path_regex} onChange={e=>{setRegexes({...regexes,[r.id]:e.target.value});setDirty(true)}}/></label>
   <div className="ip-list" aria-label={`Разрешённые адреса правила ${r.id}`}><strong>Whitelist правила</strong>
    {(rules[r.id]||[]).map((ip,index)=><div className="ip-row" key={index}><input aria-label={`IP ${r.id} ${index+1}`} readOnly={readOnly} value={ip} placeholder="IPv4, IPv6 или CIDR" onChange={e=>setRuleIP(r.id,index,e.target.value)}/>{!readOnly&&<button type="button" aria-label={`Удалить IP ${r.id} ${index+1}`} onClick={()=>removeRuleIP(r.id,index)}>Удалить</button>}</div>)}
    {(rules[r.id]||[]).length===0&&<p className="ip-list-empty">Нет адресов этого правила</p>}{!readOnly&&<button type="button" onClick={()=>addRuleIP(r.id)}>Добавить IP в whitelist {r.id}</button>}
   </div>
  </section>)}
  {!readOnly&&<div className="savebar"><button className="primary" disabled={!dirty||busy} onClick={save}>{busy?'Сохраняем…':'Сохранить изменения'}</button><button onClick={()=>reset(state.config)}>Отменить изменения</button><span>Whitelist, regex и режим применятся после перезапуска демона.</span></div>}
  {message&&(saved?<div className="notice" role="status"><strong>Сохранено.</strong> Перезапустите antiddos для применения:<br/><code>sudo systemctl restart antiddos</code></div>:<div className="error" role="alert">{message}</div>)}
  <section className="panel"><div className="panel-head"><h2>Источники логов</h2></div><div className="table-wrap"><table><thead><tr><th>Имя</th><th>Путь</th><th>Формат</th></tr></thead><tbody>{doc.sources.map(s=><tr key={s.id}><td>{s.id}</td><td><code>{s.path}</code></td><td>{s.format}</td></tr>)}</tbody></table></div></section>
 </>
}
createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);
