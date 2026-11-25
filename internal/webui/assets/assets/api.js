let configState;
let savingConfig = false;
function showBackendStatus(message) {
  const node = document.getElementById('backend-status');
  if(node) { node.textContent = message; node.hidden = !message; }
  else window.alert(message);
}
function showRestartCommand() {
  const node = document.getElementById('backend-status');
  if (!node) return;
  node.replaceChildren('Настройки сохранены. Для применения выполните на сервере: ');
  const command = document.createElement('code');
  command.textContent = 'sudo systemctl restart antiddos';
  node.append(command);
  node.hidden = false;
}
async function requestAPI(path, method='GET', data) {
  const response = await fetch('/api/'+path, {
    method, credentials:'same-origin',
    headers:{'Content-Type':'application/json', ...(typeof session !== 'undefined' && session ? {'X-CSRF-Token':session.csrf} : {})},
    ...(data === undefined ? {} : {body:JSON.stringify(data)})
  });
  const value = await response.json();
  if(!response.ok) {
    const error = new Error(value.error || 'Ошибка запроса');
    error.status = response.status;
    if(response.status === 401 && path !== 'login' && path !== 'session') location.replace('/login.html');
    throw error;
  }
  return value;
}
async function readApi(name) {
  if(name === 'config') return configState || (configState = await requestAPI('config'));
  return requestAPI(name);
}
async function saveConfig(change) {
  if(savingConfig) throw new Error('Дождитесь завершения предыдущего сохранения.');
  savingConfig = true;
  try {
    configState = await requestAPI('config/rules','PUT',{revision:configState.config.revision,...change});
    if (configState.restart_required) showRestartCommand(); else showBackendStatus('');
    return configState;
  } catch(error) {
    if(error.status === 409) error.message = 'Настройки изменены другим пользователем. Обновите страницу перед повторным редактированием.';
    throw error;
  } finally { savingConfig = false; }
}
function uiRules() {
  return configState.config.rules.map(r => ({
    ...r, enabled:r.enabled !== false, source:r.log_source, path:r.path_regex, query:r.query_regex || '',
    statuses:(r.statuses || []).join(', '), group:r.group_by, unique:r.unique_by || '',
    action:r.action || 'dry_run',
    command:r.command || '',
    blockDuration:r.block_duration || '',
    repeatBlockMultiplier:r.repeat_block_multiplier || 1,
    repeatBlockMaxDuration:r.repeat_block_max_duration || ''
  }));
}
async function saveRule(before, after) {
  const change = {rules:{},add_rules:[],delete_rules:[]};
  if(before && (!after || before.id !== after.id)) change.delete_rules.push(before.id);
  if(after) {
    const r = {enabled:after.enabled,log_source:after.source,path_regex:after.path,query_regex:after.query,
      statuses:after.statuses.split(',').map(v=>Number(v.trim())).filter(Boolean), command:after.command || '',
      group_by:after.group,unique_by:after.unique,window:after.window,threshold:after.threshold,type:after.type || 'rate',block_duration:after.blockDuration || '',
      repeat_block_multiplier:after.repeatBlockMultiplier || 1,repeat_block_max_duration:after.repeatBlockMaxDuration || ''};
    r.action = after.action;
    if(['nftables','iptables'].includes(r.action) && (!before || before.action !== after.action)) {
      if(!confirm('После перезапуска это правило будет блокировать IP в firewall. Продолжить?')) throw new Error('Сохранение отменено.');
      change.confirm_real_blocks = true;
    }
    if(before && before.id === after.id) change.rules[before.id] = r;
    else change.add_rules.push({...r,id:after.id,ignore_ips:before?.ignore_ips || [],methods:before?.methods || []});
    if (after.action === 'soft_block' && after.captchaTTL && after.captchaTTL !== configState.config.soft_block?.cookie_ttl) {
      change.cookie_ttl = after.captchaTTL;
    }
  }
  await saveConfig(change);
}
function uiSources() {
  return configState.config.sources.map(s=>({name:s.id,path:s.path,format:s.format,pattern:s.log_format || ''}));
}
