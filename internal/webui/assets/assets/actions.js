function initActions() {
  const names = {dry_run:'Наблюдение', nftables:'Блокировка nftables', iptables:'Блокировка iptables', soft_block:'Проверка CAPTCHA', custom:'Своё действие'};
  const actions = Object.entries(names).map(([id, name]) => ({id, name}));
  const get = id => document.getElementById('action-' + id);
  const dialog = get('modal');
  const modal = bootstrap.Modal.getOrCreateInstance(dialog);
  window.logbanActions = () => actions.map(action => ({...action, enabled:true}));
  get('count').textContent = actions.length;
  get('add').hidden = session.user.role !== 'admin';
  get('add').onclick = () => {
    const name = get('name');
    if (name.tagName === 'INPUT') {
      const select = Object.assign(document.createElement('select'), {id:'action-name', className:'form-select', required:true});
      name.replaceWith(select);
    }
    const select = get('name');
    select.replaceChildren(...actions.map(action => new Option(action.name, action.id)));
    document.querySelector('label[for="action-name"]').textContent = 'Действие нового правила';
    get('enabled').closest('.col-sm-4').hidden = true;
    const commandLabel = document.querySelector('label[for="action-command"]');
    const toggleCustom = () => {
      const custom = select.value === 'custom';
      get('command').hidden = !custom;
      commandLabel.hidden = !custom;
      get('command').required = custom;
      let alias = document.getElementById('action-alias-wrap');
      if (custom && !alias) {
        alias = document.createElement('div'); alias.id = 'action-alias-wrap'; alias.className = 'mt-3';
        alias.innerHTML = '<label class="form-label" for="action-alias">Название действия</label><input class="form-control" id="action-alias" placeholder="Например: Бан в fail2ban" required>';
        get('command').before(alias);
      }
      if (alias) alias.hidden = !custom;
    };
    select.onchange = toggleCustom;
    toggleCustom();
    get('title').textContent = 'Добавить действие';
    get('error').hidden = true;
    modal.show();
  };
  get('form').onsubmit = event => {
    event.preventDefault();
    const action = get('name').value;
    const command = get('command').value.trim();
    const alias = document.getElementById('action-alias')?.value.trim() || '';
    if (action === 'custom' && (!alias || !command)) return;
    modal.hide();
    location.hash = '#rules';
    setTimeout(() => document.dispatchEvent(new CustomEvent('logban-new-action', {detail:{action, command, alias}})), 0);
  };
  const list = get('list');
  list.replaceChildren();
  for (const action of actions) {
    const row = list.insertRow();
    for (const value of [action.name, 'Включено', 'Встроенное действие сервера']) row.insertCell().textContent = value;
  }
  get('status').textContent = 'Добавьте действие: будет создано правило с выбранным действием.';
  document.addEventListener('logban-session', event => { get('add').hidden = event.detail.role !== 'admin'; });
}
