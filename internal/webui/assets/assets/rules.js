function initRules(samples, sourceList) {
  const get = id => document.getElementById('rule-' + id);
  const form = get('form');
  // Validation is performed explicitly in the submit handler so an invalid
  // hidden control can never make the Save button appear to do nothing.
  form.noValidate = true;
  const saveButton = get('save');
  // Bootstrap's modal can retain native constraint-validation state for a
  // hidden field. Submit explicitly so clicking Save always reaches our
  // validation and API error handling instead of failing silently.
  saveButton.type = 'button';
  saveButton.addEventListener('click', () => {
    form.dispatchEvent(new Event('submit', {cancelable: true}));
  });
  const modal = bootstrap.Modal.getOrCreateInstance(get('modal'));
  const pager = createTablePager(get, render);
  const defaults = {
    id: '', enabled: true, source: '', path: '^/', query: '', statuses: '',
    window: '1s', threshold: 20, group: 'ip', unique: '', action: 'dry_run', command: '', blockDuration: '', captchaTTL: '', repeatBlockMultiplier: 1, repeatBlockMaxDuration: ''
  };
  const sampleSources = new Map(sourceList.map(source => [source.name, source.path]));
  let rules = [];
  let original = null;
  let returnFocus;
  let editable = document.body.dataset.page !== 'panel';

  function readRules() {
    const data = uiRules();
    if (!Array.isArray(data) || !data.every(rule => rule && typeof rule.id === 'string')) {
      throw new Error('Не удалось прочитать сохранённые правила.');
    }
    return data;
  }

  function refresh() {
    try {
      rules = readRules();
    } catch {
      get('status').textContent = 'Не удалось прочитать правила из хранилища браузера.';
    }
    render();
  }

  function iconButton(icon, label, style) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-sm ' + style;
    button.setAttribute('aria-label', label);
    const glyph = document.createElement('i');
    glyph.className = 'bi bi-' + icon;
    glyph.setAttribute('aria-hidden', 'true');
    button.append(glyph);
    return button;
  }

  function render() {
    const list = get('list');
    list.replaceChildren();
    get('count').textContent = rules.length;
    get('add').hidden = !editable;
    get('actions').hidden = !editable;
    for (const rule of pager.rows(rules)) {
      const row = list.insertRow();
      const name = document.createElement('button');
      name.type = 'button';
      name.className = 'btn btn-link text-start p-0 fw-semibold font-monospace';
      name.textContent = rule.id;
      name.dataset.ruleId = rule.id;
      name.addEventListener('click', () => open(rule));
      row.insertCell().append(name);
      row.insertCell().textContent = rule.source;
      const condition = rule.type === 'cardinality' ? 'уникальных значений' : 'событий';
      row.insertCell().textContent = rule.threshold === 1 ? 'Одно совпадение' : rule.threshold + ' ' + condition + ' / ' + rule.window;
      row.insertCell().textContent = Array.from(get('action').options).find(option => option.value === rule.action)?.text ?? rule.action;

      const state = row.insertCell();
      const label = document.createElement('label');
      label.className = 'form-check form-switch mb-0 text-nowrap';
      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.className = 'form-check-input';
      toggle.setAttribute('role', 'switch');
      toggle.setAttribute('aria-label', 'Включено — ' + rule.id);
      toggle.checked = rule.enabled;
      toggle.disabled = !editable;
      toggle.addEventListener('change', () => {
        const index = row.sectionRowIndex;
        commit(rule, {...rule, enabled: toggle.checked});
        list.querySelectorAll('input')[index]?.focus();
      });
      label.append(toggle, rule.enabled ? 'Включено' : 'Выключено');
      state.append(label);

      if (editable) {
        const cell = row.insertCell();
        cell.className = 'text-end text-nowrap';
        const edit = iconButton('pencil', 'Редактировать ' + rule.id, 'btn-outline-secondary');
        edit.addEventListener('click', () => open(rule));
        const history = iconButton('clock-history', 'Пересчитать правило по последнему архиву логов. Требуется подключение к LogBan.', 'btn-outline-secondary');
        history.disabled = true;
        const remove = iconButton('trash', 'Удалить ' + rule.id, 'btn-outline-danger');
        remove.addEventListener('click', () => {
          if (window.confirm('Удалить правило «' + rule.id + '»?')) commit(rule, null);
        });
        const actions = document.createElement('div');
        actions.className = 'd-inline-flex gap-1';
        actions.append(edit, history, remove);
        cell.append(actions);
      }
    }
    if (!rules.length) {
      const cell = list.insertRow().insertCell();
      cell.colSpan = editable ? 6 : 5;
      cell.className = 'text-body-secondary';
      cell.textContent = 'Правила пока не добавлены.';
    }
  }

  function updateActionOptions(selected) {
    const select = get('action');
    select.replaceChildren();
    for (const action of window.logbanActions()) {
      const label = action.enabled ? action.name : action.name + ' (выключено)';
      select.add(new Option(label, action.id));
    }
    if (selected && !Array.from(select.options).some(option => option.value === selected)) {
      select.add(new Option(selected, selected));
    }
    if (selected) select.value = selected;
  }

  function open(rule) {
    if (!rule && !editable) return;
    original = rule;
    returnFocus = rule?.id;
    const available = new Map(window.logbanSources().map(source => [source.name, source.path]));
    if (rule && !available.has(rule.source)) available.set(rule.source, sampleSources.get(rule.source) ?? '');
    get('source').replaceChildren();
    for (const [id, path] of available) get('source').add(new Option(path ? id + ' · ' + path : id, id));
    const draft = rule ?? {...defaults, source: available.keys().next().value};
    updateActionOptions(draft.action);
    for (const field of Object.keys(defaults)) {
      const input = get(field);
      if (!input) continue;
      input.disabled = !editable;
      input.setCustomValidity('');
      if (field === 'enabled') input.checked = draft.enabled;
      else if (field === 'unique') input.value = draft.type === 'cardinality' ? draft.unique : '';
      else input.value = draft[field] ?? '';
    }
    updateStateLabel();
    get('action').disabled = !editable;
    get('action').title = '';
    const duration = draft.blockDuration || '';
    get('block-duration').value = ['5m','15m','1h','24h','168h','720h','permanent',''].includes(duration) ? duration : 'custom';
    get('block-duration-custom').value = get('block-duration').value === 'custom' ? duration : '';
    const repeatEnabled = Number(draft.repeatBlockMultiplier) > 1;
    get('repeat-enabled').checked = repeatEnabled;
    get('repeat-multiplier').value = String(repeatEnabled ? draft.repeatBlockMultiplier : 2);
    const repeatMax = draft.repeatBlockMaxDuration || '24h';
    get('repeat-max-duration').value = ['15m','1h','24h','168h','720h'].includes(repeatMax) ? repeatMax : 'custom';
    get('repeat-max-custom').value = get('repeat-max-duration').value === 'custom' ? repeatMax : '';
    get('captcha-ttl').value = draft.captchaTTL || configState.config.soft_block?.cookie_ttl || '30m';
    updateActionFields();
    get('title').textContent = !editable ? 'Просмотр правила' : rule ? 'Редактировать правило' : 'Добавить правило';
    get('save').hidden = !editable;
    get('error').hidden = true;
    modal.show();
  }

  function updateActionFields() {
    const action = get('action').value;
    const firewall = action === 'nftables' || action === 'iptables';
    get('firewall-options').hidden = !firewall;
    get('repeat-enabled').disabled = !firewall || !editable;
    const progressive = firewall && get('repeat-enabled').checked;
    get('repeat-options').hidden = !progressive;
    get('captcha-options').hidden = action !== 'soft_block';
    get('custom-command-options').hidden = action !== 'custom';
    const permanent = get('block-duration').querySelector('option[value="permanent"]');
    if (permanent) permanent.disabled = action !== 'nftables';
    if (action === 'iptables' && get('block-duration').value === 'permanent') get('block-duration').value = '';
    const command = {
      nftables: 'nft add element inet antiddos blocked { <IP> timeout <срок> }',
      iptables: 'ipset add antiddos-blocked <IP> timeout <срок>',
      soft_block: 'CAPTCHA-проверка через soft-block proxy; cookie TTL: ' + (get('captcha-ttl').value || '30m')
    }[action];
    get('action-command').hidden = !command;
    get('action-command').textContent = command ? 'Будет выполнено: ' + command : '';
    const custom = get('block-duration').value === 'custom';
    get('block-duration-custom').hidden = !custom || !firewall;
    get('block-duration-help').hidden = !custom || !firewall;
    const repeatCustom = get('repeat-max-duration').value === 'custom';
    get('repeat-max-custom').hidden = !progressive || !repeatCustom;
    if (progressive) {
      const base = get('block-duration').value === 'custom' ? (get('block-duration-custom').value || 'срок сервера') : (get('block-duration').value || 'срок сервера');
      const max = repeatCustom ? (get('repeat-max-custom').value || '…') : get('repeat-max-duration').value;
      get('repeat-help').textContent = 'Базовый срок ' + base + ', множитель ×' + get('repeat-multiplier').value + ': ' + base + ' → …; не выше ' + max + '. Серия сбрасывается через 7 дней.';
    }
  }

  async function commit(before, after) {
    if (!editable) return false;
    const inModal = get('modal').classList.contains('show');
    const feedback = inModal ? get('error') : get('status');
    try {
      const latest = readRules();
      const index = before ? latest.findIndex(rule => rule.id === before.id) : latest.length;
      if (before && JSON.stringify(latest[index]) !== JSON.stringify(before)) {
        feedback.textContent = 'Список правил изменился. Откройте правило заново.';
        feedback.hidden = false;
        refresh();
        return false;
      }
      if (after && latest.some((rule, i) => i !== index && rule.id === after.id)) {
        get('id').setCustomValidity('Правило с таким именем уже есть.');
        get('id').reportValidity();
        return false;
      }
      const next = latest.slice();
      if (after) next[index] = after;
      else next.splice(index, 1);
      await saveRule(before, after);
      rules = uiRules();
      if (after) pager.showRow(index);
      render();
      get('status').textContent = after ? 'Правило «' + after.id + '» сохранено на сервере.' : 'Правило «' + before.id + '» удалено.';
      return true;
    } catch (error) {
      feedback.textContent = error.message;
      feedback.hidden = false;
      render();
      return false;
    }
  }

  function validateRegex(field) {
    // Accept the leading case-insensitive flag used by the LogBan presets.
    try { new RegExp(get(field).value.replace(/^\(\?i\)/, '')); }
    catch { get(field).setCustomValidity('Проверьте регулярное выражение.'); }
  }

  function updateStateLabel() {
    get('state').textContent = get('enabled').checked ? 'Включено' : 'Выключено';
  }

  get('enabled').addEventListener('change', updateStateLabel);
  get('action').addEventListener('change', updateActionFields);
  get('block-duration').addEventListener('change', updateActionFields);
  get('repeat-enabled').addEventListener('change', updateActionFields);
  get('repeat-multiplier').addEventListener('change', updateActionFields);
  get('repeat-max-duration').addEventListener('change', updateActionFields);
  get('repeat-max-custom').addEventListener('input', updateActionFields);
  form.addEventListener('input', event => event.target.setCustomValidity?.(''));
  get('add').addEventListener('click', () => open(null));
  document.addEventListener('logban-new-action', event => {
    if (!editable) return;
    open(null);
    get('action').value = event.detail.action;
    if (event.detail.command) get('command').value = event.detail.command;
    if (event.detail.alias) get('id').value = event.detail.alias.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    updateActionFields();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!editable) return;
    const save = saveButton;
    if (save.disabled) return;
    const rule = {...original};
    for (const field of Object.keys(defaults)) {
      // These fields are represented by separate controls and are copied below.
      if (['enabled', 'blockDuration', 'captchaTTL', 'repeatBlockMultiplier', 'repeatBlockMaxDuration'].includes(field)) continue;
      rule[field] = get(field).value.trim();
    }
    rule.blockDuration = get('block-duration').value === 'custom' ? get('block-duration-custom').value.trim() : get('block-duration').value;
    rule.repeatBlockMultiplier = get('repeat-enabled').checked ? Number(get('repeat-multiplier').value) : 1;
    rule.repeatBlockMaxDuration = get('repeat-max-duration').value === 'custom' ? get('repeat-max-custom').value.trim() : get('repeat-max-duration').value;
    if (rule.repeatBlockMultiplier === 1) rule.repeatBlockMaxDuration = '';
    if (rule.blockDuration && rule.blockDuration !== 'permanent' && !/^(?=.*\d)(?:\d+(?:ns|us|µs|ms|s|m|h))+$/i.test(rule.blockDuration)) {
      get('block-duration-custom').setCustomValidity('Укажите длительность, например 90s, 15m или 2h30m.');
    }
    if (rule.repeatBlockMultiplier > 1 && (!/^(?=.*\d)(?:\d+(?:ns|us|µs|ms|s|m|h))+$/i.test(rule.repeatBlockMaxDuration) || rule.repeatBlockMaxDuration === 'permanent')) {
      get('repeat-max-custom').setCustomValidity('Укажите положительный максимальный срок, например 2h или 24h.');
    }
    rule.captchaTTL = get('captcha-ttl').value;
    rule.enabled = get('enabled').checked;
    rule.threshold = Number(rule.threshold);
    if (!rule.id || /\s/.test(rule.id)) get('id').setCustomValidity('Введите имя правила без пробелов.');
    if (rule.action === 'custom' && !/^\/\S+(?:\s+\S+)*$/.test(rule.command)) get('command').setCustomValidity('Укажите абсолютный путь к программе и аргументы.');

    if (rule.statuses && !/^[1-9]\d{2}(?:\s*,\s*[1-9]\d{2})*$/.test(rule.statuses)) {
      get('statuses').setCustomValidity('Укажите трёхзначные HTTP-статусы через запятую.');
    }
    if (rule.unique) rule.type = 'cardinality';
    else rule.type = rule.threshold === 1 && rule.window === '1s' ? 'signature' : 'rate';
    if (!/^(?:(?:\d+(?:\.\d+)?|\.\d+)(?:ns|us|µs|ms|s|m|h))+$/.test(rule.window) || !/[1-9]/.test(rule.window)) {
      get('window').setCustomValidity('Укажите положительный интервал, например 10s или 1m30s.');
    }
    if (!form.checkValidity()) {
      const invalid = Array.from(form.elements).find(element => !element.validity?.valid);
      const feedback = get('error');
      feedback.textContent = invalid?.validationMessage || 'Проверьте заполнение полей правила.';
      feedback.hidden = false;
      invalid?.focus();
      return;
    }
    save.disabled = true;
    const saved = await commit(original, rule);
    save.disabled = false;
    if (!saved) return;
    returnFocus = rule.id;
    modal.hide();
    // Keep the modal state deterministic when a save finishes during the
    // Bootstrap transition (the table is re-rendered by commit()).
    const element = get('modal');
    element.classList.remove('show');
    element.setAttribute('aria-hidden', 'true');
    element.style.display = 'none';
  });
  get('modal').addEventListener('shown.bs.modal', () => (editable ? get('id') : get('modal')).focus());
  get('modal').addEventListener('hidden.bs.modal', () => {
    const name = Array.from(get('list').querySelectorAll('[data-rule-id]')).find(button => button.dataset.ruleId === returnFocus);
    (name ?? get('add')).focus();
  });
  document.addEventListener('logban-session', event => {
    editable = event.detail.role === 'admin';
    render();
  });
  document.addEventListener('logban-actions', () => {
    updateActionOptions(get('action').value);
    render();
  });
  window.logbanRuleNames = () => rules.map(rule => rule.id);
  updateActionOptions();
  document.addEventListener('logban-config', refresh);
  refresh();
}
