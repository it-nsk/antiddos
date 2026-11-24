(() => {
  const get = id => document.getElementById('allow-' + id);
  const editor = get('addresses');
  const mask = get('mask');
  let saved = '';
  let editable = document.body.dataset.page !== 'panel';
  let storageError = '';
  let loadState = 'idle';

  async function loadExample() {
    if (loadState !== 'idle' || document.getElementById('allowlist').hidden) return;
    loadState = 'loading';
    get('loading').hidden = false;
    get('failed').hidden = true;
    try {
      const example = await readApi('config');
      if (!Array.isArray(example.config.ignore_ips) || !example.config.ignore_ips.every(ip => typeof ip === 'string' && validEntry(ip))) {
        throw new Error('allowlist');
      }
      saved = example.config.ignore_ips.join('\n');

      draft = saved;
      filter();
      get('card').hidden = false;
      loadState = 'ready';
    } catch {
      loadState = 'idle';
      get('failed').hidden = false;
    } finally {
      get('loading').hidden = true;
    }
  }

  function validEntry(text) {
    const [ip, prefix, ...extra] = text.split('/');
    const ipv6 = ip.includes(':');
    if (extra.length || (prefix !== undefined &&
      (!/^(0|[1-9]\d{0,2})$/.test(prefix) || Number(prefix) > (ipv6 ? 128 : 32)))) return false;
    if (!ipv6) {
      const octets = ip.split('.');
      return octets.length === 4 && octets.every(n => /^(0|[1-9]\d{0,2})$/.test(n) && Number(n) <= 255);
    }
    if (!/^[\da-f:.]+$/i.test(ip)) return false;
    try {
      new URL('http://[' + ip + ']');
      return true;
    } catch {
      return false;
    }
  }

  let draft = '';
  let projection = null;
  const tokens = text => text.match(/[^\s,]+/g) || [];

  function filter() {
    const prefix = mask.value.trim().toLowerCase();
    projection = null;
    if (prefix) {
      const all = tokens(draft);
      const selected = all.filter(text => text.toLowerCase().startsWith(prefix));
      projection = { all, prefix, initial: selected.join('\n'), original: draft };
      editor.value = projection.initial;
    } else {
      editor.value = draft;
    }
    editor.placeholder = prefix ? 'Совпадений нет' : 'Список пуст';
    get('clear').hidden = !mask.value;
    get('results').hidden = !prefix;
    update();
  }

  // Keep hidden entries and merge edits against the snapshot taken when the query changed.
  function readEditor() {
    if (!projection) {
      draft = editor.value;
    } else if (editor.value === projection.initial) {
      draft = projection.original;
    } else {
      const visible = tokens(editor.value);
      let next = 0;
      const merged = [];
      for (const text of projection.all) {
        if (!text.toLowerCase().startsWith(projection.prefix)) merged.push(text);
        else if (next < visible.length) merged.push(visible[next++]);
      }
      draft = merged.concat(visible.slice(next)).join('\n');
    }
    update();
  }

  function update() {
    let error = '';
    const visible = tokens(editor.value);
    get('count').textContent = 'Показано записей: ' + visible.length;
    get('remove').disabled = !editable || !visible.length;
    const lines = draft.split('\n');
    for (const [index, line] of lines.entries()) {
      const invalid = tokens(line).find(text => !validEntry(text));
      if (invalid) {
        error = 'Строка ' + (index + 1) + ' полного списка: «' + invalid + '» — неверный IP-адрес или CIDR.';
        break;
      }
    }
    editor.readOnly = !editable;
    editor.classList.toggle('is-invalid', Boolean(error));
    editor.setAttribute('aria-invalid', String(Boolean(error)));
    editor.setCustomValidity(error);
    get('error').textContent = error;
    const dirty = draft !== saved;
    get('save').disabled = !editable || !dirty || Boolean(error);
    get('reset').disabled = !editable || !dirty;
    get('status').textContent = storageError || (dirty ? 'Есть несохранённые изменения' : '');
  }

  mask.addEventListener('input', filter);
  editor.addEventListener('input', readEditor);
  get('clear').addEventListener('click', () => {
    mask.value = '';
    filter();
    mask.focus();
  });
  get('remove').addEventListener('click', () => {
    if (!editable || !projection) return;
    editor.value = '';
    readEditor();
  });
  get('reset').addEventListener('click', () => {
    draft = saved;
    filter();
  });
  get('save').addEventListener('click', async () => {
    if (!editable || !editor.reportValidity()) return;
    try {
      await saveConfig({ignore_ips:tokens(draft)});
      saved = draft;
      storageError = '';
      update();
      get('status').textContent = 'Все изменения сохранены на сервере';
    } catch (error) {
      storageError = error.message;
      update();
    }
  });
  document.addEventListener('logban-session', event => {
    editable = event.detail.role === 'admin';
    update();
  });
  get('retry').addEventListener('click', loadExample);
  window.addEventListener('hashchange', loadExample);
  loadExample();
})();
