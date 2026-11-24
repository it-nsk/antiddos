function initSources(initial) {
  const get = id => document.getElementById('source-' + id);
  const raw = String.raw;
  const quoted = raw`(?:[^"\\]|\\.)*`;
  const syslogTime = raw`(?<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+))`;
  const formats = {
    nginx_combined: {
      label: 'Nginx combined access', path: '/var/log/nginx/access.log',
      pattern: raw`^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time_local>[^\]]+)\]\s+"(?<request>${quoted})"\s+(?<status>\d{3})\s+(?<body_bytes_sent>\d+|-)\s+"${quoted}"\s+"(?<http_user_agent>${quoted})"(?:\s+.*)?$`
    },
    nginx_error: {
      label: 'Nginx error', path: '/var/log/nginx/error.log',
      pattern: raw`^(?<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?\bclient: (?<ip>[\da-fA-F:.]+)(?:,.*)?$`
    },
    syslog_sshd: {
      label: 'OpenSSH auth.log', path: '/var/log/auth.log',
      pattern: raw`^${syslogTime}\s+.*?\bsshd(?:-session)?(?:\[\d+\])?: .*?(?:[Ff]ailed (?:password|publickey)|[Ii]nvalid user|authentication failure).*?(?:\bfrom\s+|\brhost=)(?<ip>[\da-fA-F:.]+)(?:\s.*)?$`
    },
    netfilter_log: {
      label: 'UFW / kernel netfilter', path: '/var/log/ufw.log',
      pattern: raw`^${syslogTime}\s+.*?\bSRC=(?<ip>\S+)\s+.*?\bPROTO=(?<protocol>\S+)\s+.*?\bDPT=(?<dst_port>\d+)\b.*$`
    },
    nginx_custom: {label: 'Nginx log_format', path: '/var/log/nginx/access.log', pattern: ''}
  };

  // Each entry supplies a named capture and a matching value for the same example.
  const fields = [
    ['ip', 'IP клиента', raw`\S+`, '192.0.2.10'],
    ['time_local', 'Локальное время Nginx', raw`[^"]+`, '22/Nov/2026:10:00:00 +0000'],
    ['time_iso8601', 'Время в ISO 8601', raw`\S+`, '2026-11-22T10:00:00Z'],
    ['msec', 'Unix-время в секундах', raw`\d+(?:\.\d+)?`, '1795341600.123'],
    ['request', 'Строка HTTP-запроса', quoted, 'GET /items?q=1 HTTP/1.1'],
    ['method', 'HTTP-метод', raw`\S+`, 'GET'],
    ['uri', 'Путь запроса', raw`\S+`, '/items'],
    ['request_uri', 'URI с параметрами', raw`\S+`, '/items?q=1'],
    ['status', 'HTTP-статус', raw`\d{3}`, '200'],
    ['body_bytes_sent', 'Размер тела ответа, байты', raw`\d+|-`, '120'],
    ['bytes_sent', 'Размер ответа с заголовками, байты', raw`\d+|-`, '300'],
    ['request_time', 'Длительность запроса, секунды', raw`\d+(?:\.\d+)?|-`, '0.025'],
    ['http_user_agent', 'User-Agent', quoted, 'Example Browser'],
    ['response_origin', 'Источник ответа', 'application|challenge|service', 'application'],
    ['timestamp', 'Время события системного журнала', raw`[^"]+`, 'Nov 22 10:00:00'],
    ['protocol', 'Протокол', raw`\S+`, 'TCP'],
    ['dst_port', 'Порт назначения', raw`\d+`, '443']
  ];
  get('example-line').textContent = fields.map(([,,, value]) => '"' + value + '"').join(' ');
  get('example-pattern').textContent = '^' + fields.map(([name,, re]) => `"(?<${name}>${re})"`).join(raw`\s+`) + '$';
  for (const [name, label] of fields) {
    const item = document.createElement('div');
    item.className = 'col';
    const term = document.createElement('dt');
    const code = document.createElement('code');
    code.textContent = name;
    term.append(code);
    const description = document.createElement('dd');
    description.className = 'mb-1';
    description.textContent = label;
    item.append(term, description);
    get('groups').append(item);
  }

  const format = get('format');
  const name = get('name');
  const path = get('path');
  const pattern = get('pattern');
  for (const [value, preset] of Object.entries(formats)) format.add(new Option(preset.label, value));
  const dialog = get('modal');
  const modal = bootstrap.Modal.getOrCreateInstance(dialog);
  const pager = createTablePager(get, render);
  let editable = document.body.dataset.page !== 'panel';
  let sources = [];
  let original = null;
  let focusName;
  let previousFormat;
  const drafts = new Map();

  function readSources() {
    return uiSources();
  }

  window.logbanSources = () => sources.map(({name, path}) => ({name, path}));

  function render() {
    const list = get('list');
    list.replaceChildren();
    get('add').hidden = !editable;
    get('actions').hidden = !editable;
    for (const source of pager.rows(sources)) {
      const row = list.insertRow();
      row.insertCell().textContent = source.name;
      const file = row.insertCell();
      file.className = 'font-monospace text-break';
      file.textContent = source.path;
      row.insertCell().textContent = formats[source.format].label;
      if (editable) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-sm btn-outline-secondary';
        button.textContent = 'Редактировать';
        button.setAttribute('aria-label', 'Редактировать ' + source.name);
        button.dataset.sourceName = source.name;
        button.addEventListener('click', () => open(source));
        const action = row.insertCell();
        action.className = 'text-end';
        action.append(button);
      }
    }
    if (!sources.length) {
      const cell = list.insertRow().insertCell();
      cell.colSpan = editable ? 4 : 3;
      cell.className = 'text-body-secondary';
      cell.textContent = 'Источники логов пока не добавлены.';
    }
  }

  function refresh() {
    try {
      sources = readSources();
    } catch {
      get('status').textContent = 'Не удалось прочитать источники из хранилища браузера.';
    }
    render();
  }

  function changeFormat() {
    const preset = formats[format.value];
    pattern.value = drafts.get(format.value) ?? preset.pattern;
    path.placeholder = preset.path;
    get('help').hidden = format.value !== 'nginx_custom';
    pattern.readOnly = format.value !== 'nginx_custom';
    previousFormat = format.value;
  }

  function open(source) {
    if (!editable) return;
    original = source;
    focusName = source?.name;
    drafts.clear();
    if (source) drafts.set(source.format, source.pattern);
    name.value = source?.name ?? '';
    path.value = source?.path ?? '';
    format.value = source?.format ?? 'nginx_combined';
    changeFormat();
    get('help').open = false;
    get('title').textContent = source ? 'Редактировать источник' : 'Добавить источник';
    get('save-error').hidden = true;
    for (const input of [name, path, pattern]) input.classList.remove('is-invalid');
    name.readOnly = Boolean(source);
    get('save').disabled = Boolean(source);
    get('save').title = source ? 'Изменение существующих источников пока не поддерживается API' : '';
    modal.show();
  }

  function patternError() {
    if (!pattern.value.trim()) return 'Введите паттерн с именованной группой.';
    let groups;
    try {
      // An empty first alternative exposes group names without running the user's pattern.
      groups = new RegExp('(?:)|(?:' + pattern.value + ')', 'u').exec('').groups;
    } catch {
      return 'Проверьте синтаксис регулярного выражения.';
    }
    if (!groups) return 'Добавьте хотя бы одну именованную группу, например (?<ip>\\S+).';
    const unknown = Object.keys(groups).find(key => !fields.some(([field]) => field === key));
    return unknown ? 'Неизвестная группа «' + unknown + '».' : '';
  }

  get('add').addEventListener('click', () => open(null));
  format.addEventListener('change', () => {
    drafts.set(previousFormat, pattern.value);
    changeFormat();
    pattern.classList.remove('is-invalid');
  });
  dialog.addEventListener('shown.bs.modal', () => name.focus());
  dialog.addEventListener('hidden.bs.modal', () => {
    const edit = Array.from(get('list').querySelectorAll('button')).find(button => button.dataset.sourceName === focusName);
    (edit ?? get('add')).focus();
  });
  get('form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!editable) return;
    const error = get('save-error');
    error.hidden = true;
    try {
      const latest = readSources();
      if (original && !latest.some(source => source.name === original.name && source.path === original.path &&
        source.format === original.format && source.pattern === original.pattern)) {
        error.textContent = 'Источник изменился. Закройте форму и откройте его заново.';
        error.hidden = false;
        refresh();
        return;
      }
      const others = latest.filter(source => source.name !== original?.name);
      const record = {name: name.value.trim(), path: path.value.trim(), format: format.value, pattern: pattern.value};
      const errors = [
        [name, !record.name || /\s/u.test(record.name) ? 'Введите имя источника без пробелов.' :
          others.some(source => source.name === record.name) ? 'Источник с таким именем уже есть.' : ''],
        [path, !record.path.startsWith('/') ? 'Укажите абсолютный путь к файлу лога.' :
          others.some(source => source.path === record.path) ? 'Этот путь уже указан у другого источника.' : ''],
        [pattern, format.value === 'nginx_custom' && !pattern.value.trim() ? 'Введите log_format Nginx.' : '']
      ];
      for (const [input, message] of errors) {
        input.classList.toggle('is-invalid', Boolean(message));
        document.getElementById(input.id + '-error').textContent = message;
      }
      const invalid = errors.find(([,message]) => message);
      if (invalid) {
        invalid[0].focus();
        return;
      }
      const next = original ? latest.map(source => source.name === original.name ? record : source) : [...latest, record];
      if(original) throw new Error('Изменение существующего источника пока не поддерживается API.');
      await saveConfig({add_sources:[{id:record.name,path:record.path,format:record.format,log_format:record.format === 'nginx_custom' ? record.pattern : ''}],
        add_rules:[{id:record.name+'-monitor',enabled:false,type:'rate',log_source:record.name,path_regex:'.*',window:'1m',threshold:100,group_by:'ip',ignore_ips:[],action:'dry_run'}]});
      document.dispatchEvent(new Event('logban-config'));
      sources = next;
      pager.showRow(next.indexOf(record));
      focusName = record.name;
      render();
      get('status').textContent = 'Источник «' + record.name + '» сохранён на сервере с выключенным правилом наблюдения.';
      modal.hide();
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      refresh();
    }
  });

  document.addEventListener('logban-session', event => {
    editable = event.detail.role === 'admin';
    render();
  });
  refresh();
}
