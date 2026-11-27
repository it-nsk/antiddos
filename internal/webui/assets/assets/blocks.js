function initBlocks(items) {
  const list = document.getElementById('block-list');
  const search = document.getElementById('block-search');
  const status = document.getElementById('block-status');
  const startedHeader = document.getElementById('block-started-header');
  const expiresHeader = document.getElementById('block-expires-header');
  const ipInput = document.getElementById('block-ip');
  const durationSelect = document.getElementById('block-duration');
  const customDuration = document.getElementById('block-duration-custom');
  const submit = document.getElementById('block-submit');
  const formError = document.getElementById('block-form-error');
  const ipError = document.getElementById('block-ip-error');
  function validIP(text) {
    const ipv6 = text.includes(':');
    if (!ipv6) { const octets=text.split('.'); return octets.length===4 && octets.every(n=>/^(0|[1-9]\d{0,2})$/.test(n)&&Number(n)<=255); }
    if (!/^[\da-f:.]+$/i.test(text)) return false;
    try { new URL('http://[' + text + ']'); return true; } catch { return false; }
  }
  function updateIPValidity() {
    const value = ipInput.value.trim();
    const invalid = Boolean(value) && !validIP(value);
    ipInput.classList.toggle('is-invalid', invalid);
    ipInput.setAttribute('aria-invalid', String(invalid));
    ipError.textContent = invalid ? 'Неверный IP-адрес или CIDR.' : '';
    submit.disabled = !value || invalid;
    return !value || invalid;
  }
  ipInput.addEventListener('input', updateIPValidity);
  updateIPValidity();
  durationSelect.replaceChildren();
  for (const [label, duration] of [['5 минут','5m'],['1 час','1h'],['1 день','24h'],['7 дней','168h'],['30 дней','720h'],['Своё значение','custom']]) {
      const option=document.createElement('option'); option.value=duration; option.textContent=label + (duration !== 'custom' ? ' (' + duration + ')' : ''); durationSelect.append(option);
  }
  durationSelect.addEventListener('change', () => { customDuration.hidden = durationSelect.value !== 'custom'; });
  const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const cities = {'Europe/Moscow': 'Москва', 'Asia/Yekaterinburg': 'Екатеринбург', 'Asia/Omsk': 'Омск', 'Asia/Novosibirsk': 'Новосибирск', 'Asia/Krasnoyarsk': 'Красноярск', 'Asia/Irkutsk': 'Иркутск', 'Asia/Yakutsk': 'Якутск', 'Asia/Vladivostok': 'Владивосток'};
  function zone() { return localStorage.getItem('logban-timezone') || browserZone; }
  function caption(name = zone(), at = Date.now()) {
    if (name === 'UTC') return 'UTC';
    const values = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {timeZone: name, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'}).formatToParts(new Date(at)).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
    const minutes = (Date.UTC(values.year, Number(values.month) - 1, values.day, values.hour, values.minute) - Math.floor(at / 60000) * 60000) / 60000;
    const sign = minutes < 0 ? '−' : '+';
    const absolute = Math.abs(minutes);
    const offset = `UTC${sign}${Math.floor(absolute / 60)}${absolute % 60 ? ':' + String(absolute % 60).padStart(2, '0') : ''}`;
    return offset + ' · ' + (cities[name] || name);
  }
  const time = seconds => new Date(seconds * 1000).toLocaleString('ru-RU', {timeZone: zone()});
  async function unblock(ip) {
    try {
      await requestAPI('blocks/unblock', 'POST', {ip});
      const index = items.findIndex(item => item.ip === ip);
      if(index >= 0) items.splice(index, 1);
      render();
    } catch(error) { showBackendStatus(error.message); }
  }
  function parseDuration(value) {
    const match = /^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?$/.exec(value.trim());
    if (!match || !match[0].replace(/[hms]/g, '').trim() || !(Number(match[1]||0)*3600 + Number(match[2]||0)*60 + Number(match[3]||0) > 0)) throw new Error('Укажите срок в формате 15m, 2h30m или 720h');
    return (Number(match[1]||0)*3600 + Number(match[2]||0)*60 + Number(match[3]||0)) * 1000;
  }
  submit.addEventListener('click', async () => {
    formError.hidden = true; submit.disabled = true;
    try {
      const ip = ipInput.value.trim();
      if (!ip) throw new Error('Укажите IP-адрес');
      if (updateIPValidity()) throw new Error('Исправьте IP-адрес');
      const duration = parseDuration(durationSelect.value === 'custom' ? customDuration.value : durationSelect.value);
      const expiresAt = new Date(Date.now() + duration);
      await requestAPI('blocks', 'POST', {ip, rule_id: 'manual', expires_at: expiresAt.toISOString()});
      items.push({ip, rule: 'manual', started_at: Math.floor(Date.now()/1000), expires_at: Math.floor(expiresAt.getTime()/1000), origin:'external'});
      ipInput.value = ''; render();
    } catch(error) { formError.textContent = error.message; formError.hidden = false; }
    finally { submit.disabled = false; }
  });
  function render() {
    const label = caption();
    startedHeader.textContent = 'Дата добавления (' + label + ')';
    expiresHeader.textContent = 'Дата снятия (' + label + ')';
    list.replaceChildren();
    for(const item of items.filter(item=>item.ip.toLowerCase().includes(search.value.trim().toLowerCase()))) {
      const row = list.insertRow();
      for(const value of [item.ip,item.rule || 'Внешняя блокировка',time(item.started_at)])
        row.insertCell().textContent=value;
      row.insertCell().textContent = time(item.expires_at);
      const action = row.insertCell();
      const remove = document.createElement('button');
      remove.type = 'button'; remove.className = 'btn btn-danger btn-sm'; remove.textContent = '×';
      remove.title = 'Снять блокировку'; remove.setAttribute('aria-label', 'Снять блокировку ' + item.ip);
      remove.addEventListener('click', () => unblock(item.ip));
      action.append(remove);
    }
    if(!list.rows.length) { const cell=list.insertRow().insertCell();cell.colSpan=4;cell.textContent='Активных блокировок нет.'; }
  }
  status.textContent = 'Данные сервера. Нажмите ×, чтобы снять блокировку.';
  search.addEventListener('input',render);
  document.addEventListener('logban-timezone', render);
  render();
  return render;
}
