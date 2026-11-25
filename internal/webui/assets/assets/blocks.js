function initBlocks(items) {
  const list = document.getElementById('block-list');
  const search = document.getElementById('block-search');
  const status = document.getElementById('block-status');
  const add = document.getElementById('block-add');
  const startedHeader = document.getElementById('block-started-header');
  const expiresHeader = document.getElementById('block-expires-header');
  add.disabled = true;
  add.title = 'Ручное добавление блокировок пока не поддерживается API';
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
    }
    if(!list.rows.length) { const cell=list.insertRow().insertCell();cell.colSpan=4;cell.textContent='Активных блокировок нет.'; }
  }
  status.textContent = 'Данные сервера. Ручное добавление и снятие блокировок через UI пока недоступны.';
  search.addEventListener('input',render);
  document.addEventListener('logban-timezone', render);
  render();
  return render;
}
