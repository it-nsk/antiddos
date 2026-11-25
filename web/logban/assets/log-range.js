function createTimeRange(prefix, snapshot, duration, onChange) {
  const get = name => document.getElementById(prefix + '-' + name);
  const content = document.getElementById('time-range-template').content.cloneNode(true);
  for (const part of content.querySelectorAll('[data-range-part]')) part.id = prefix + '-' + part.dataset.rangePart;
  get('range-control').append(content);
  const toggle = get('range-toggle'), form = get('range-form');
  const from = get('from'), to = get('to');
  const timezone = get('timezone'), timezoneReset = get('timezone-reset');
  const day = 86400000;
  const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const zones = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : ['UTC', browserZone];
  let zone = localStorage.getItem('logban-timezone') || browserZone;
  if (!zones.includes(zone) && zone !== 'UTC') zone = browserZone;
  const cities = {
    'Europe/Kaliningrad': 'Калининград', 'Europe/Moscow': 'Москва', 'Europe/Samara': 'Самара',
    'Asia/Yekaterinburg': 'Екатеринбург', 'Asia/Omsk': 'Омск', 'Asia/Novosibirsk': 'Новосибирск',
    'Asia/Barnaul': 'Барнаул', 'Asia/Tomsk': 'Томск', 'Asia/Krasnoyarsk': 'Красноярск',
    'Asia/Irkutsk': 'Иркутск', 'Asia/Chita': 'Чита', 'Asia/Yakutsk': 'Якутск',
    'Asia/Vladivostok': 'Владивосток', 'Asia/Magadan': 'Магадан', 'Asia/Kamchatka': 'Камчатка'
  };
  function offsetMinutes(name, ms = snapshot) {
    if (name === 'UTC') return 0;
    const value = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {timeZone: name, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'}).formatToParts(new Date(ms)).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
    // The formatter deliberately has minute precision; compare it with the
    // same minute boundary so current seconds cannot turn UTC+3 into UTC+2:59.
    return (Date.UTC(value.year, Number(value.month) - 1, value.day, value.hour, value.minute) - Math.floor(ms / 60000) * 60000) / 60000;
  }
  function zoneCaption(name = zone) {
    const minutes = offsetMinutes(name);
    const sign = minutes < 0 ? '−' : '+';
    const absolute = Math.abs(minutes);
    const offset = minutes === 0 ? 'UTC' : `UTC${sign}${Math.floor(absolute / 60)}${absolute % 60 ? ':' + String(absolute % 60).padStart(2, '0') : ''}`;
    return name === 'UTC' ? offset : offset + ' · ' + (cities[name] || name);
  }
  for (const name of ['UTC', browserZone, ...zones]) {
    if ([...timezone.options].some(option => option.value === name)) continue;
    timezone.add(new Option(zoneCaption(name), name));
  }
  timezone.value = zone;
  const parts = ms => Object.fromEntries(new Intl.DateTimeFormat('en-CA', {timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).formatToParts(new Date(ms)).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
  const iso = ms => { const p = parts(ms); return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`; };
  const stamp = ms => { const p = parts(ms); return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`; };
  function wallTime(text) {
    const match = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/.exec(text);
    if (!match) return NaN;
    const [, year, month, date, hour, minute] = match;
    const naive = Date.UTC(year, Number(month) - 1, date, hour, minute);
    const offset = time => { const p = parts(time); return Date.UTC(p.year, Number(p.month) - 1, p.day, p.hour, p.minute, p.second) - time; };
    let result = naive - offset(naive);
    result = naive - offset(result);
    return iso(result) === text ? result : NaN;
  }
  function value(field) {
    const text = field.value.trim().replace('T', ' ');
    if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(text)) return NaN;
    return wallTime(text);
  }
  // Air Datepicker uses local Date objects, while the selected calendar day is
  // represented in the selected time zone.
  function calendarDate(ms) {
    const p = parts(ms);
    return new Date(p.year, Number(p.month) - 1, p.day);
  }
  const zoneDay = d => wallTime(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} 00:00`);
  let applied = [snapshot - duration, snapshot];
  let zoomBase = null;
  let following = true, draftFollowing = true;
  function caption() {
    const [a, b] = applied.map(iso);
    get('range-label').textContent = a.slice(5) + ' – ' + (a.slice(0,10) === b.slice(0,10) ? b.slice(11) : b.slice(5)) + ' ' + zoneCaption();
    toggle.setAttribute('aria-label', 'Выбрать период: ' + get('range-label').textContent);
  }
  const picker = new AirDatepicker(get('calendar'), {
    inline: true,
    range: true,
    toggleSelected: false,
    startDate: calendarDate(snapshot),
    maxDate: calendarDate(snapshot),
    onSelect({date}) {
      if (!date.length) return;
      draftFollowing = false;
      from.value = iso(zoneDay(date[0]));
      const nextDay = new Date(date[date.length - 1]); nextDay.setDate(nextDay.getDate() + 1);
      to.value = iso(Math.min(snapshot, zoneDay(nextDay)));
      to.setCustomValidity('');
    }
  });
  function syncCalendar() {
    const start = value(from), finish = value(to);
    if (!Number.isFinite(start) || !Number.isFinite(finish) || finish <= start || finish > snapshot) return;
    const dates = [calendarDate(start), calendarDate(finish - 1)];
    picker.update({maxDate: calendarDate(snapshot), selectedDates: dates}, {silent: true});
    picker.setViewDate(dates[1]);
  }
  for (const [minutes, label] of [[15,'15 минут'],[30,'30 минут'],[60,'1 час'],[360,'6 часов'],[720,'12 часов'],[1440,'24 часа'],[10080,'7 дней'],[43200,'30 дней']]) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'dropdown-item small rounded px-2';
    button.textContent = 'За ' + label;
    button.onclick = () => {
      draftFollowing = true;
      from.value = iso(snapshot - minutes * 60000);
      to.value = iso(snapshot);
      syncCalendar();
    };
    get('presets').append(button);
  }
  toggle.addEventListener('show.bs.dropdown', () => {
    draftFollowing = following;
    from.value = iso(applied[0]); to.value = iso(applied[1]);
    to.setCustomValidity('');
    syncCalendar();
  });
  for (const field of [from, to]) {
    field.addEventListener('input', () => { draftFollowing = false; to.setCustomValidity(''); syncCalendar(); });
  }
  timezone.addEventListener('change', () => {
    const current = applied.slice();
    zone = timezone.value;
    localStorage.setItem('logban-timezone', zone);
    from.value = iso(current[0]); to.value = iso(current[1]);
    syncCalendar(); caption();
    document.dispatchEvent(new Event('logban-timezone'));
  });
  timezoneReset.addEventListener('click', () => {
    timezone.value = browserZone;
    timezone.dispatchEvent(new Event('change'));
  });
  form.onsubmit = event => {
    event.preventDefault();
    for (const field of [from, to]) {
      const ms = value(field);
      const error = !Number.isFinite(ms) ? 'Введите дату и время в формате ГГГГ-ММ-ДД ЧЧ:ММ.'
        : ms > snapshot ? 'Дата и время должны быть не позже ' + iso(snapshot) + ' (' + zoneCaption() + ').' : '';
      if (error) {
        field.setCustomValidity(error);
        field.reportValidity();
        field.setCustomValidity('');
        return;
      }
    }
    if (value(from) >= value(to)) {
      to.setCustomValidity('Конец интервала должен быть позже начала.');
      to.reportValidity();
      to.setCustomValidity('');
      return;
    }
    applied = [value(from), value(to)];
    zoomBase = null;
    following = draftFollowing;
    caption();
    bootstrap.Dropdown.getInstance(toggle).hide();
    toggle.focus();
    onChange();
  };
  caption();
  return {
    current: () => applied,
    set(start, finish) {
      if (!Number.isFinite(start) || !Number.isFinite(finish) || finish <= start) return;
      if (!zoomBase) zoomBase = applied.slice();
      applied = [start, finish];
      following = false;
      caption();
      onChange();
    },
    resetZoom() {
      if (!zoomBase) return;
      applied = zoomBase;
      zoomBase = null;
      following = false;
      caption();
      onChange();
    },
    following: () => following,
    timeZone: zoneCaption,
    format: stamp,
    advance(delta, currentTime) {
      if (currentTime !== undefined) snapshot = currentTime;
      if (!following || form.classList.contains('show')) return false;
      if (currentTime === undefined) snapshot += delta;
      applied = [snapshot - (applied[1] - applied[0]), snapshot];
      caption();
      return true;
    }
  };
}
