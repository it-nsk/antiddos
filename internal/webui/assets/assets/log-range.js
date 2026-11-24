function createTimeRange(prefix, snapshot, duration, onChange) {
  const get = name => document.getElementById(prefix + '-' + name);
  const content = document.getElementById('time-range-template').content.cloneNode(true);
  for (const part of content.querySelectorAll('[data-range-part]')) part.id = prefix + '-' + part.dataset.rangePart;
  get('range-control').append(content);
  const toggle = get('range-toggle'), form = get('range-form');
  const from = get('from'), to = get('to');
  const day = 86400000;
  const iso = ms => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
  function value(field) {
    const text = field.value.trim().replace('T', ' ');
    if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(text)) return NaN;
    const ms = Date.parse(text.replace(' ', 'T') + ':00Z');
    return Number.isFinite(ms) && iso(ms) === text ? ms : NaN;
  }
  // Air Datepicker uses local calendar dates. Form values are always UTC.
  function calendarDate(ms) {
    const d = new Date(ms);
    return new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  }
  const utcDay = d => Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
  let applied = [snapshot - duration, snapshot];
  let zoomBase = null;
  let following = true, draftFollowing = true;
  function caption() {
    const [a, b] = applied.map(iso);
    get('range-label').textContent = a.slice(5) + ' – ' + (a.slice(0,10) === b.slice(0,10) ? b.slice(11) : b.slice(5)) + ' UTC';
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
      from.value = iso(utcDay(date[0]));
      to.value = iso(Math.min(snapshot, utcDay(date[date.length - 1]) + day));
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
  form.onsubmit = event => {
    event.preventDefault();
    for (const field of [from, to]) {
      const ms = value(field);
      const error = !Number.isFinite(ms) ? 'Введите дату и время в формате ГГГГ-ММ-ДД ЧЧ:ММ.'
        : ms > snapshot ? 'Дата и время должны быть не позже ' + iso(snapshot) + ' UTC.' : '';
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
