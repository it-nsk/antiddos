function initIncidents({snapshot, rules, frames}, incidents) {
  const get = key => document.getElementById('hit-' + key);
  const minute = 60000;
  const day = 1440 * minute;
  const range = createTimeRange('hit', snapshot, day, draw);
  const graph = createSeriesChart(get, rules, frames, range, 'Срабатываний');
  function draw(liveTick = false) {
    graph.draw();
    if (!liveTick) document.dispatchEvent(new Event('logban-range'));
    document.dispatchEvent(new CustomEvent('logban-detections-range', {detail: {liveTick}}));
  }

  const pager = createTablePager(get, journal);
  function journal() {
    const rows = incidents.filter(row => row.hits);
    rows.sort((a, b) => b.start - a.start);
    const list = get('list');
    const expanded = new Set([...list.querySelectorAll('details[open]')].map(detail => detail.dataset.rule));
    list.replaceChildren();
    for (const row of pager.rows(rows)) {
      const tr = list.insertRow();
      const start = range.format(row.start).replace(' ', ', ') + ' ' + range.timeZone();
      const avg = row.blocked ? (row.delay / row.blocked / 1000).toLocaleString('ru-RU', {maximumFractionDigits: 2}) + ' с' : '—';
      for (const value of [start, row.rule.name, row.hits]) tr.insertCell().textContent = value;
      const detail = document.createElement('details');
      detail.dataset.rule = row.rule.name;
      const summary = document.createElement('summary');
      summary.textContent = row.ips.length;
      summary.setAttribute('aria-label', 'IP-адреса по правилу ' + row.rule.name + ': ' + row.ips.length);
      const addresses = document.createElement('div');
      addresses.className = 'overflow-auto small mt-2';
      addresses.style.maxHeight = '10rem';
      detail.append(summary, addresses);
      detail.ontoggle = () => {
        if (!detail.open || addresses.childElementCount) return;
        for (const ip of row.ips) {
          const line = document.createElement('div');
          line.className = 'text-nowrap';
          line.textContent = ip;
          addresses.append(line);
        }
      };
      tr.insertCell().append(detail);
      detail.open = expanded.has(row.rule.name);
      for (const value of [row.requests, row.blocked ?? '—', avg]) tr.insertCell().textContent = value;
    }
    if (!rows.length) {
      const cell = list.insertRow().insertCell();
      cell.colSpan = 7;
      cell.textContent = 'Срабатываний пока нет.';
    }
  }
  function refresh(liveTick = false) {
    draw(liveTick);
    if (!get('list').querySelector('details[open]')) journal();
  }
  document.addEventListener('logban-data', () => refresh(true));
  refresh();
  return range;
}
