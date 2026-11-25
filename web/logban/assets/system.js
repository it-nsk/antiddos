function initSystem(host, detectionsRange) {
  const step = host.interval_seconds * 1000;
  const origin = host.start * 1000;
  const sampleCount = host.series.cpu_pct.length;
  const now = origin + (sampleCount - 1) * step;
  const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
  const format = value => number.format(value);
  const colors = ['#3975e5', '#39a47a'];

  function channel(label, key, capacity) {
    const samples = host.series[key].map(v => capacity == null ? v : 100 * v / capacity);
    const prefix = [0];
    for (const value of samples) prefix.push(prefix.at(-1) + value);
    return {label, average: (a, b) => (prefix[b] - prefix[a]) / (b - a)};
  }
  const metrics = [
    {name: 'Процессор', unit: '%', context: host.cpu_cores + ' ядра / ' + host.cpu_threads + ' потоков · ' + format(host.cpu_ghz) + ' ГГц', lines: [channel('Процессор', 'cpu_pct')]},
    ...[['Память', 'memory'], ['Подкачка', 'swap'], ['Диск', 'disk']].map(([name, key]) => {
      const capacity = host[key + '_total_gib'];
      return {name, disk: key === 'disk', unit: '%', capacity, lines: capacity ? [channel(name, key + '_used_gib', capacity)] : []};
    }),
    {name: 'Трафик', unit: 'КиБ/с', context: host.interface, lines: [channel('Отдача', 'tx_kib_s'), channel('Приём', 'rx_kib_s')]},
    {name: 'Соединения', unit: 'сокетов', lines: [channel('TCP', 'tcp'), channel('UDP', 'udp')]}
  ];
  function node(parent, tag, cls, text = '') {
    const el = document.createElement(tag);
    el.className = cls;
    el.textContent = text;
    parent.append(el);
    return el;
  }
  function card(container, metric, full) {
    const box = node(container, 'article', 'card system-metric');
    node(box, 'h3', 'h6 mb-1', metric.name);
    const primary = node(box, 'div', 'system-number');
    const note = node(box, 'div', 'small text-body-secondary');
    if (!metric.lines.length) {
      primary.textContent = '—';
      note.textContent = 'Не настроена';
      return () => {};
    }
    const plot = node(box, 'div', 'system-plot');
    plot.setAttribute('role', 'img');
    const tip = node(plot, 'div', 'series-tooltip');
    tip.hidden = true;
    const stats = node(box, 'div', 'small text-body-secondary');
    let chart, selectedRange;
    const clock = ms => selectedRange ? selectedRange.format(ms).slice(5, 19) : new Date(ms).toISOString().slice(5, 19).replace('T', ' ');
    const zone = () => selectedRange?.timeZone() || 'UTC';
    return (start, finish, range) => {
      selectedRange = range;
      const first = Math.max(0, Math.ceil((start - origin) / step));
      const end = Math.min(sampleCount, Math.floor((finish - origin) / step) + 1);
      plot.hidden = first >= end;
      if (plot.hidden) {
        primary.textContent = '—';
        note.textContent = 'За выбранный период данных нет.';
        stats.textContent = '';
        return;
      }
      const stride = Math.max(1, Math.ceil((end - first) / (full ? 240 : host.window_samples)));
      const data = [[], ...metric.lines.map(() => [])];
      for (let a = first; a < end; a += stride) {
        const b = Math.min(a + stride, end);
        data[0].push(origin + (a + b - 1) / 2 * step);
        metric.lines.forEach((line, i) => data[i + 1].push(line.average(a, b)));
      }
      const latest = metric.lines.map(line => line.average(end - 1, end));
      const total = latest.reduce((a,b) => a + b, 0);
      primary.textContent = format(total) + ' ' + metric.unit;
      note.textContent = metric.capacity ? format(total * metric.capacity / 100) + ' / ' + format(metric.capacity) + ' ГиБ'
        : [metric.context, ...metric.lines.flatMap((line,i) => metric.lines.length > 1 ? [line.label + ' ' + format(latest[i])] : [])].filter(Boolean).join(' · ');
      const average = metric.lines.reduce((sum, line) => sum + line.average(first, end), 0);
      let peak = 0;
      for (let n = first; n < end; n++) {
        peak = Math.max(peak, metric.lines.reduce((sum, line) => sum + line.average(n, n + 1), 0));
      }
      stats.textContent = 'Среднее ' + format(average) + ' ' + metric.unit + ' · Пик ' + format(peak) + ' ' + metric.unit;
      if (metric.disk) stats.textContent += ' · Свободно ' + format(metric.capacity * (1 - total / 100)) + ' ГиБ';
      plot.setAttribute('aria-label', metric.name + ' · ' + primary.textContent + ' · ' + stats.textContent);
      if (!chart) {
        chart = new uPlot({
          width: plot.clientWidth, height: plot.clientHeight,
          scales: {x: {time: false, range: (_, a, b) => [a,b]}, y: {range: (_, a, b) => [0, Math.max(1,b * 1.1)]}},
          legend: {show: false}, cursor: {y: false, drag: {x: false, y: false}},
          axes: [{show: full, size: 24, stroke: '#808080', grid: {show: false}, ticks: {show: false},
            splits: (_, axis, min, max) => [min + (max - min) / 6, (min + max) / 2, max - (max - min) / 6],
            values: (_, ticks) => ticks.map(t => clock(t).slice(0,11) + ' ' + zone())},
            {show: full, size: 42, stroke: '#808080', ticks: {show: false}, grid: {stroke: 'rgba(128,128,128,.20)'}}],
          series: [{}, ...metric.lines.map((line,i) => ({label: line.label, stroke: colors[i], fill: colors[i] + '20', width: 2, paths: uPlot.paths.spline(), points: {show: false}}))],
          hooks: {setCursor: [u => {
            const {idx,left,top} = u.cursor;
            tip.hidden = idx == null || left < 0 || top < 0;
            if (!tip.hidden) tip.textContent = [clock(u.data[0][idx]) + ' ' + zone(), ...metric.lines.map((l,i) => l.label + ' · ' + format(u.data[i + 1][idx]) + ' ' + metric.unit)].join('\n');
          }]}
        }, data, plot);
        new ResizeObserver(() => {
          if (plot.clientWidth) chart.setSize({width: plot.clientWidth,height: plot.clientHeight});
        }).observe(plot);
      }
      chart.batch(() => { chart.setData(data); chart.setScale('x', {min:start,max:finish}); });
    };
  }
  const views = ['dashboard', 'system'].map(id => {
    const section = document.getElementById(id);
    const container = document.getElementById(id + '-metrics');
    const range = id === 'dashboard' ? detectionsRange : createTimeRange(id, now, 15 * 60000, render);
    const cards = metrics.map(m => card(container, m, id === 'system'));
    return {range, section, cards};
  });
  function render() {
    for (const view of views) {
      if (!view.section.getClientRects().length) continue;
      const bounds = view.range.current();
      for (const update of view.cards) update(...bounds, view.range);
    }
  }
  for (const {section} of views) new ResizeObserver(render).observe(section);
  document.addEventListener('logban-detections-range', render);
  render();
}
