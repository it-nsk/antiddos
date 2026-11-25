function initLogs({sources: demoSources, frames}, records, detectionsRange) {
  function recentRecords(source, start, finish, limit) {
    return (records[source] ?? []).filter(row => row.time >= start && row.time < finish).sort((a,b)=>b.time-a.time).slice(0, limit);
  }

  function explorer() {
    const get = key => document.getElementById('log-' + key);
    const range = detectionsRange;
    let graph, traffic;
    function loadSources() {
      const select = get('source');
      const names = [...new Set([...window.logbanSources().map(item => item.name), ...demoSources])];
      if (graph && names.every((name, i) => select.options[i + 1]?.value === name) && select.length === names.length + 1) return;
      const selected = select.value;
      select.options.length = 1;
      for (const name of names) select.add(new Option(name, name));
      select.value = names.includes(selected) ? selected : '';
      graph?.destroy();
      traffic?.destroy();
      const palette = ['#d78c34', '#10828f', '#9370b5', '#4385f5'];
      const lines = names.map(name => {
        const index = demoSources.indexOf(name);
        return {name, index, color: palette[index < 0 ? 3 : index]};
      });
      graph = createSeriesChart(get, lines, frames, range, 'Обращений', {rateUnit: 'зап/с', axisUnit: ''});
      traffic = createSeriesChart(key => get('traffic-' + key), lines,
        frames, range, 'Объём ответов', {field: 'responseSizes', rateUnit: 'Мб/с', factor: 8 / 1000000, totalUnit: 'Мб'});
    }
    function element(tag, classes, text) {
      const node = document.createElement(tag);
      node.className = classes;
      node.textContent = text;
      return node;
    }
    function appendLogMessage(row, record) {
      const summary = record.method ? [record.method, record.status, record.path].join(' · ') : record.summary;
      const button = element('button', 'log-disclosure', '');
      button.type = 'button';
      const arrow = element('i', 'bi bi-chevron-down', '');
      arrow.setAttribute('aria-hidden', 'true');
      if (record.method) {
        button.classList.add('log-http-summary');
        button.append(element('span', '', record.method), element('span', '', record.status),
          element('span', 'text-truncate', record.path));
      } else {
        button.append(element('span', 'text-truncate', summary));
      }
      button.append(arrow);
      row.insertCell().append(button);

      const detail = row.parentNode.insertRow();
      detail.hidden = true;
      detail.id = 'log-detail-' + record.id + '-' + record.time;
      const cell = detail.insertCell();
      cell.colSpan = 3;
      cell.append(element('pre', 'log-raw mb-0', record.raw));
      button.setAttribute('aria-controls', detail.id);
      function setExpanded(open) {
        detail.hidden = !open;
        button.setAttribute('aria-expanded', String(open));
        button.setAttribute('aria-label', (open ? 'Свернуть' : 'Раскрыть') + ' строку журнала · ' + summary);
      }
      setExpanded(false);
      button.onclick = () => setExpanded(detail.hidden);
    }
    function render(liveTick = false) {
      const source = get('source').value;
      get('work').hidden = !source;
      graph.draw();
      traffic.draw();
      if (!source || document.getElementById('logs').hidden) return;
      const [start, finish] = range.current();
      const rows = recentRecords(source, start, finish, Number(get('page-size').value));
      const headers = ['Время (' + range.timeZone() + ')', 'IP-адрес', 'Сообщение'];
      if (liveTick === true && (get('list').querySelector('[aria-expanded="true"]') || get('list').contains(document.activeElement))) return;
      if (liveTick !== true) get('head').replaceChildren(...headers.map(text => element('th', 'text-nowrap', text)));
      const list = get('list');
      list.replaceChildren();
      for (const record of rows) {
        const row = list.insertRow();
        row.insertCell().textContent = range.format(record.time).slice(11, 19);
        const address = row.insertCell();
        address.className = 'text-nowrap';
        address.textContent = record.ip;
        appendLogMessage(row, record);
      }
      if (!rows.length) {
        const cell = list.insertRow().insertCell();
        cell.colSpan = headers.length;
        cell.textContent = 'За выбранный период обращений нет.';
      }
    }
    get('page-size').addEventListener('change', render);
    document.addEventListener('logban-detections-range', event => {
      render(event.detail.liveTick);
    });
    get('source').addEventListener('change', render);
    window.addEventListener('hashchange', () => {
      if (get('chart').getClientRects().length) loadSources();
      render();
    });
    loadSources();
    render();
  }
  explorer();
}
