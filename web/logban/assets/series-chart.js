function createSeriesChart(get, lines, frames, range, quantity, {rateUnit = '', field = 'counts', factor = 1, totalUnit = ''} = {}) {
  const perSecond = Boolean(rateUnit);
  const minute = 60000, day = 1440 * minute;
  const rateFormat = new Intl.NumberFormat('ru-RU', {maximumSignificantDigits: 3});
  const hidden = new Set();
  const labels = lines.map(line => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-sm text-start d-flex align-items-center gap-2';
    const eye = document.createElement('i');
    eye.style.color = line.color;
    eye.setAttribute('aria-hidden', 'true');
    const label = document.createElement('span');
    label.textContent = line.name;
    const count = document.createElement('span');
    count.className = 'ms-auto text-body-secondary';
    button.append(eye, label, count);
    get('legend').append(button);
    button.onclick = () => {
      if (hidden.has(line)) hidden.delete(line);
      else hidden.add(line);
      draw();
    };
    return {button, eye, count};
  });
  const host = get('chart');
  const clock = time => new Date(time).toISOString().slice(11, 16);
  let chart;
  let selectionStart = null;
  let selectionCurrent = null;
  let zoom = null;
  const selection = document.createElement('div');
  selection.className = 'series-chart-selection';
  selection.hidden = true;
  host.append(selection);
  host.classList.add('position-relative');
  const tip = document.createElement('div');
  tip.className = 'series-tooltip';
  tip.hidden = true;
  const heading = document.createElement('strong');
  tip.append(heading);
  const readings = lines.map(line => {
    const row = document.createElement('div');
    row.className = 'series-reading';
    const dot = document.createElement('i');
    dot.style.backgroundColor = line.color;
    const name = document.createElement('span');
    name.textContent = line.name;
    const value = document.createElement('b');
    row.append(dot, name, value);
    tip.append(row);
    return {row, value};
  });
  host.append(tip);
  const stamp = time => new Date(time).toISOString().slice(5, 16).replace('T', ' ');
  function renderAxis(start, finish) {
    get('axis').replaceChildren(...[start, (start + finish) / 2, finish].map(t => {
      const span = document.createElement('span');
      span.textContent = (finish - start >= day ? new Date(t).toISOString().slice(5,10) + ' ' : '') + clock(t) + ' UTC';
      return span;
    }));
  }
  function showValues(plot) {
    const {idx, left, top} = plot.cursor;
    tip.hidden = idx == null || left < 0 || top < 0 || hidden.size === lines.length;
    if (tip.hidden) return;
    heading.textContent = stamp(plot.data[0][idx]) + ' UTC';
    readings.forEach(({row, value}, i) => {
      row.hidden = hidden.has(lines[i]);
      const reading = plot.data[i + 1][idx];
      value.textContent = perSecond ? rateFormat.format(reading) + ' ' + rateUnit : reading;
    });
    const x = plot.over.offsetLeft + plot.valToPos(plot.data[0][idx], 'x');
    const y = plot.over.offsetTop + top;
    const leftEdge = x + 14 + tip.offsetWidth <= host.clientWidth ? x + 14 : x - 14 - tip.offsetWidth;
    tip.style.left = Math.max(0, leftEdge) + 'px';
    tip.style.top = Math.max(0, Math.min(y - tip.offsetHeight / 2, host.clientHeight - tip.offsetHeight)) + 'px';
  }
  function draw() {
    if (!host.clientWidth) return;
    const [start, finish] = range.current();
    const bucket = Math.max(minute, Math.ceil((finish - start) / (288 * minute)) * minute);
    const first = Math.floor(start / bucket) * bucket;
    const size = Math.ceil((finish - first) / bucket);
    const x = Array.from({length: size}, (_, i) => (Math.max(start, first + i * bucket) + Math.min(finish, first + (i + 1) * bucket)) / 2);
    const series = lines.map(() => Array(size).fill(0));
    for (const frame of frames) {
      if (frame.time < start || frame.time >= finish) continue;
      const index = Math.floor((frame.time - first) / bucket);
      lines.forEach((line, i) => { series[i][index] += frame[field][line.index ?? i] ?? 0; });
    }
    let total = 0;
    let peak = perSecond ? 0 : 1;
    lines.forEach((line, i) => {
      const active = !hidden.has(line);
      const sum = series[i].reduce((a, b) => a + b, 0);
      if (perSecond) {
        series[i] = series[i].map((count, index) => {
          const left = first + index * bucket;
          const seconds = (Math.min(finish, left + bucket) - Math.max(start, left)) / 1000;
          return count * factor / seconds;
        });
      }
      labels[i].eye.className = active ? 'bi bi-eye' : 'bi bi-eye-slash';
      labels[i].button.setAttribute('aria-pressed', String(active));
      labels[i].button.setAttribute('aria-label', (active ? 'Скрыть ' : 'Показать ') + line.name);
      labels[i].count.textContent = totalUnit ? rateFormat.format(sum * factor) + ' ' + totalUnit : sum;
      if (active) {
        total += sum;
        peak = Math.max(peak, ...series[i]);
      }
    });
    const data = [x, ...series];
    if (!chart) {
      chart = new uPlot({
        width: host.clientWidth, height: host.clientHeight,
        legend: {show: false}, cursor: {
          x: false, y: false, drag: {x: false, y: false},
          points: {size: 9, width: 0, fill: (_, i) => lines[i - 1].color}
        },
        scales: {x: {time: false, range: (u, a, b) => [a, b]}, y: {range: (u, a, b) => [0, b || 1]}},
        axes: [{show: false}, {size: perSecond ? 44 : 26, stroke: '#858d96', ticks: {show: false}, grid: {stroke: 'rgba(128,140,150,.22)', width: 1}, ...(perSecond ? {} : {incrs: [1,2,5,10,20,50,100,200,500,1000,5000,10000]})}],
        hooks: {setCursor: [showValues]},
        series: [{}, ...lines.map(line => ({
          label: line.name, stroke: line.color, width: 2,
          paths: uPlot.paths.spline(), points: {show: plot => plot.data[0].length === 1},
          fill: plot => {
            const {top, height} = plot.bbox;
            const gradient = plot.ctx.createLinearGradient(0, top, 0, top + height);
            gradient.addColorStop(0, line.color + '60');
            gradient.addColorStop(1, line.color + '08');
            return gradient;
          }
        }))]
      }, data, host);
      chart.over.addEventListener('pointerdown', event => {
        if (event.pointerType === 'mouse') return;
        const rect = chart.over.getBoundingClientRect();
        chart.setCursor({left: event.clientX - rect.left, top: event.clientY - rect.top});
      });
      chart.over.addEventListener('mousedown', event => {
        if (event.button !== 0) return;
        selectionStart = event.offsetX;
        selectionCurrent = selectionStart;
        selection.hidden = false;
        selection.style.left = selectionStart + 'px';
        selection.style.width = '0px';
        chart.over.setPointerCapture?.(event.pointerId);
      });
      chart.over.addEventListener('mousemove', event => {
        if (selectionStart == null) return;
        const left = Math.min(selectionStart, event.offsetX);
        const width = Math.abs(event.offsetX - selectionStart);
        selectionCurrent = event.offsetX;
        selection.style.left = left + 'px';
        selection.style.width = width + 'px';
      });
      const finishSelection = event => {
        if (selectionStart == null) return;
        const startPixel = selectionStart;
        const rect = chart.over.getBoundingClientRect();
        const endPixel = Math.max(0, Math.min(chart.over.clientWidth, selectionCurrent ?? (event.clientX - rect.left)));
        selectionStart = null;
        selectionCurrent = null;
        selection.hidden = true;
        if (Math.abs(endPixel - startPixel) < 8) return;
        const a = chart.posToVal(Math.min(startPixel, endPixel), 'x');
        const b = chart.posToVal(Math.max(startPixel, endPixel), 'x');
        if (Number.isFinite(a) && Number.isFinite(b) && b > a) {
          zoom = {min: a, max: b};
          chart.setScale('x', zoom);
          renderAxis(a, b);
          range.set?.(a, b);
        }
      };
      chart.over.addEventListener('mouseup', finishSelection);
      document.addEventListener('mouseup', finishSelection);
      chart.over.addEventListener('dblclick', () => {
        const [start, finish] = range.current();
        zoom = null;
        chart.setScale('x', {min: start, max: finish});
        renderAxis(start, finish);
        range.resetZoom?.();
      });
    }
    chart.batch(() => {
      chart.setData(data, false);
      lines.forEach((r, i) => {
        if (chart.series[i + 1].show === hidden.has(r)) chart.setSeries(i + 1, {show: !hidden.has(r)});
      });
      const min = zoom ? Math.max(start, zoom.min) : start;
      const max = zoom ? Math.min(finish, zoom.max) : finish;
      chart.setScale('x', max > min ? {min, max} : {min: start, max: finish});
      chart.setScale('y', {min: 0, max: peak || 1});
    });
    if (get('total')) get('total').textContent = total;
    host.setAttribute('aria-label', quantity + ' за выбранный период: ' + (totalUnit ? rateFormat.format(total * factor) + ' ' + totalUnit : total));
    renderAxis(zoom && zoom.max > zoom.min ? Math.max(start, zoom.min) : start, zoom && zoom.max > zoom.min ? Math.min(finish, zoom.max) : finish);
  }

  const observer = new ResizeObserver(() => {
    if (!host.clientWidth) return;
    chart?.setSize({width: host.clientWidth, height: host.clientHeight});
    draw();
  });
  observer.observe(host);
  return {
    draw,
    destroy() {
      observer.disconnect();
      tip.remove();
      selection.remove();
      if (typeof finishSelection === 'function') document.removeEventListener('mouseup', finishSelection);
      chart?.destroy();
      get('legend').replaceChildren();
    }
  };
}
