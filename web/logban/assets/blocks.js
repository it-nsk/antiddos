function initBlocks(items) {
  const list = document.getElementById('block-list');
  const search = document.getElementById('block-search');
  const status = document.getElementById('block-status');
  const add = document.getElementById('block-add');
  add.disabled = true;
  add.title = 'Ручное добавление блокировок пока не поддерживается API';
  function render() {
    list.replaceChildren();
    for(const item of items.filter(item=>item.ip.toLowerCase().includes(search.value.trim().toLowerCase()))) {
      const row = list.insertRow();
      for(const value of [item.ip,item.rule || 'Внешняя блокировка',new Date(item.started_at*1000).toLocaleString('ru-RU')])
        row.insertCell().textContent=value;
      row.insertCell().textContent = 'До '+new Date(item.expires_at*1000).toLocaleString('ru-RU');
    }
    if(!list.rows.length) { const cell=list.insertRow().insertCell();cell.colSpan=4;cell.textContent='Активных блокировок нет.'; }
  }
  status.textContent = 'Данные сервера. Ручное добавление и снятие блокировок через UI пока недоступны.';
  search.addEventListener('input',render);
  render();
  return render;
}
