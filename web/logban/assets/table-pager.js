function createTablePager(get, render) {
  const pageSize = get('page-size');
  let page = 1;
  pageSize.addEventListener('change', () => {
    page = 1;
    render();
  });
  get('prev').addEventListener('click', () => {
    page--;
    render();
  });
  get('next').addEventListener('click', () => {
    page++;
    render();
  });

  function rows(items) {
    const size = Number(pageSize.value);
    const pages = Math.max(1, Math.ceil(items.length / size));
    page = Math.max(1, Math.min(page, pages));
    const start = (page - 1) * size;
    const end = Math.min(start + size, items.length);
    get('range').textContent = items.length ? `${start + 1}–${end} из ${items.length}` : '0 из 0';
    get('page').textContent = page;
    get('page').setAttribute('aria-label', `Страница ${page} из ${pages}`);
    get('prev').disabled = page === 1;
    get('next').disabled = page === pages;
    get('prev').parentElement.classList.toggle('disabled', page === 1);
    get('next').parentElement.classList.toggle('disabled', page === pages);
    return items.slice(start, end);
  }

  function showRow(index) {
    page = Math.floor(index / Number(pageSize.value)) + 1;
  }
  return {rows, showRow};
}
