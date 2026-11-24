const pageLinks = document.querySelectorAll('#navigation a[href^="#"]');

const headerItems = document.querySelectorAll('.app-header [data-header-page]');

const settingsToggle = document.getElementById('settings-toggle');
const settingsMenu = document.getElementById('settings-menu');

function expandSettings(expanded) {
  settingsToggle.parentElement.classList.toggle('menu-open', expanded);
  settingsToggle.setAttribute('aria-expanded', String(expanded));
}

settingsToggle.addEventListener('click', () => {
  expandSettings(settingsToggle.getAttribute('aria-expanded') === 'false');
});

function showPage() {
  const current = Array.from(pageLinks).find(link => link.hash === location.hash) || pageLinks[0];
  const page = current.hash.slice(1);
  if (page === 'dashboard' || page === 'incidents') {
    document.getElementById(page + '-detections').append(document.getElementById('detections-card'));
    document.getElementById('hit-title').textContent = page === 'dashboard' ? 'Инциденты' : 'Срабатывания по времени';
  }
  if (page === 'dashboard' || page === 'logs') {
    document.getElementById(page + '-log-charts').append(document.getElementById('log-charts'));
  }
  for (const item of headerItems) {
    item.hidden = !item.dataset.headerPage.split(' ').includes(page);
    if (item.hidden) {
      const openToggle = item.querySelector('[data-bs-toggle="dropdown"].show');
      if (openToggle) bootstrap.Dropdown.getInstance(openToggle)?.hide();
    }
  }
  if (settingsMenu.contains(current)) expandSettings(true);
  for (const link of pageLinks) {
    const active = link === current;
    const section = document.getElementById(link.hash.slice(1));
    section.hidden = !active;
    link.classList.toggle('active', active);
    if (active) {
      link.setAttribute('aria-current', 'page');
      document.title = link.textContent.trim() + ' · LogBan';
    } else {
      link.removeAttribute('aria-current');
    }
  }
}

window.addEventListener('hashchange', showPage);
showPage();
