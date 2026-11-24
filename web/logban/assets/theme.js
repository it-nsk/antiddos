const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');

function applySystemTheme() {
  document.documentElement.dataset.bsTheme = systemTheme.matches ? 'dark' : 'light';
}

applySystemTheme();
systemTheme.addEventListener('change', applySystemTheme);
