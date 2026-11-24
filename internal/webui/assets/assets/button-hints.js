(() => {
  const hint = document.createElement('div');
  hint.id = 'button-hint';
  hint.setAttribute('role', 'tooltip');
  hint.hidden = true;
  document.body.append(hint);
  let active;

  function hide() {
    if (!active) return;
    const ids = (active.getAttribute('aria-describedby') || '').split(' ').filter(id => id && id !== hint.id);
    if (ids.length) active.setAttribute('aria-describedby', ids.join(' '));
    else active.removeAttribute('aria-describedby');
    active = null;
    hint.hidden = true;
  }

  function show(button) {
    if (!button || button === active) return;
    hide();
    const label = button.getAttribute('aria-label') || button.textContent.trim();
    const messages = {
      'Назад': 'Перейти на предыдущую страницу',
      'Вперёд': 'Перейти на следующую страницу',
      'Отмена': 'Закрыть форму без сохранения',
      'Меню пользователя': 'Открыть меню пользователя'
    };
    hint.textContent = button.dataset.ruleId ? 'Открыть правило ' + button.dataset.ruleId :
      messages[label] || label;
    if (!hint.textContent) return;
    active = button;
    button.setAttribute('aria-describedby', [button.getAttribute('aria-describedby'), hint.id].filter(Boolean).join(' '));
    hint.hidden = false;
    hint.style.left = '0';
    const rect = button.getBoundingClientRect();
    const width = hint.offsetWidth, height = hint.offsetHeight;
    hint.style.left = Math.max(4, Math.min(innerWidth - width - 4, rect.left + (rect.width - width) / 2)) + 'px';
    hint.style.top = (rect.top >= height + 8 ? rect.top - height - 6 : rect.bottom + 6) + 'px';
  }

  document.addEventListener('pointerover', event => {
    if (event.pointerType !== 'touch') show(event.target.closest('button'));
  });
  document.addEventListener('pointerout', event => {
    if (active && active.contains(event.target) && !active.contains(event.relatedTarget)) hide();
  });
  document.addEventListener('focusin', event => show(event.target.closest('button')));
  document.addEventListener('focusout', hide);
  document.addEventListener('click', hide, true);
  document.addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
  document.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
  window.addEventListener('hashchange', hide);
  new MutationObserver(() => { if (active && !active.getClientRects().length) hide(); })
    .observe(document.body, {childList: true, subtree: true});
})();
