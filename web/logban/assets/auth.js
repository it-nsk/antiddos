let session;
async function checkSession() {
  const loginPage = document.body.dataset.page === 'login';
  try {
    session = await requestAPI('session');
    if (loginPage) return location.replace('/');
    await loadPanel();
    document.dispatchEvent(new CustomEvent('logban-session', {detail: {role:session.user.role}}));
    for (const node of document.querySelectorAll('[data-session-login]')) node.textContent = session.user.username;
    document.body.hidden = false;
  } catch (error) {
    if (error.status === 401) {
      if (!loginPage) location.replace('/login.html');
    } else {
      document.body.hidden = false;
      showBackendStatus(error.message);
    }
  }
}
if (document.body.dataset.page === 'login') {
  const form = document.getElementById('login-form');
  const password = document.getElementById('loginPassword');
  form.addEventListener('input', () => password.setCustomValidity(''));
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('[type=submit]');
    button.disabled = true;
    try {
      session = await requestAPI('login', 'POST', {username:form.elements.username.value.trim(),password:password.value,remember:document.getElementById('flexCheckDefault').checked});
      location.replace('/');
    } catch(error) {
      password.setCustomValidity(error.status === 401 ? 'Неверное имя пользователя или пароль.' : error.message);
      password.reportValidity();
    } finally { button.disabled = false; }
  });
} else {
  document.getElementById('logout').addEventListener('click', async () => {
    try { await requestAPI('logout', 'POST', {}); location.replace('/login.html'); }
    catch(error) { showBackendStatus(error.message); }
  });
}
checkSession();
window.addEventListener('pageshow', event => { if(event.persisted) location.reload(); });
