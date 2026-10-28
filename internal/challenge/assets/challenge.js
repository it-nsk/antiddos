const form = document.querySelector('#challenge-form');
const error = document.querySelector('#challenge-error');
const submit = form?.querySelector('button[type="submit"]');
let submitting = false;

document.addEventListener('submit', async (event) => {
  if (!form || event.target !== form) return;
  event.preventDefault();
  if (submitting || !form.reportValidity()) return;
  submitting = true;
  if (submit) submit.disabled = true;
  if (error) error.textContent = '';
  try {
    const body = new URLSearchParams(new FormData(form));
    const response = await fetch(form.action, {
      method: 'POST',
      body,
      credentials: 'same-origin',
      redirect: 'follow',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    const destination = new URL(response.url);
    if (!response.redirected || destination.origin !== window.location.origin) throw new Error('Verification failed. Reload the challenge and try again.');
    window.location.assign(destination.href);
  } catch (err) {
    if (error) error.textContent = err instanceof Error ? err.message : 'Verification failed. Reload the challenge and try again.';
    submitting = false;
    if (submit) submit.disabled = false;
  }
}, true);
