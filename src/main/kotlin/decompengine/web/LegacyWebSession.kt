package decompengine.web

/** Public login contains no job data; credentials are consumed only from the local handoff. */
internal fun renderLegacyLogin(): String = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local session · decomp_engine</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><main class="shell"><h1>Open a local session</h1>
<p id="session-message" role="status">Open the session link printed by the running application. Restart the application to obtain a new link if it has expired.</p>
<a href="/">Continue with an existing session</a></main><script>
(() => {
  const fragment = location.hash;
  history.replaceState(null, '', location.pathname + location.search);
  const token = /^#bootstrap=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1];
  if (!token) return;
  const message = document.querySelector('#session-message');
  message.textContent = 'Opening local session…';
  fetch('/api/v1/session', { method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify({ token }) })
    .then(response => {
      if (!response.ok) throw new Error('Session unavailable');
      location.replace('/');
    }).catch(() => { message.textContent = 'This session link is unavailable or expired. Open a new link from the running application.'; });
})();
</script></body></html>"""

/** CSRF stays in the document closure. A failed mutation is never automatically retried. */
internal val LEGACY_SESSION_SCRIPT = """
(() => {
  let csrf;
  let pending = false;
  const message = document.createElement('p');
  message.setAttribute('role', 'status');
  message.className = 'shell';
  document.querySelector('.topbar')?.after(message);
  async function credentials() {
    if (csrf) return csrf;
    const response = await fetch('/api/v1/session/csrf', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
    if (!response.ok) throw new Error('Session unavailable');
    const body = await response.json();
    csrf = body.data.csrfToken;
    return csrf;
  }
  function failed() {
    csrf = undefined;
    message.textContent = 'The result could not be confirmed. Your session may have expired. Open a new local session link and check job status before trying again.';
  }
  document.querySelectorAll('form[method="post"]').forEach(form => form.addEventListener('submit', async event => {
    event.preventDefault();
    if (pending) return;
    pending = true;
    const buttons = Array.from(form.querySelectorAll('button'));
    buttons.forEach(button => { button.disabled = true; });
    try {
      const headers = { 'X-CSRF-Token': await credentials(), 'Accept': 'text/html' };
      const multipart = form.enctype === 'multipart/form-data';
      if (!multipart) headers['Content-Type'] = 'application/json';
      const response = await fetch(form.action, { method: 'POST', credentials: 'same-origin', headers,
        body: multipart ? new FormData(form) : '{}' });
      if (!response.ok || !response.redirected || new URL(response.url).origin !== location.origin) throw new Error('Request unavailable');
      location.assign(response.url);
    } catch (_) { failed(); }
    finally { pending = false; buttons.forEach(button => { button.disabled = false; }); }
  }));
  const logout = document.createElement('button');
  logout.type = 'button';
  logout.className = 'button secondary';
  logout.textContent = 'End session';
  document.querySelector('.topbar')?.append(logout);
  logout.addEventListener('click', async () => {
    if (pending) return;
    pending = true;
    logout.disabled = true;
    try {
      const response = await fetch('/api/v1/session', { method: 'DELETE', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': await credentials() } });
      if (response.status !== 204) throw new Error('Session unavailable');
      csrf = undefined;
      location.replace('/login');
    } catch (_) { failed(); }
    finally { pending = false; logout.disabled = false; }
  });
})();
"""
