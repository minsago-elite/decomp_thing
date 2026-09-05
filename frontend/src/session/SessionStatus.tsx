import { useLayoutEffect, useState } from 'preact/hooks';
import type { BrowserSession, SessionState } from './session';

function explanation(state: SessionState): string {
  if (state.status === 'required') {
    switch (state.reason) {
      case 'session-changed': return 'Another tab reported a session change. Private data was cleared. Check the session to reconnect.';
      case 'signed-out': return 'You signed out of this browser. Public pages remain available.';
      case 'expired': return 'Your local session expired. Open a fresh sign-in link from the application terminal.';
      case 'bootstrap-expired': return 'This sign-in link expired. Open a fresh link from the application terminal.';
      case 'bootstrap-required': return 'This sign-in link is no longer available. Open a fresh link from the application terminal.';
      case 'invalid-link': return 'This sign-in link is incomplete or invalid. Open a fresh link from the application terminal.';
      case 'missing': return 'To access private work, open the sign-in link printed by your local application.';
    }
  }
  if (state.status === 'unavailable') {
    switch (state.reason) {
      case 'logout-unconfirmed': return 'Sign-out could not be confirmed. Check the session before trying again.';
      case 'configuration': return 'The browser address and application configuration do not match. Open the configured local address.';
      case 'removal-failed': return 'The sign-in link could not be cleared from this tab. Close it and open a fresh local link in a supported browser.';
      case 'connection': return 'The local session could not be checked. Confirm the application is running, then check the session.';
    }
  }
  return '';
}

export function SessionStatus({ session }: { session: BrowserSession }) {
  const [state, setState] = useState(session.snapshot);
  useLayoutEffect(() => {
    const unsubscribe = session.subscribe(setState);
    setState(session.snapshot());
    return unsubscribe;
  }, [session]);
  if (state.status === 'public') return null;
  if (state.status === 'checking' || state.status === 'signing-out') {
    return <aside class="session-notice notice" role="status">
      <p>{state.status === 'checking' ? 'Checking local session…' : 'Signing out…'}</p>
    </aside>;
  }
  if (state.status === 'authenticated') {
    return <aside class="session-notice notice" aria-label="Local session">
      <p>Local session connected.</p>
      <button type="button" onClick={() => { void session.logout(); }}>Sign out</button>
    </aside>;
  }
  const removalFailed = state.status === 'unavailable' && state.reason === 'removal-failed';
  return <aside class="session-notice notice" aria-label="Local session" role="status">
    <p>{explanation(state)}</p>
    {!removalFailed && <button type="button" onClick={() => { void session.refresh(); }}>Check session</button>}
  </aside>;
}
