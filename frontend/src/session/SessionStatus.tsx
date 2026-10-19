import { sessionStatusCopy as copy } from '../copy/shell';
import { message as displayMessage } from '../shared/messages';
import { useLayoutEffect, useState } from 'preact/hooks';
import type { BrowserSession, SessionState } from './session';

function explanation(state: SessionState): string {
  if (state.status === 'required') {
    switch (state.reason) {
      case 'session-changed': return copy.anotherTabReportedASessionChangePrivateDataWasCleared;
      case 'signed-out': return copy.youSignedOutOfThisBrowserPublicPagesRemainAvailable;
      case 'expired': return copy.yourLocalSessionExpiredOpenAFreshSignInLink;
      case 'bootstrap-expired': return copy.thisSignInLinkExpiredOpenAFreshLinkFrom;
      case 'bootstrap-required': return copy.thisSignInLinkIsNoLongerAvailableOpenA;
      case 'invalid-link': return copy.thisSignInLinkIsIncompleteOrInvalidOpenA;
      case 'missing': return copy.toAccessPrivateWorkOpenTheSignInLinkPrinted;
    }
  }
  if (state.status === 'unavailable') {
    switch (state.reason) {
      case 'logout-unconfirmed': return copy.signOutCouldNotBeConfirmedCheckTheSessionBefore;
      case 'configuration': return copy.theBrowserAddressAndApplicationConfigurationDoNotMatchOpen;
      case 'removal-failed': return copy.theSignInLinkCouldNotBeClearedFromThis;
      case 'connection': return copy.theLocalSessionCouldNotBeCheckedConfirmTheApplication;
      case 'incompatible': return copy.thisPageAndTheLocalServerUseIncompatibleAPIFormats;
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
      <p>{state.status === 'checking' ? copy.checkingLocalSession : copy.signingOut}</p>
    </aside>;
  }
  if (state.status === 'authenticated') {
    return <aside class="session-notice notice" aria-label={copy.localSession}>
      <p>{copy.localSessionConnected}</p>
      <button type="button" onClick={() => { void session.logout(); }}>{copy.signOut}</button>
    </aside>;
  }
  const canCheck = state.status !== 'unavailable' || !['removal-failed', 'incompatible'].includes(state.reason);
  return <aside class="session-notice notice" aria-label={copy.localSession} role="status">
    <p>{explanation(state)}{'referenceId' in state && state.referenceId && <>{displayMessage(copy.reference, { reference: <code>{state.referenceId}</code> })}</>}</p>
    {canCheck && <button type="button" onClick={() => { void session.refresh(); }}>{copy.checkSession}</button>}
  </aside>;
}
