import { sessionStatusCopy as copy } from '../copy/shell';
import { message as displayMessage } from '../shared/messages';
import { useLayoutEffect, useRef, useState } from 'preact/hooks';
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

/** Sessions whose Sign out action was activated from a still-focused button; consumed by the page notice. */
const signOutFocus = new WeakSet<BrowserSession>();

/**
 * The connected state is quiet header chrome; every other state is a page notice.
 *
 * Each placement keeps one persistent `role="status"` paragraph for its whole lifetime, so the live
 * region exists before its text changes. Only one placement holds text for a given state (header:
 * application-instance change; page: checking, signing-out, required and unavailable), so mounting
 * both never duplicates an announcement. Only the active visible container carries `.session-notice`;
 * an idle placement drops its landmark/group semantics and becomes an out-of-flow `.sr-only` wrapper
 * (never display:none or aria-hidden) around its empty live paragraph. Buttons stay outside the status paragraph.
 */
export function SessionStatus({ session, placement = 'any' }: { session: BrowserSession; placement?: 'header' | 'page' | 'any' }) {
  const [state, setState] = useState(session.snapshot);
  const notice = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    const unsubscribe = session.subscribe(setState);
    setState(session.snapshot());
    return unsubscribe;
  }, [session]);
  const connected = state.status === 'authenticated';
  const pageActive = state.status !== 'public' && !connected;
  useLayoutEffect(() => {
    if (placement === 'header' || connected || !signOutFocus.has(session)) return;
    signOutFocus.delete(session);
    // The activated Sign out button is gone; move focus to the outcome only if nothing else took it.
    const active = document.activeElement;
    if (pageActive && (active === null || active === document.body)) notice.current?.focus();
  }, [session, placement, connected, pageActive]);

  const header = placement !== 'page' && <div class={connected ? 'session-notice is-connected' : 'sr-only'}
    {...(connected ? { role: 'group', 'aria-label': copy.localSession } : {})}>
    {connected && <p>{copy.localSessionConnected}</p>}
    <p role="status" data-session-announcement="header" class={connected && state.serverChanged ? undefined : 'sr-only'}>
      {connected && state.serverChanged ? copy.applicationInstanceChanged : ''}
    </p>
    {connected && <button type="button" onClick={event => {
      if (document.activeElement === event.currentTarget) signOutFocus.add(session);
      void session.logout();
    }}>{copy.signOut}</button>}
  </div>;
  if (placement === 'header') return header;

  const text = state.status === 'checking' ? copy.checkingLocalSession
    : state.status === 'signing-out' ? copy.signingOut : explanation(state);
  const canCheck = (state.status === 'required' || state.status === 'unavailable')
    && (state.status !== 'unavailable' || !['removal-failed', 'incompatible'].includes(state.reason));
  const page = <aside ref={notice} class={pageActive ? 'session-notice notice' : 'sr-only'}
    {...(pageActive ? { 'aria-label': copy.localSession, tabIndex: -1 } : { role: 'none' })}>
    <p role="status" data-session-announcement="page">
      {pageActive && text}{pageActive && 'referenceId' in state && state.referenceId
        && <>{displayMessage(copy.reference, { reference: <code>{state.referenceId}</code> })}</>}
    </p>
    {canCheck && <button type="button" onClick={() => { void session.refresh(); }}>{copy.checkSession}</button>}
  </aside>;
  return placement === 'page' ? page : <>{header}{page}</>;
}
