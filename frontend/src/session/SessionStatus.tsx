import { sessionStatusCopy as copy } from '../copy/shell';
import { message as displayMessage } from '../shared/messages';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
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

/**
 * Focus hand-off after a user activates a session button that then disappears. The value is the
 * element focus was last moved to on the user's behalf (null right after activation). Only a
 * focused click records it, so programmatic, peer-tab and passive transitions never move focus.
 */
const focusIntent = new WeakMap<BrowserSession, HTMLElement | null>();

/** Moves focus on the user's behalf only if focus is still ours (body, or where we last put it). */
function handOff(session: BrowserSession, target: HTMLElement | null, settled: boolean) {
  if (!focusIntent.has(session)) return;
  const active = document.activeElement;
  const ours = active === null || active === document.body || active === focusIntent.get(session);
  if (!ours || !target) { focusIntent.delete(session); return; }
  target.focus();
  if (settled) focusIntent.delete(session); else focusIntent.set(session, target);
}

function recordActivation(session: BrowserSession, button: HTMLElement) {
  if (document.activeElement === button) focusIntent.set(session, null);
  else focusIntent.delete(session);
}

/**
 * A live paragraph mounted together with its text is not reliably announced (cold startup publishes
 * a state before the first render). Until the empty paragraph has been in the document for a paint,
 * its text is shown in a plain sibling instead, so the first screen looks the same.
 */
function useLiveReady() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const frame = typeof requestAnimationFrame === 'function'
      ? requestAnimationFrame(() => { timer = setTimeout(() => setReady(true), 0); }) : undefined;
    if (frame === undefined) timer = setTimeout(() => setReady(true), 0);
    return () => { if (frame !== undefined) cancelAnimationFrame(frame); clearTimeout(timer); };
  }, []);
  return ready;
}

/**
 * The connected state is quiet header chrome; every other state is a page notice.
 *
 * Each placement keeps one persistent `role="status"` paragraph for its whole lifetime, so the live
 * region exists, empty, before its text changes; text present at mount waits one paint (see
 * useLiveReady). Only one placement holds text for a given state (header: application-instance
 * change; page: checking, signing-out, required and unavailable), so mounting both never duplicates
 * an announcement. Only the active visible container carries `.session-notice`; an idle placement
 * drops its landmark/group semantics and becomes an out-of-flow `.sr-only` wrapper (never
 * display:none or aria-hidden) around its empty live paragraph. Buttons stay outside the status paragraph.
 */
export function SessionStatus({ session, placement = 'any' }: { session: BrowserSession; placement?: 'header' | 'page' | 'any' }) {
  const [state, setState] = useState(session.snapshot);
  const notice = useRef<HTMLElement>(null);
  const signOut = useRef<HTMLButtonElement>(null);
  const ready = useLiveReady();
  useLayoutEffect(() => {
    const unsubscribe = session.subscribe(setState);
    setState(session.snapshot());
    return unsubscribe;
  }, [session]);
  const connected = state.status === 'authenticated';
  const pageActive = state.status !== 'public' && !connected;
  const transient = state.status === 'checking' || state.status === 'signing-out';
  useLayoutEffect(() => {
    if (placement !== 'page' && connected) handOff(session, signOut.current, true);
    else if (placement !== 'header' && !connected) {
      if (pageActive) handOff(session, notice.current, !transient);
      else handOff(session, null, true);
    }
  }, [session, placement, state]);

  const headerText = connected && state.serverChanged ? copy.applicationInstanceChanged : '';
  const header = placement !== 'page' && <div class={connected ? 'session-notice is-connected' : 'sr-only'}
    {...(connected ? { role: 'group', 'aria-label': copy.localSession } : {})}>
    {connected && <p>{copy.localSessionConnected}</p>}
    {!ready && headerText && <p>{headerText}</p>}
    <p role="status" data-session-announcement="header" class={ready && headerText ? undefined : 'sr-only'}>
      {ready ? headerText : ''}
    </p>
    {connected && <button type="button" ref={signOut} onClick={event => {
      recordActivation(session, event.currentTarget);
      void session.logout();
    }}>{copy.signOut}</button>}
  </div>;
  if (placement === 'header') return header;

  const text = state.status === 'checking' ? copy.checkingLocalSession
    : state.status === 'signing-out' ? copy.signingOut : explanation(state);
  const content = pageActive && <>{text}{'referenceId' in state && state.referenceId
    && <>{displayMessage(copy.reference, { reference: <code>{state.referenceId}</code> })}</>}</>;
  const canCheck = (state.status === 'required' || state.status === 'unavailable')
    && (state.status !== 'unavailable' || !['removal-failed', 'incompatible'].includes(state.reason));
  const page = <aside ref={notice} class={pageActive ? 'session-notice notice' : 'sr-only'}
    {...(pageActive ? { 'aria-label': copy.localSession, tabIndex: -1 } : { role: 'none' })}>
    {!ready && pageActive && <p>{content}</p>}
    <p role="status" data-session-announcement="page" class={ready ? undefined : 'sr-only'}>{ready && content}</p>
    {canCheck && <button type="button" onClick={event => {
      recordActivation(session, event.currentTarget);
      void session.refresh();
    }}>{copy.checkSession}</button>}
  </aside>;
  return placement === 'page' ? page : <>{header}{page}</>;
}
