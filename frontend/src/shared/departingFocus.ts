import { useLayoutEffect, useRef } from 'preact/hooks';
import type { RefObject } from 'preact';

// The control whose own operation is synchronously re-rendering the view (#512). Chrome reports the removal of a focused
// control as an ordinary blur of a still-connected, enabled element, so only that operation's synchronous transition may
// keep it as the departing control; the claim lapses before any later user action can be mistaken for it.
let transitionHolder: Element | null = null;

/** Keeps `control` as the departing control while its own operation's synchronous view transition replaces it. */
export function holdFocusThroughTransition(control: Element | null) {
  if (!(control instanceof Element)) return;
  transitionHolder = control;
  setTimeout(() => { if (transitionHolder === control) transitionHolder = null; }, 0);
}

/**
 * The control a deletion transition may remove (#512). Browsers that blur a focused control when it becomes
 * disabled (Chrome while a read is outstanding) leave the document focused, so the control that the page
 * itself disabled or removed is remembered until the user moves focus anywhere else. Focus the user moved elsewhere,
 * including deliberately to the document, is never captured.
 */
export function useDepartingFocus(root: RefObject<Element>) {
  // The last control focused inside `root`, kept only while losing focus can be explained by the page disabling it.
  const disabledFrom = useRef<Element | null>(null);
  useLayoutEffect(() => {
    const inside = (target: EventTarget | null): target is Element => target instanceof Element && (root.current?.contains(target) ?? false);
    const into = (event: FocusEvent) => { disabledFrom.current = inside(event.target) ? event.target : null; };
    // A browser may or may not report the blur of a control it disabled; a blur of an enabled control is the user's.
    // A control the page removes (a panel clearing stale actions) departs without the user moving focus either.
    const out = (event: FocusEvent) => {
      const target = event.target;
      const departed = target === disabledFrom.current && target instanceof Element && !target.isConnected;
      const held = target === disabledFrom.current && target === transitionHolder && (event.relatedTarget === null);
      if (!departed && !held && !(inside(target) && target.matches(':disabled'))) disabledFrom.current = null;
    };
    document.addEventListener('focusin', into, true);
    document.addEventListener('focusout', out, true);
    return () => { document.removeEventListener('focusin', into, true); document.removeEventListener('focusout', out, true); };
  }, [root]);
  /** The element focus departs from now: the focused element, or the control the page disabled under it. */
  return () => {
    const active = document.activeElement;
    if (active && active !== document.body) return active;
    const from = disabledFrom.current;
    return from && (!from.isConnected || from.matches(':disabled')) ? from : null;
  };
}

/** Lands on the surviving notice only when the transition removed the departing control and focus is still unowned. */
export function focusSurvivingNotice(from: Element | null, notice: HTMLElement | null) {
  if (!from || from === document.body || from.isConnected) return;
  const active = document.activeElement;
  if (active && active !== document.body) return;
  notice?.focus();
}

/**
 * Keyboard recovery once a panel's own read or command settles. `from` is the departing control captured before the
 * settling render. Focus still owned anywhere, including by a user who moved it, is left alone. A control the page only
 * disabled gets focus back once it is enabled again; one the settlement removed hands focus to `fallback`, a persistent
 * destination that carries the outcome. A later route deletion then departs from that destination like any other control.
 */
export function restoreSettledFocus(from: Element | null, fallback: HTMLElement | null) {
  if (!(from instanceof HTMLElement)) return;
  const active = document.activeElement;
  if (active && active !== document.body) return;
  if (from.isConnected) { if (!from.matches(':disabled')) from.focus(); return; }
  fallback?.focus();
}
