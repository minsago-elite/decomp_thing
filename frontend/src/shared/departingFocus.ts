import { useEffect, useRef } from 'preact/hooks';
import type { RefObject } from 'preact';

/**
 * The control a deletion transition may remove (#512). Browsers that blur a focused control when it becomes
 * disabled (Chrome while a read is outstanding) leave the document focused, so the control that the page
 * itself disabled is remembered until the user moves focus anywhere else. Focus the user moved elsewhere,
 * including deliberately to the document, is never captured.
 */
export function useDepartingFocus(root: RefObject<Element>) {
  // The last control focused inside `root`, kept only while losing focus can be explained by the page disabling it.
  const disabledFrom = useRef<Element | null>(null);
  useEffect(() => {
    const inside = (target: EventTarget | null): target is Element => target instanceof Element && (root.current?.contains(target) ?? false);
    const into = (event: FocusEvent) => { disabledFrom.current = inside(event.target) ? event.target : null; };
    // A browser may or may not report the blur of a control it disabled; a blur of an enabled control is the user's.
    const out = (event: FocusEvent) => {
      if (!(inside(event.target) && event.target.matches(':disabled'))) disabledFrom.current = null;
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
    return from?.isConnected && from.matches(':disabled') ? from : null;
  };
}

/** Lands on the surviving notice only when the transition removed the departing control and focus is still unowned. */
export function focusSurvivingNotice(from: Element | null, notice: HTMLElement | null) {
  if (!from || from === document.body || from.isConnected) return;
  const active = document.activeElement;
  if (active && active !== document.body) return;
  notice?.focus();
}
