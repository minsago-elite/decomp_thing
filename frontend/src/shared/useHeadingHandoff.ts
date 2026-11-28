import { useLayoutEffect, useRef } from 'preact/hooks';

/**
 * A pending heading handoff after an entry or a chosen page. The reader's own focus choice while the read is
 * outstanding (moving to another control, or blurring one that stays on the page) withdraws the handoff;
 * a control removed by the transition does not.
 */
export function useHeadingHandoff(heading: { current: HTMLHeadingElement | null }, initial: boolean) {
  const armed = useRef(initial);
  useLayoutEffect(() => {
    const moved = (event: FocusEvent) => { if (armed.current && event.target !== heading.current) armed.current = false; };
    const left = (event: FocusEvent) => {
      const target = event.target;
      if (!armed.current || event.relatedTarget !== null || !(target instanceof Node)) return;
      queueMicrotask(() => {
        if (target.isConnected && !(target instanceof Element && target.matches(':disabled')) &&
          (document.activeElement === null || document.activeElement === document.body)) armed.current = false;
      });
    };
    const cancel = () => { armed.current = false; };
    window.addEventListener('popstate', cancel);
    document.addEventListener('focusin', moved, true);
    document.addEventListener('focusout', left, true);
    return () => {
      window.removeEventListener('popstate', cancel);
      document.removeEventListener('focusin', moved, true);
      document.removeEventListener('focusout', left, true);
    };
  }, [heading]);
  return armed;
}
