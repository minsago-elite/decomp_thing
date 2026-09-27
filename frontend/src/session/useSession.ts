import { useLayoutEffect, useState } from 'preact/hooks';
import type { BrowserSession } from './session';

export function useSession(session: BrowserSession | null) {
  const [state, setState] = useState(() => session?.snapshot());
  useLayoutEffect(() => {
    setState(session?.snapshot());
    return session?.subscribe(setState);
  }, [session]);
  return state;
}
