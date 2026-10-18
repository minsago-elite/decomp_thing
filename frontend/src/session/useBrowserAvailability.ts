import { useEffect, useState } from 'preact/hooks';

/** Browser hints control observation traffic, never the lifetime of server work. */
export function useBrowserAvailability() {
  const read = () => ({ online: navigator.onLine !== false, visible: document.visibilityState !== 'hidden' });
  const [availability, setAvailability] = useState(() => {
    const initial = read();
    return { ...initial, hasBeenOffline: !initial.online };
  });
  useEffect(() => {
    const update = () => {
      const next = read();
      // Preserve a brief offline hint even when reconnect renders are coalesced.
      setAvailability(current => ({ ...next, hasBeenOffline: current.hasBeenOffline || !next.online }));
    };
    window.addEventListener('online', update);
    window.addEventListener('offline', update);
    document.addEventListener('visibilitychange', update);
    update();
    return () => {
      window.removeEventListener('online', update);
      window.removeEventListener('offline', update);
      document.removeEventListener('visibilitychange', update);
    };
  }, []);
  return availability;
}
