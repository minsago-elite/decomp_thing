import { useEffect, useState } from 'preact/hooks';

/** Browser hints control observation traffic, never the lifetime of server work. */
export function useBrowserAvailability() {
  const read = () => ({ online: navigator.onLine !== false, visible: document.visibilityState !== 'hidden' });
  const [availability, setAvailability] = useState(read);
  useEffect(() => {
    const update = () => setAvailability(read());
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
