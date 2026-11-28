import { setTimeout as delay } from 'node:timers/promises';
import { render } from 'preact';
import { useEffect } from 'preact/hooks';
import { expect, it, vi } from 'vitest';

it('runs after-paint effects outside the testing-library act wrapper', async () => {
  const container = document.body.appendChild(document.createElement('div'));
  let finish!: () => void;
  const painted = new Promise<void>(resolve => { finish = resolve; });
  const effect = vi.fn(finish);
  function Probe() {
    useEffect(effect, []);
    return null;
  }
  try {
    render(<Probe />, container);
    await painted;
    expect(effect).toHaveBeenCalledOnce();
  } finally {
    render(null, container);
    container.remove();
  }
});

it('does not use removed browser globals for already-unmounted after-paint work', async () => {
  const container = document.body.appendChild(document.createElement('div'));
  const effect = vi.fn();
  function Probe() {
    useEffect(effect, []);
    return null;
  }
  try {
    render(<Probe />, container);
    render(null, container);
    // Model Vitest removing browser globals while a Node fallback timer survives.
    // An uncaught scheduler error must fail the run, not be filtered or ignored.
    vi.stubGlobal('cancelAnimationFrame', undefined);
    await delay(150);
    expect(effect).not.toHaveBeenCalled();
  } finally {
    render(null, container);
    container.remove();
  }
});
