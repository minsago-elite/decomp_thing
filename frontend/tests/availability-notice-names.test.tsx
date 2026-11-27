import { render, screen, within } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import Home from '../src/routes/Home';
import Runtime from '../src/routes/Runtime';
import { createBrowserSession } from '../src/session/session';

function absentSession() {
  const gateway = { bootstrap: vi.fn(), exchange: vi.fn(), logout: vi.fn() };
  return { gateway, session: createBrowserSession(gateway, '/') };
}

it('names the unauthenticated Home availability notice as a region from its heading', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch');
  const { gateway, session } = absentSession();
  try {
    await session.initialize({ kind: 'absent' });
    expect(session.snapshot()?.status).not.toBe('authenticated');
    const probesBefore = gateway.bootstrap.mock.calls.length;
    const { container } = render(<Home session={session} />);
    const region = screen.getByRole('region', { name: 'The workbench shell is ready' });
    expect(region.tagName).toBe('SECTION');
    expect(region.getAttribute('aria-labelledby')).toBe('availability-title');
    expect(within(region).getByRole('heading', { level: 2, name: 'The workbench shell is ready' })).toBeTruthy();
    expect(region.querySelectorAll('p')).toHaveLength(2);
    expect(within(region).queryAllByRole('button')).toHaveLength(0);
    expect(within(region).queryAllByRole('link')).toHaveLength(0);
    expect(container.querySelector('div[aria-labelledby="availability-title"]')).toBeNull();
    expect(gateway.bootstrap).toHaveBeenCalledTimes(probesBefore);
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  } finally { session.dispose(); fetchSpy.mockRestore(); }
});

it('names the unauthenticated Runtime availability notice as a region from its heading', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch');
  const { gateway, session } = absentSession();
  try {
    await session.initialize({ kind: 'absent' });
    expect(session.snapshot()?.status).not.toBe('authenticated');
    const probesBefore = gateway.bootstrap.mock.calls.length;
    const { container } = render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: 'ui' }} session={session} />);
    const region = screen.getByRole('region', { name: 'Runtime information is not connected' });
    expect(region.tagName).toBe('SECTION');
    expect(region.getAttribute('aria-labelledby')).toBe('runtime-availability-title');
    expect(within(region).getByRole('heading', { level: 2, name: 'Runtime information is not connected' })).toBeTruthy();
    expect(region.querySelectorAll('p')).toHaveLength(1);
    expect(within(region).queryAllByRole('button')).toHaveLength(0);
    expect(within(region).queryAllByRole('link')).toHaveLength(0);
    expect(container.querySelector('div[aria-labelledby="runtime-availability-title"]')).toBeNull();
    expect(gateway.bootstrap).toHaveBeenCalledTimes(probesBefore);
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  } finally { session.dispose(); fetchSpy.mockRestore(); }
});

it('negative control: a generic div with aria-labelledby is not exposed as a named region', () => {
  render(<div class="notice" aria-labelledby="neg-title"><h2 id="neg-title">Negative control</h2></div>);
  expect(screen.queryByRole('region', { name: 'Negative control' })).toBeNull();
});
