import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { ViewBoundary } from '../src/shared/ViewBoundary';
import { createAssetRecovery } from '../src/app/assetRecovery';

const fixtureMarker = 'DECOMP_TEST_ONLY_SENTINEL';

describe('public workbench shell', () => {
  it('exposes navigation and truthful availability without contacting APIs', () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    render(<App />);
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeTruthy();
    expect(screen.getByRole('main')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Skip to content' }).getAttribute('href')).toBe('#main');
    expect(screen.getByRole('heading', { level: 1, name: 'Your work, with its evidence' })).toBeTruthy();
    expect(screen.getByText(/does not read jobs or start workflows/)).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('loads the split runtime route and returns with browser history', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(window.location.pathname).toBe('/runtime');
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('main')));
    window.history.back();
    expect(await screen.findByRole('heading', { level: 1, name: 'Your work, with its evidence' })).toBeTruthy();
    expect(window.location.pathname).toBe('/');
  });

  it('preserves the deployment prefix for direct routes and navigation', async () => {
    window.history.replaceState(null, '', '/tools/decomp/runtime?from=bookmark');
    render(<App basePath="/tools/decomp" />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Workspace' }).getAttribute('href')).toBe('/tools/decomp/');
    expect(window.location.search).toBe('?from=bookmark');
    fireEvent.click(screen.getByRole('link', { name: 'Workspace' }));
    expect(await screen.findByRole('heading', { name: 'Your work, with its evidence' })).toBeTruthy();
    expect(window.location.pathname).toBe('/tools/decomp/');
  });

  it('keeps a version notice in view when focusing the next route', async () => {
    const recovery = createAssetRecovery();
    recovery.reportFailure();
    const focus = vi.spyOn(HTMLElement.prototype, 'focus');
    try {
      render(<App recovery={recovery} />);
      fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
      expect(await screen.findByRole('heading', { name: 'Runtime status' })).toBeTruthy();
      expect(focus).toHaveBeenCalledWith({ preventScroll: true });
      expect(screen.getByRole('heading', { name: 'The application may have updated' })).toBeTruthy();
    } finally {
      focus.mockRestore();
    }
  });

  it('gives unknown routes a clear return destination', () => {
    window.history.replaceState(null, '', '/missing.view');
    render(<App />);
    expect(screen.getByRole('heading', { name: 'This page could not be found' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Return to the workspace' }).getAttribute('href')).toBe('/');
  });
});

describe('view errors', () => {
  it('contains private exception details and retries only the view', async () => {
    let fails = true;
    function FailingView() {
      if (fails) throw new Error(fixtureMarker);
      return <p>View restored</p>;
    }
    render(<ViewBoundary><FailingView /></ViewBoundary>);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByText(fixtureMarker)).toBeNull();
    fails = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('View restored')).toBeTruthy();
  });
});
