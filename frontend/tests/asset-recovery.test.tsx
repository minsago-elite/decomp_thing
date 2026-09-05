import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { createAssetRecovery, observeAssetFailures } from '../src/app/assetRecovery';
import { UNKNOWN_BUILD } from '../src/app/buildIdentity';
import { AssetRecoveryNotice } from '../src/shared/AssetRecoveryNotice';
import { lazyRoute } from '../src/shared/LazyRoute';
import { ViewBoundary } from '../src/shared/ViewBoundary';

const uiBuildId = 'a'.repeat(64);

function reportPreloadFailure() {
  const event = new Event('vite:preloadError', { cancelable: true });
  Object.defineProperty(event, 'payload', { value: new Error('DECOMP_TEST_ONLY_SENTINEL') });
  fireEvent(window, event);
}

describe('asset version recovery', () => {
  it('coalesces failures and waits for one explicit reload without making requests', async () => {
    const reload = vi.fn();
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    render(<App identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
    reportPreloadFailure();
    reportPreloadFailure();
    expect(await screen.findByRole('heading', { name: 'The application may have updated' })).toBeTruthy();
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(screen.getByText(uiBuildId)).toBeTruthy();
    expect(screen.queryByText('DECOMP_TEST_ONLY_SENTINEL')).toBeNull();
    expect(reload).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    const button = screen.getByRole<HTMLButtonElement>('button', { name: 'Reload application' });
    fireEvent.click(button);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(button.disabled).toBe(true);
    reportPreloadFailure();
    fireEvent.click(button);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('catches a rejected lazy import and renders a stable recovery view', async () => {
    const recovery = createAssetRecovery();
    const reload = vi.fn();
    const load = vi.fn().mockRejectedValue(new TypeError('DECOMP_TEST_ONLY_SENTINEL'));
    const FailedRoute = lazyRoute(load, recovery);
    const view = render(
      <>
        <AssetRecoveryNotice recovery={recovery} identity={UNKNOWN_BUILD} reload={reload} />
        <ViewBoundary><FailedRoute /></ViewBoundary>
      </>,
    );
    expect(await screen.findByRole('heading', { name: 'This view is unavailable' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reload application' })).toBeTruthy();
    view.rerender(
      <>
        <AssetRecoveryNotice recovery={recovery} identity={UNKNOWN_BUILD} reload={reload} />
        <ViewBoundary><FailedRoute /></ViewBoundary>
      </>,
    );
    expect(load).toHaveBeenCalledTimes(1);
    expect(reload).not.toHaveBeenCalled();
    expect(screen.queryByText('DECOMP_TEST_ONLY_SENTINEL')).toBeNull();
  });

  it('handles a suppressed preload rejection without repeatedly suspending', async () => {
    const recovery = createAssetRecovery();
    const load = vi.fn().mockResolvedValue(undefined);
    const FailedRoute = lazyRoute(load, recovery);
    render(<ViewBoundary><FailedRoute /></ViewBoundary>);
    expect(await screen.findByRole('heading', { name: 'This view is unavailable' })).toBeTruthy();
    expect(recovery.snapshot()).toBe('unavailable');
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('offers browser recovery if navigation is unavailable, without trying again', async () => {
    const recovery = createAssetRecovery();
    recovery.reportFailure();
    const reload = vi.fn(() => { throw new Error('Navigation unavailable'); });
    render(<AssetRecoveryNotice recovery={recovery} identity={UNKNOWN_BUILD} reload={reload} />);
    fireEvent.click(screen.getByRole('button', { name: 'Reload application' }));
    expect(await screen.findByText('Use your browser’s Reload action to request the current version.')).toBeTruthy();
    expect(screen.queryByRole('button')).toBeNull();
    recovery.reportFailure();
    recovery.requestReload(reload);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('removes the window listener when the shell unmounts', async () => {
    const recovery = createAssetRecovery();
    const view = render(<App recovery={recovery} />);
    view.unmount();
    reportPreloadFailure();
    await waitFor(() => expect(recovery.snapshot()).toBe('ready'));
  });

  it('never reloads from a notification, a timer or a fresh page state', () => {
    vi.useFakeTimers();
    try {
      const recovery = createAssetRecovery();
      const reload = vi.fn();
      const remove = observeAssetFailures(window, recovery);
      recovery.requestReload(reload);
      window.dispatchEvent(new Event('vite:preloadError'));
      vi.runAllTimers();
      expect(recovery.snapshot()).toBe('unavailable');
      expect(reload).not.toHaveBeenCalled();
      expect(createAssetRecovery().snapshot()).toBe('ready');
      remove();
    } finally {
      vi.useRealTimers();
    }
  });
});
