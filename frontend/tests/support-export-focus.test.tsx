import { cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { createApiClient } from '../src/api/client';
import { SupportExport } from '../src/jobs/SupportExport';

type Client = ReturnType<typeof createApiClient>;
const client = { get: vi.fn() } as unknown as Client;
const scrollIntoView = vi.fn();

beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: scrollIntoView });
  // The Firefox 146 failure: a 1440x900 viewport with the checked radio's box starting at its bottom edge.
  vi.spyOn(document.documentElement, 'clientWidth', 'get').mockReturnValue(1440);
  vi.spyOn(document.documentElement, 'clientHeight', 'get').mockReturnValue(900);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); scrollIntoView.mockReset(); });

function place(control: HTMLElement, left: number, top: number) {
  const size = 17.600006103515625;
  vi.spyOn(control, 'getBoundingClientRect').mockReturnValue({
    left, top, right: left + size, bottom: top + size, width: size, height: size, x: left, y: top, toJSON: () => ({}),
  });
}
const radios = () => [screen.getByRole('radio', { name: /Server/ }), screen.getByRole('radio', { name: /One job/ })] as HTMLInputElement[];

it('reveals the focused scope radio left below the viewport with one nearest scroll, keeping focus and selection', () => {
  render(<SupportExport client={client} />);
  const [serverRadio, jobRadio] = radios();
  place(serverRadio!, 311, 900);
  serverRadio!.focus();
  expect(document.activeElement).toBe(serverRadio);
  expect(scrollIntoView).toHaveBeenCalledOnce();
  expect(scrollIntoView.mock.contexts[0]).toBe(serverRadio);
  expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', inline: 'nearest' });
  expect(serverRadio!.checked).toBe(true);
  expect(jobRadio!.checked).toBe(false);
});

it('reveals a radio whose focus ring would be clipped even though its box is inside the viewport', () => {
  render(<SupportExport client={client} />);
  const [serverRadio] = radios();
  place(serverRadio!, 311, 900 - 17.6 - 3);
  serverRadio!.focus();
  expect(scrollIntoView).toHaveBeenCalledOnce();
});

it('does not scroll the page for a scope radio whose focus ring is already visible', () => {
  render(<SupportExport client={client} />);
  const [serverRadio, jobRadio] = radios();
  place(serverRadio!, 311, 400);
  place(jobRadio!, 311, 6);
  serverRadio!.focus();
  jobRadio!.focus();
  expect(document.activeElement).toBe(jobRadio);
  expect(scrollIntoView).not.toHaveBeenCalled();
});

it('keeps both native radio choices bound to the scope and revealable when they become the focused choice', () => {
  render(<SupportExport client={client} />);
  const [serverRadio, jobRadio] = radios();
  expect(serverRadio!.name).toBe(jobRadio!.name);
  place(jobRadio!, 311, -40);
  // A native arrow-key move focuses then checks the next radio; emulate that order.
  jobRadio!.focus();
  fireEvent.click(jobRadio!);
  expect(jobRadio!.checked).toBe(true);
  expect(serverRadio!.checked).toBe(false);
  expect(screen.getByLabelText(/Job ID/)).toBeTruthy();
  expect(scrollIntoView).toHaveBeenCalledOnce();
  expect(scrollIntoView.mock.contexts[0]).toBe(jobRadio);
  fireEvent.click(serverRadio!);
  expect(serverRadio!.checked).toBe(true);
  expect(jobRadio!.checked).toBe(false);
  expect(screen.queryByLabelText(/Job ID/)).toBeNull();
});
