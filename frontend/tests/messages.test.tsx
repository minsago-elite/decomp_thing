import { cleanup, fireEvent, render } from '@testing-library/preact';
import { afterEach, expect, it } from 'vitest';
import { message, textMessage } from '../src/shared/messages';
import { formatExactTimestamp } from '../src/copy/format';
import { SchedulerSummary } from '../src/jobs/SchedulerSummary';
import { ProgressRetentionSummary } from '../src/jobs/ProgressRetentionSummary';

afterEach(cleanup);

it('reorders named text and live markup while preserving exact values and actions', () => {
  const timestamp = '2026-09-05T09:00:00.000000001+09:00';
  const count = '18446744073709551615';
  let clicks = 0;
  const values = () => ({
    count,
    time: <time dateTime={timestamp} title={timestamp}>{formatExactTimestamp(timestamp)}</time>,
    action: <button type="button" onClick={() => { clicks += 1; }}>Inspect</button>,
  });
  const view = render(<p>{message('{time} · {action} · {count}', values())}</p>);
  expect(view.container.textContent).toBe('2026-09-05 09:00:00.000000001+09:00 · Inspect · 18446744073709551615');
  fireEvent.click(view.getByRole('button', { name: 'Inspect' }));
  view.rerender(<p>{message('{count} · {action} · {time}', values())}</p>);
  expect(view.container.textContent).toBe('18446744073709551615 · Inspect · 2026-09-05 09:00:00.000000001+09:00');
  expect(view.container.querySelector('time')?.dateTime).toBe(timestamp);
  expect(view.container.querySelector('time')?.title).toBe(timestamp);
  fireEvent.click(view.getByRole('button', { name: 'Inspect' }));
  expect(clicks).toBe(2);
});

it('renders technical values as text without interpreting markup or recursive slots', () => {
  const value = '<b>{other} & "quoted"</b>';
  const view = render(<p>{message('Value: {value}', { value })}</p>);
  expect(view.container.textContent).toBe('Value: <b>{other} & "quoted"</b>');
  expect(view.container.querySelector('b')).toBeNull();
  expect(textMessage('{right} / {left}', { right: value, left: '18446744073709551615' }))
    .toBe('<b>{other} & "quoted"</b> / 18446744073709551615');
});

it('shows timezone context and retains nanoseconds, source offsets and large counters in runtime summaries', () => {
  const utc = '2026-09-08t00:00:00.123456789z';
  const offset = '2026-09-08t00:00:00.000000001-03:30';
  const view = render(<>
    <SchedulerSummary scheduler={{ state: 'unavailable', reasonCode: 'EXTERNAL_EXECUTOR', sampledAt: utc }} />
    <ProgressRetentionSummary retention={{ enabled: true, sampledAt: offset, examined: '18446744073709551615',
      expired: '9007199254740993', failures: '0', lastFailureCode: null }} />
  </>);
  expect([...view.container.querySelectorAll('time')].map(time => [time.textContent, time.dateTime, time.title]))
    .toEqual([
      ['2026-09-08 00:00:00.123456789 UTC', utc, utc],
      ['2026-09-08 00:00:00.000000001-03:30', offset, offset],
    ]);
  expect(view.getByText('18446744073709551615')).toBeTruthy();
  expect(view.getByText('9007199254740993')).toBeTruthy();
  expect(view.queryByText('Active workers (count)')).toBeNull();
});

it('rejects absent own values instead of displaying inherited object methods', () => {
  // @ts-expect-error A required rich-message slot must be supplied.
  expect(() => message<'{missing}'>('{missing}', {})).toThrow('Missing display message parameter');
  // @ts-expect-error Plain text uses the same required named-value contract.
  expect(() => textMessage<'{toString}'>('{toString}', {})).toThrow('Missing display message parameter');
});
