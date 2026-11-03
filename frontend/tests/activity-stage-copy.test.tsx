import { render } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type * as CommonModule from '../src/copy/common';
import { activityStagesCopy as copy, stageLabels } from '../src/copy/activityStages';
import { ActivityStages } from '../src/jobs/ActivityStages';

const catalog = vi.hoisted(() => ({ labeledValue: '{label}: {value}' }));
vi.mock('../src/copy/common', async load => {
  const original = await load<typeof CommonModule>();
  return { ...original, commonCopy: { ...original.commonCopy, get labeledValue() { return catalog.labeledValue; } } };
});

it('lets the catalog reorder the attempt label without losing its state mark or unknown fallback', () => {
  const view = render(<ActivityStages run={{ state: 'running', acceptance: 'not-evaluated' }} events={[]} />);
  const summary = () => view.container.querySelector('p')!;
  expect(summary().textContent).toBe(`${copy.attempt}: ${stageLabels.running}`);
  expect(summary().querySelector('.state-mark')?.getAttribute('data-tone')).toBe('active');

  try {
    catalog.labeledValue = '{value} / {label}';
    view.rerender(<ActivityStages run={{ state: 'running', acceptance: 'not-evaluated' }} events={[]} />);
    expect(summary().textContent).toBe(`${stageLabels.running} / ${copy.attempt}`);
    expect(summary().querySelector('.state-mark')?.getAttribute('data-tone')).toBe('active');

    view.rerender(<ActivityStages run={null} events={[]} />);
    expect(summary().textContent).toBe(`${copy.attemptUnknown} / ${copy.attempt}`);
    expect(summary().querySelector('.state-mark')).toBeNull();
  } finally { catalog.labeledValue = '{label}: {value}'; }
});
