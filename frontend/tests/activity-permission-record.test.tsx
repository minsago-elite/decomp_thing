import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, within } from '@testing-library/preact';
import { describe, expect, it } from 'vitest';
import type { ProgressObservation, WebEvent } from '../src/api/generated';
import { ActivityRow } from '../src/jobs/ActivityRow';

type Observation = WebEvent & { type: 'workflow.observation'; payload: ProgressObservation };
const events = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/events-observation-poll.json'), 'utf8')) as { data: { items: Observation[] } };
const base = events.data.items[0]!;
const row = (kind: ProgressObservation['observationKind'], fields: ProgressObservation['fields']): Observation =>
  ({ ...base, sequence: '7', cursor: 'cursor_7', payload: { ...base.payload, observationKind: kind, fields } });
const region = () => screen.queryByRole('group', { name: 'Recorded permission decision' });

describe('recorded permission decisions in activity (#563)', () => {
  it.each([
    ['allow_once', 'allowed once'], ['allow_session', 'allowed for the agent session'],
    ['deny', 'denied'], ['cancelled', 'cancelled'], [undefined, 'not recorded'],
  ] as const)('shows %s as a read-only record with no decision control', (decision, label) => {
    render(<ul><ActivityRow event={row('permission', decision ? { decision } : {})} basePath="/w" /></ul>);
    const section = region()!;
    expect(within(section).getByText(label, { selector: 'dd' })).toBeTruthy();
    expect(within(section).getByText('Operator decisions are unavailable in this view.')).toBeTruthy();
    expect(within(section).queryAllByRole('button')).toHaveLength(0);
    expect(within(section).queryAllByRole('link')).toHaveLength(0);
    expect(section.querySelectorAll('input, select, textarea, form')).toHaveLength(0);
    // Identity stays in the existing correlation details; it is not repeated here.
    expect(section.textContent).not.toMatch(/[a-f0-9]{64}/);
  });

  it.each(['tool', 'file_change', 'message', 'unknown'] as const)('does not render on %s rows', kind => {
    render(<ul><ActivityRow event={row(kind, { decision: 'deny', status: 'completed' })} basePath="/w" /></ul>);
    expect(region()).toBeNull();
    expect(screen.queryByText(/Operator decisions are unavailable/)).toBeNull();
  });
});
