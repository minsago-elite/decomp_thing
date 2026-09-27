import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeContract, decodeResponse } from '../src/api/decode';
import type { ResponseOf } from '../src/api/generated';

const root = resolve(process.cwd(), '../contracts/web/v1');
type Outcome = 'successful' | 'empty' | 'partial' | 'interrupted' | 'failed' | 'denied' | 'unsupported';
const index = JSON.parse(readFileSync(resolve(root, 'outcomes.json'), 'utf8')) as {
  version: number;
  cases: { outcome: Outcome; fixture: string }[];
};

describe('shared deterministic web outcomes (#604)', () => {
  it('keeps the versioned seven-outcome index complete and unambiguous', () => {
    expect(index.version).toBe(1);
    expect(index.cases.map(({ outcome }) => outcome).sort()).toEqual(
      ['successful', 'empty', 'partial', 'interrupted', 'failed', 'denied', 'unsupported'].sort(),
    );
    expect(new Set(index.cases.map(({ fixture }) => fixture)).size).toBe(index.cases.length);
  });

  for (const { outcome, fixture } of index.cases) {
    it(`decodes and preserves the ${outcome} wire outcome with generated v1 types`, () => {
      expect(fixture).toMatch(/^fixtures\/[a-z0-9-]+\.json$/);
      const text = readFileSync(resolve(root, fixture), 'utf8');
      const document = decodeContract(text, { mode: 'producer' });
      expect(document).toEqual(JSON.parse(text));
      switch (outcome) {
        case 'successful': {
          const report: ResponseOf<'report'> = decodeResponse(text, 'report');
          expect(report.data.state).toBe('available');
          expect(report.data.acceptance).toBe('accepted');
          expect(report.data.summary).toMatchObject({ result: 'passed' });
          break;
        }
        case 'empty': {
          const page: ResponseOf<'jobs'> = decodeResponse(text, 'jobs');
          expect(page.data.items).toEqual([]);
          expect(page.data.page.nextCursor).toBeNull();
          break;
        }
        case 'partial': {
          const report: ResponseOf<'report'> = decodeResponse(text, 'report');
          expect(report.data.state).toBe('partial');
          expect(report.data.acceptance).toBe('unknown');
          break;
        }
        case 'interrupted':
        case 'failed': {
          const run: ResponseOf<'run'> = decodeResponse(text, 'run');
          expect(run.data.state).toBe(outcome);
          expect(run.data.terminalReason).toBe(outcome === 'failed' ? 'FAILED' : 'PROCESS_INTERRUPTED');
          expect(run.data.endedAt).not.toBeNull();
          expect(run.data.resultRevisionId).toBeNull();
          expect(run.data.acceptance).toBe('not-evaluated');
          break;
        }
        case 'denied': {
          const error: ResponseOf<'error'> = decodeResponse(text, 'error');
          expect(error.error.code).toBe('ORIGIN_DENIED');
          expect(error.error.retryable).toBe(false);
          break;
        }
        case 'unsupported': {
          const report: ResponseOf<'report'> = decodeResponse(text, 'report');
          expect(report.data.state).toBe('unsupported');
          expect(report.data.acceptance).toBe('unknown');
          expect(report.data.sourceArtifact).toBeNull();
          break;
        }
      }
    });
  }
});
