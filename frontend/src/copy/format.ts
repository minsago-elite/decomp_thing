import type { Job } from '../api/generated';
import { textMessage } from '../shared/messages';
import { commonCopy, jobStatusLabels } from './common';

/**
 * The single display-format layer (#621). Catalog modules own words; this module owns how values
 * become text. Exact wire values (uint64 decimals, offsets, nanosecond timestamps) are rendered
 * from their original strings and never pass through Number or Date, so a later locale can add
 * digit grouping or translated units here without touching components or losing inspectable digits.
 */
export const displayLocale = 'en';

const pluralRules = new Intl.PluralRules(displayLocale);

/** Choose a catalog form by the locale's plural category; unsupported categories fall back to other. */
export function pluralForm<Form>(count: number, forms: { one: Form; other: Form } & Partial<Record<Intl.LDMLPluralRule, Form>>): Form {
  return forms[pluralRules.select(count)] ?? forms.other;
}

/**
 * Exact decimal counters stay character-for-character. This is the one place a locale would add
 * grouping (BigInt formatting keeps every digit); English deliberately shows the inspectable value.
 */
export function formatExactCount(value: string): string {
  return value;
}

/** Keep the canonical decimal value intact; Number would round valid uint64 values. */
export function formatExactBytes(value: string): string {
  return textMessage(commonCopy.bytes, { value: formatExactCount(value) });
}

/**
 * Preserve source offsets and fractional digits, with explicit timezone context: a UTC marker is
 * named, and any numeric offset is kept exactly as recorded. The API accepts either marker case.
 */
export function formatExactTimestamp(value: string): string {
  const displayed = value.replace(/[Tt]/, ' ');
  return /[Zz]$/.test(displayed) ? textMessage(commonCopy.utcTimestamp, { time: displayed.slice(0, -1) }) : displayed;
}

export function formatJobStatus(status: Job['status']): string { return jobStatusLabels[status]; }
