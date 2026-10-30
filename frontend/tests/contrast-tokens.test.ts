import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';

// Fast, deterministic contrast gate over the design tokens (#616). The packaged browser audit
// (scripts/packaged-browser-audit.mjs) measures every rendered text node; this test fails earlier,
// in `npm test`, when a token edit breaks a documented foreground/background pairing.
const css = readFileSync(resolve(process.cwd(), 'src/styles/app.css'), 'utf8');

function tokens(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  expect(start, selector).toBeGreaterThanOrEqual(0);
  const body = css.slice(start + selector.length + 2, css.indexOf('}', start));
  return Object.fromEntries([...body.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{3,6})\s*;/gi)].map(match => [match[1]!, match[2]!.toLowerCase()]));
}

function rgb(hex: string): number[] {
  const digits = hex.length === 4 ? [...hex.slice(1)].map(digit => digit + digit).join('') : hex.slice(1);
  return [0, 2, 4].map(index => parseInt(digits.slice(index, index + 2), 16));
}
function luminance(hex: string): number {
  return rgb(hex).map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index]!, 0);
}
function ratio(a: string, b: string): number {
  const [low, high] = [luminance(a), luminance(b)].sort((x, y) => x - y) as [number, number];
  return (high + 0.05) / (low + 0.05);
}

const surfaces = ['canvas', 'surface', 'surface-sunken', 'selected', 'code-surface'];
// [foreground, backgrounds, minimum]: body text needs 4.5:1; control boundaries and focus need 3:1.
const pairs: [string, string[], number][] = [
  ['text', [...surfaces, 'danger-surface', 'attention-surface'], 4.5],
  ['muted', ['canvas', 'surface', 'surface-sunken', 'selected'], 4.5],
  ['accent', ['canvas', 'surface', 'surface-sunken', 'selected'], 4.5],
  ['on-accent', ['accent', 'accent-hover'], 4.5],
  ['danger', ['canvas', 'surface', 'danger-surface'], 4.5],
  ['attention', ['canvas', 'surface', 'surface-sunken', 'attention-surface'], 4.5],
  ['control-line', ['canvas', 'surface', 'surface-sunken'], 3],
  ['focus', ['canvas', 'surface', 'surface-sunken', 'selected', 'danger-surface', 'attention-surface'], 3],
];

const light = tokens(':root');
const dark = tokens(':root[data-theme="dark"]');
const systemDark = tokens('  :root:not([data-theme="light"])');

it('keeps the explicit and system dark themes identical', () => {
  expect(systemDark).toEqual(dark);
  expect(Object.keys(dark).sort()).toEqual(Object.keys(light).filter(name => name in dark).sort());
});

for (const [theme, values] of [['light', light], ['dark', dark]] as const) {
  it(`meets WCAG contrast for every documented ${theme} token pairing`, () => {
    const failures: string[] = [];
    for (const [foreground, backgrounds, minimum] of pairs) {
      for (const background of backgrounds) {
        const value = ratio(values[foreground]!, values[background]!);
        if (value < minimum) failures.push(`${foreground} on ${background}: ${value.toFixed(3)} < ${minimum}`);
      }
    }
    expect(failures).toEqual([]);
  });
}
