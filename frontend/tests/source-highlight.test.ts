// @vitest-environment node
import { expect, it } from 'vitest';
import { answerHighlightRequest, boundedHighlightRows, highlightRows, readHighlightResponse, sourceHighlightLanguage,
  HIGHLIGHT_MAX_CHARACTERS, HIGHLIGHT_MAX_ROWS, HIGHLIGHT_MAX_TOKENS } from '../src/sources/highlight';
import { visibleSourceText } from '../src/sources/viewer';

// Strings and DTOs only: no DOM, worker, network, filesystem or timer.
it('preserves markup URLs visible controls and multiline C comments and raw strings as inert text tokens', () => {
  const rows = ['int main() { /* <script src="https://example.invalid/a.js">',
    'comment */ return R"tag(<img src=x onerror=alert(1)>', 'https://example.invalid/ )tag"; }',
    visibleSourceText('/*\u0000\u001b\u202e*/')];
  const result = highlightRows(rows, 'c');
  expect(result.mode).toBe('formatted');
  expect(result.rows.map(row => row.map(token => token.text).join(''))).toEqual(rows);
  expect(result.rows.flat().some(token => token.kind === 'keyword' && token.text === 'return')).toBe(true);
  expect(result.rows.flat().some(token => token.kind === 'comment' && token.text.includes('<script'))).toBe(true);
  expect(result.rows.flat().some(token => token.kind === 'string' && token.text.includes('<img'))).toBe(true);
  expect(readHighlightResponse({ type: 'source-highlighted', id: 1, ...result }, rows)).toEqual(result);
});

it('keeps JSON build and unsupported-file formatting local without changing any displayed character', () => {
  for (const [path, language] of [['src/a.cpp', 'c'], ['src/a.hpp', 'c'], ['data.json', 'json'],
    ['Makefile', 'build'], ['CMakeLists.txt', 'build'], ['cfg/a.cmake', 'build'],
    ['README.md', 'plain'], ['https://example.invalid/payload.html', 'plain']] as const) {
    expect(sourceHighlightLanguage(path)).toBe(language);
  }
  const json = ['{"url":"<svg onload=alert(1)>", "value":null, "ready":true, "count":42}'];
  const build = ['# https://example.invalid/script', 'target: "<img src=x>"'];
  for (const [rows, language] of [[json, 'json'], [build, 'build'], [json, 'plain']] as const) {
    const result = highlightRows(rows, language);
    expect(result.rows.map(row => row.map(token => token.text).join(''))).toEqual(rows);
    expect(readHighlightResponse({ type: 'source-highlighted', id: 1, ...result }, rows)).toEqual(result);
  }
  expect(highlightRows(json, 'plain').mode).toBe('plain');
});

it('bounds rows characters raw delimiters and token expansion with a complete plain-text fallback', () => {
  expect(boundedHighlightRows(Array<string>(HIGHLIGHT_MAX_ROWS).fill(''))).toBe(true);
  expect(boundedHighlightRows(Array<string>(HIGHLIGHT_MAX_ROWS + 1).fill(''))).toBe(false);
  expect(boundedHighlightRows(['x'.repeat(HIGHLIGHT_MAX_CHARACTERS)])).toBe(true);
  expect(boundedHighlightRows(['x'.repeat(HIGHLIGHT_MAX_CHARACTERS), 'x'])).toBe(false);
  expect(boundedHighlightRows(['line\nextra'])).toBe(false);
  expect(boundedHighlightRows(['a\ud800b'])).toBe(false);
  const rows = ['int 1 '.repeat(5000), 'R"x" '.repeat(10000), ''];
  const result = highlightRows(rows, 'c');
  expect(result).toEqual({ mode: 'plain', rows: rows.map(text => [{ kind: 'plain', text }]) });
  expect(result.rows.flat().length).toBeLessThanOrEqual(HIGHLIGHT_MAX_TOKENS);
  expect(() => highlightRows(['x'.repeat(HIGHLIGHT_MAX_CHARACTERS + 1)], 'c')).toThrow();
});

it('refuses worker text changes styles extra fields identities and cumulative output expansion before rendering', () => {
  const rows = ['int x = 1;']; const result = highlightRows(rows, 'c');
  const value = { type: 'source-highlighted', id: 1, ...result };
  const invalid = [{ ...value, id: 2 }, { ...value, type: 'html' }, { ...value, raw: '<script>' },
    { ...value, rows: [] }, { ...value, rows: [[{ kind: 'html', text: rows[0] }]] },
    { ...value, rows: [[{ kind: 'plain', text: '<script>' }]] },
    { ...value, rows: [[{ kind: 'plain', text: rows[0], style: 'url(https://example.invalid)' }]] },
    { ...value, rows: [Array<{ kind: string; text: string }>(HIGHLIGHT_MAX_TOKENS + 1).fill({ kind: 'plain', text: '' })] },
    { ...value, rows: [[{ kind: 'plain', text: 'x'.repeat(HIGHLIGHT_MAX_CHARACTERS) },
      { kind: 'plain', text: 'x'.repeat(HIGHLIGHT_MAX_CHARACTERS) }]] }];
  for (const response of invalid) expect(() => readHighlightResponse(response, rows)).toThrow();
  // Sparse arrays must visit missing elements instead of silently skipping validation.
  expect(() => readHighlightResponse({ ...value, rows: Array(1) }, rows)).toThrow();
  expect(() => readHighlightResponse({ ...value, rows: [Array(1)] }, [''])).toThrow();
  const astral = ['🐈'];
  expect(() => readHighlightResponse({ type: 'source-highlighted', id: 1, mode: 'formatted', rows: [[
    { kind: 'string', text: '\ud83d' }, { kind: 'comment', text: '\udc08' },
  ]] }, astral)).toThrow();
  expect(readHighlightResponse({ type: 'source-highlighted', id: 1, ...highlightRows(astral, 'c') }, astral)
    .rows[0]!.map(token => token.text).join('')).toBe('🐈');
});

it('runs the actual worker-facing request handler as pure data and never returns peer error text', () => {
  const rows = ['int main() { return 0; }'];
  const request = { type: 'source-highlight', id: 1, language: 'c', rows };
  const response = answerHighlightRequest(request);
  expect(readHighlightResponse(response, rows)).toEqual(highlightRows(rows, 'c'));
  for (const invalid of [null, [], 'PRIVATE SOURCE', { ...request, type: 'evaluate' }, { ...request, id: 2 },
    { ...request, language: 'https://example.invalid/PRIVATE' }, { ...request, url: 'PRIVATE' },
    { ...request, rows: ['PRIVATE\nSOURCE'] }, { ...request, rows: ['\ud800'] }]) {
    expect(answerHighlightRequest(invalid)).toEqual({ type: 'source-highlight-failed', id: 1 });
  }
});
