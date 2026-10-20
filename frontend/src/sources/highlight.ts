/** Presentation only. Tokens always retain the complete, unchanged displayed text. */
export const HIGHLIGHT_MAX_ROWS = 200;
export const HIGHLIGHT_MAX_CHARACTERS = 262144;
export const HIGHLIGHT_MAX_TOKENS = 4096;
export type HighlightLanguage = 'c' | 'json' | 'build' | 'plain';
export type HighlightKind = 'plain' | 'keyword' | 'string' | 'comment' | 'number';
export interface HighlightToken { kind: HighlightKind; text: string }
export interface HighlightedRows { mode: 'formatted' | 'plain'; rows: HighlightToken[][] }
export type HighlightResponse = ({ type: 'source-highlighted'; id: 1 } & HighlightedRows)
  | { type: 'source-highlight-failed'; id: 1 };
const kinds = new Set<HighlightKind>(['plain', 'keyword', 'string', 'comment', 'number']);
const languages = new Set<HighlightLanguage>(['c', 'json', 'build', 'plain']);
const keywords = new Set(('alignas alignof asm auto bool break case catch char class const constexpr continue default delete do double else enum explicit extern false float for friend goto if inline int long namespace new noexcept nullptr operator private protected public register return short signed sizeof static static_assert struct switch template this thread_local throw true try typedef typename union unsigned using virtual void volatile wchar_t while _Bool _Complex _Generic _Static_assert').split(' '));
const jsonKeywords = new Set(['true', 'false', 'null']);
const noKeywords = new Set<string>();

function wellFormed(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

export function sourceHighlightLanguage(path: string): HighlightLanguage {
  const name = path.slice(path.lastIndexOf('/') + 1).toLowerCase();
  if (/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/.test(name)) return 'c';
  if (name.endsWith('.json')) return 'json';
  if (name === 'makefile' || name === 'gnumakefile' || name === 'cmakelists.txt' || /\.(?:mk|cmake)$/.test(name)) return 'build';
  return 'plain';
}

export function boundedHighlightRows(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > HIGHLIGHT_MAX_ROWS) return false;
  let characters = 0;
  for (const row of value) {
    if (typeof row !== 'string' || row.length > HIGHLIGHT_MAX_CHARACTERS) return false;
    characters += row.length;
    if (characters > HIGHLIGHT_MAX_CHARACTERS || row.includes('\n') || !wellFormed(row)) return false;
  }
  return true;
}

function plain(rows: readonly string[]): HighlightedRows {
  return { mode: 'plain', rows: rows.map(text => [{ kind: 'plain', text }]) };
}

/** Pure entry used by the packaged worker; malformed requests produce only a fixed failure tag. */
export function answerHighlightRequest(value: unknown): HighlightResponse {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid highlighting request');
    const record = value as Record<string, unknown>;
    if (Object.keys(record).sort().join(',') !== 'id,language,rows,type' || record.type !== 'source-highlight'
      || record.id !== 1 || typeof record.language !== 'string' || !languages.has(record.language as HighlightLanguage)
      || !boundedHighlightRows(record.rows)) throw Error('Invalid highlighting request');
    return { type: 'source-highlighted', id: 1, ...highlightRows(record.rows, record.language as HighlightLanguage) };
  } catch { return { type: 'source-highlight-failed', id: 1 }; }
}

/** Linear bounded lexer, with local comment/raw-string context only within these displayed rows. */
export function highlightRows(rows: string[], language: HighlightLanguage): HighlightedRows {
  if (!boundedHighlightRows(rows) || !languages.has(language)) throw Error('Invalid highlighting request');
  if (language === 'plain') return plain(rows);
  let blockComment = false; let rawClose: string | null = null; let totalTokens = 0;
  const result: HighlightToken[][] = [];
  for (const row of rows) {
    const ranges: { kind: HighlightKind; from: number; to: number }[] = []; let index = 0;
    function add(kind: HighlightKind, end: number) {
      const previous = ranges.at(-1);
      if (previous?.kind === kind) previous.to = end;
      else { ranges.push({ kind, from: index, to: end }); totalTokens++; }
      index = end;
    }
    while (index < row.length) {
      if (totalTokens >= HIGHLIGHT_MAX_TOKENS) return plain(rows);
      if (blockComment) {
        const end = row.indexOf('*/', index);
        add('comment', end < 0 ? row.length : end + 2); blockComment = end < 0; continue;
      }
      if (rawClose !== null) {
        const end = row.indexOf(rawClose, index);
        add('string', end < 0 ? row.length : end + rawClose.length);
        if (end >= 0) rawClose = null;
        continue;
      }
      if (language === 'c' && row.startsWith('//', index)) { add('comment', row.length); continue; }
      if (language === 'build' && row[index] === '#') { add('comment', row.length); continue; }
      if (language === 'c' && row.startsWith('/*', index)) {
        const end = row.indexOf('*/', index + 2);
        add('comment', end < 0 ? row.length : end + 2); blockComment = end < 0; continue;
      }
      if (language === 'c') {
        const prefix = ['u8R"', 'uR"', 'UR"', 'LR"', 'R"'].find(value => row.startsWith(value, index));
        if (prefix) {
          const start = index + prefix.length; const maximum = Math.min(row.length, start + 17);
          let opening = start;
          while (opening < maximum && row[opening] !== '(') opening++;
          if (opening < maximum && /^[^\s()\\]*$/.test(row.slice(start, opening))) {
            rawClose = ')' + row.slice(start, opening) + '"';
            const end = row.indexOf(rawClose, opening + 1);
            add('string', end < 0 ? row.length : end + rawClose.length);
            if (end >= 0) rawClose = null;
            continue;
          }
        }
      }
      const char = row[index]!;
      if (char === '"' || (char === "'" && language !== 'json')) {
        let end = index + 1;
        while (end < row.length) {
          if (row[end] === '\\') { end = Math.min(row.length, end + 2); continue; }
          if (row[end++] === char) break;
        }
        add('string', end); continue;
      }
      if (/[A-Za-z_]/.test(char)) {
        let end = index + 1;
        while (end < row.length && /[A-Za-z0-9_]/.test(row[end]!)) end++;
        const word = row.slice(index, end);
        add((language === 'c' ? keywords : language === 'json' ? jsonKeywords : noKeywords).has(word) ? 'keyword' : 'plain', end);
        continue;
      }
      if (/[0-9]/.test(char)) {
        let end = index + 1;
        while (end < row.length && /[A-Za-z0-9_.]/.test(row[end]!)) end++;
        add('number', end); continue;
      }
      add('plain', index + 1);
    }
    if (ranges.length === 0) {
      if (totalTokens >= HIGHLIGHT_MAX_TOKENS) return plain(rows);
      ranges.push({ kind: 'plain', from: 0, to: 0 }); totalTokens++;
    }
    result.push(ranges.map(({ kind, from, to }) => ({ kind, text: row.slice(from, to) })));
  }
  return { mode: 'formatted', rows: result };
}

/** The worker cannot introduce markup, text, styles, rows or an unbounded token population. */
export function readHighlightResponse(value: unknown, expected: readonly string[]): HighlightedRows {
  if (!boundedHighlightRows(expected)) throw Error('Invalid highlighting response');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid highlighting response');
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'id,mode,rows,type' || record.type !== 'source-highlighted' || record.id !== 1
    || (record.mode !== 'formatted' && record.mode !== 'plain') || !Array.isArray(record.rows) || record.rows.length !== expected.length) {
    throw Error('Invalid highlighting response');
  }
  let total = 0; let characters = 0;
  const rows = Array.from(record.rows, (row: unknown, index) => {
    if (!Array.isArray(row) || row.length < 1 || row.length > HIGHLIGHT_MAX_TOKENS) throw Error('Invalid highlighting response');
    const tokens = Array.from(row, (token: unknown) => {
      if (++total > HIGHLIGHT_MAX_TOKENS || !token || typeof token !== 'object' || Array.isArray(token)) throw Error('Invalid highlighting response');
      const item = token as Record<string, unknown>;
      if (Object.keys(item).sort().join(',') !== 'kind,text' || typeof item.kind !== 'string' || !kinds.has(item.kind as HighlightKind)
        || typeof item.text !== 'string' || item.text.length > HIGHLIGHT_MAX_CHARACTERS || !wellFormed(item.text)
        || (record.mode === 'plain' && item.kind !== 'plain')) throw Error('Invalid highlighting response');
      characters += item.text.length;
      if (characters > HIGHLIGHT_MAX_CHARACTERS) throw Error('Invalid highlighting response');
      return { kind: item.kind as HighlightKind, text: item.text };
    });
    if (tokens.map(token => token.text).join('') !== expected[index]) throw Error('Invalid highlighting response');
    return tokens;
  });
  return { mode: record.mode, rows };
}
