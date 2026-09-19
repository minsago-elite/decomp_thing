import { ApiClientError } from './errors';

export const MAX_JSON_BYTES = 1024 * 1024;
const MAX_DEPTH = 40;
const MAX_NODES = 50_000;

/** Bounded JSON parser: duplicate keys, non-finite numbers and unpaired UTF-16 are invalid. */
export function parseBoundedJson(text: string, maxBytes = MAX_JSON_BYTES): unknown {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JSON_BYTES) {
    throw new ApiClientError('invalid_request');
  }
  // Character count avoids allocating an encoded copy when the input is already too large.
  if (text.length > maxBytes || new TextEncoder().encode(text).byteLength > maxBytes) {
    throw new ApiClientError('response_too_large');
  }
  let position = 0;
  let nodes = 0;
  const invalid = (): never => { throw new ApiClientError('invalid_json'); };
  const whitespace = () => {
    while (position < text.length && /[\x20\t\r\n]/.test(text[position] ?? '')) position++;
  };
  const string = (): string => {
    const start = position++;
    while (position < text.length) {
      const char = text[position++];
      if (char === '\\') position++;
      else if (char === '"') {
        let result: string;
        try { result = JSON.parse(text.slice(start, position)) as string; } catch { return invalid(); }
        // Reject escaped unpaired surrogates as well as malformed literal Unicode.
        for (let i = 0; i < result.length; i++) {
          const unit = result.charCodeAt(i);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = result.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff)) return invalid();
          } else if (unit >= 0xdc00 && unit <= 0xdfff) return invalid();
        }
        return result;
      }
    }
    return invalid();
  };
  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw new ApiClientError('response_too_large');
    whitespace();
    const char = text[position];
    if (char === '"') return string();
    if (char === '{') {
      position++;
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      whitespace();
      if (text[position] === '}') { position++; return object; }
      while (position < text.length) {
        whitespace();
        if (text[position] !== '"') return invalid();
        const key = string();
        if (Object.hasOwn(object, key)) return invalid();
        whitespace();
        if (text[position++] !== ':') return invalid();
        object[key] = value(depth + 1);
        whitespace();
        const separator = text[position++];
        if (separator === '}') return object;
        if (separator !== ',') return invalid();
      }
      return invalid();
    }
    if (char === '[') {
      position++;
      const array: unknown[] = [];
      whitespace();
      if (text[position] === ']') { position++; return array; }
      while (position < text.length) {
        array.push(value(depth + 1));
        whitespace();
        const separator = text[position++];
        if (separator === ']') return array;
        if (separator !== ',') return invalid();
      }
      return invalid();
    }
    for (const [literal, result] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(literal, position)) { position += literal.length; return result; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(position));
    if (!match) return invalid();
    position += match[0].length;
    const number = Number(match[0]);
    return Number.isFinite(number) ? number : invalid();
  };
  const result = value(0);
  whitespace();
  if (position !== text.length) return invalid();
  return result;
}
