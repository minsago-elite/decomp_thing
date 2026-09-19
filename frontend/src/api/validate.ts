import { contractSchema } from './generated-schema';
import { ApiClientError } from './errors';
import type { Schema } from './schema-types';

const patterns = new Map<string, RegExp>();
export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Canonical object order makes uniqueItems independent of JSON property order.
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? '';
}

function instant(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= (days[month - 1] ?? 0)
    && Number(match[4]) <= 23 && Number(match[5]) <= 59 && Number(match[6]) <= 59
    && (match[8] === undefined || (Number(match[8]) <= 23 && Number(match[9]) <= 59));
}

/** Validate the generated schema subset; optional projection drops additive response fields. */
export function validateSchema(value: unknown, schema: Schema, additive: boolean): unknown {
  let steps = 0;
  const step = () => { if (++steps > 250_000) throw new ApiClientError('response_too_large'); };
  const dereference = (node: Schema): Schema => {
    if (!node.$ref) return node;
    const target = contractSchema.definitions?.[node.$ref.slice(14)];
    if (!target) throw new ApiClientError('unsupported_contract');
    return target;
  };
  const matches = (node: Schema, item: unknown): boolean => {
    step();
    if (node.$ref) return matches(dereference(node), item);
    if ('const' in node && canonical(item) !== canonical(node.const)) return false;
    if (node.enum && !node.enum.some((candidate) => canonical(candidate) === canonical(item))) return false;
    if (node.type) {
      const valid = node.type === 'object' ? isObject(item) : node.type === 'array' ? Array.isArray(item)
        : node.type === 'null' ? item === null : node.type === 'integer' ? typeof item === 'number' && Number.isSafeInteger(item)
          : typeof item === node.type;
      if (!valid) return false;
    }
    if (typeof item === 'number' && (!Number.isFinite(item) || (node.minimum !== undefined && item < node.minimum) || (node.maximum !== undefined && item > node.maximum))) return false;
    if (typeof item === 'string') {
      const length = [...item].length;
      if ((node.minLength !== undefined && length < node.minLength) || (node.maxLength !== undefined && length > node.maxLength)) return false;
      if (node.pattern) {
        let pattern = patterns.get(node.pattern);
        if (!pattern) { pattern = new RegExp(node.pattern, 'u'); patterns.set(node.pattern, pattern); }
        if (!pattern.test(item)) return false;
      }
      if (node.format === 'date-time' && !instant(item)) return false;
    }
    if (isObject(item)) {
      if (node.required?.some((key) => !Object.hasOwn(item, key))) return false;
      if (!additive && node.additionalProperties === false && Object.keys(item).some((key) => !Object.hasOwn(node.properties ?? {}, key))) return false;
      for (const [key, child] of Object.entries(node.properties ?? {})) if (Object.hasOwn(item, key) && !matches(child, item[key])) return false;
    }
    if (Array.isArray(item)) {
      if ((node.minItems !== undefined && item.length < node.minItems) || (node.maxItems !== undefined && item.length > node.maxItems)) return false;
      if (node.items && !item.every((entry) => matches(node.items as Schema, entry))) return false;
      if (node.uniqueItems && new Set(item.map(canonical)).size !== item.length) return false;
    }
    if (node.allOf && !node.allOf.every((child) => matches(child, item))) return false;
    if (node.anyOf && !node.anyOf.some((child) => matches(child, item))) return false;
    if (node.oneOf && node.oneOf.filter((child) => matches(child, item)).length !== 1) return false;
    if (node.if) {
      const branch = matches(node.if, item) ? node.then : node.else;
      if (branch && !matches(branch, item)) return false;
    }
    return true;
  };
  if (!matches(schema, value)) throw new ApiClientError('invalid_response');
  if (!additive) return value;
  // Union/intersection schemas contribute only fields from matching branches.
  const fields = new Map<object, Set<string>>();
  const collect = (node: Schema, item: unknown): void => {
    step();
    if (node.$ref) { collect(dereference(node), item); return; }
    if (isObject(item)) {
      const known = fields.get(item) ?? new Set<string>();
      fields.set(item, known);
      for (const [key, child] of Object.entries(node.properties ?? {})) if (Object.hasOwn(item, key)) {
        known.add(key); collect(child, item[key]);
      }
    }
    if (Array.isArray(item) && node.items) for (const entry of item) collect(node.items, entry);
    for (const child of node.allOf ?? []) collect(child, item);
    for (const child of [...node.anyOf ?? [], ...node.oneOf ?? []]) if (matches(child, item)) collect(child, item);
    if (node.if) {
      const branch = matches(node.if, item) ? node.then : node.else;
      if (branch) collect(branch, item);
    }
  };
  collect(schema, value);
  const project = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(project);
    if (isObject(item)) return Object.fromEntries([...(fields.get(item) ?? [])].map((key) => [key, project(item[key])]));
    return item;
  };
  return project(value);
}
