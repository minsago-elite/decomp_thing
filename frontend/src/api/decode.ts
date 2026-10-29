import { contractSchema } from './generated-schema';
import type { ContractDocument, RequestData, RequestKind, ResponseKind, ResponseOf } from './generated';
import { ApiClientError } from './errors';
import { MAX_JSON_BYTES, parseBoundedJson } from './json';
import { checkSemantics } from './semantics';
import { isObject, registerDefinitions, validateSchema } from './validate';
import type { Schema } from './schema-types';

const variants = new Map<string, Schema>();
for (const schema of contractSchema.oneOf ?? []) {
  const kind = schema.properties?.kind?.const;
  if (typeof kind === 'string') variants.set(kind, schema);
}
variants.set('event', { $ref: '#/definitions/event' });

const groupChecks = new Map<string, (document: ContractDocument) => void>();

/** Admit a generated lazy response group and its semantic checks; its kinds stay unsupported until the owning route loads. */
export function registerContractGroup(group: Schema, check: (document: ContractDocument) => void): void {
  registerDefinitions(group.definitions ?? {});
  for (const schema of group.oneOf ?? []) {
    const kind = schema.properties?.kind?.const;
    if (typeof kind !== 'string' || (variants.has(kind) && variants.get(kind) !== schema)) throw new ApiClientError('unsupported_contract');
    variants.set(kind, schema);
    groupChecks.set(kind, check);
  }
}

/** Producer mode checks shared closed fixtures; response mode projects additive v1 fields. */
export function decodeContract(text: string, options: { mode?: 'producer' | 'response'; maxBytes?: number; basePath?: string } = {}): ContractDocument {
  const value = parseBoundedJson(text, options.maxBytes ?? MAX_JSON_BYTES);
  if (!isObject(value)) throw new ApiClientError('invalid_response');
  if (value.apiVersion !== 1 || typeof value.kind !== 'string' || !variants.has(value.kind)) throw new ApiClientError('unsupported_contract');
  if (value.kind === 'event' && !contractSchema.definitions?.eventBase?.properties?.type?.enum?.includes(value.type)) {
    throw new ApiClientError('unsupported_contract');
  }
  const schema = variants.get(value.kind);
  if (!schema) throw new ApiClientError('unsupported_contract');
  const additive = options.mode !== 'producer' && !value.kind.endsWith('Request');
  const document = validateSchema(value, schema, additive) as ContractDocument;
  checkSemantics(document, options.basePath ?? '/');
  groupChecks.get(document.kind)?.(document);
  return document;
}

export function decodeResponse<K extends ResponseKind>(text: string, expectedKind: K, maxBytes = MAX_JSON_BYTES, basePath = '/'): ResponseOf<K> {
  const document = decodeContract(text, { maxBytes, basePath });
  if (document.kind !== expectedKind) throw new ApiClientError('unexpected_response');
  return document as ResponseOf<K>;
}

/** Request envelopes exist only in the fixture/type pipeline; HTTP sends the validated data. */
export function encodeRequest<K extends RequestKind>(kind: K, data: RequestData<K>): string {
  try {
    const document = decodeContract(JSON.stringify({ apiVersion: 1, kind, data }), { mode: 'producer' });
    if (!('data' in document)) throw new ApiClientError('invalid_request');
    return JSON.stringify(document.data);
  } catch {
    throw new ApiClientError('invalid_request');
  }
}
