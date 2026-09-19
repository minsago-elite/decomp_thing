export type ApiErrorCode = 'invalid_json' | 'response_too_large' | 'invalid_response'
  | 'unsupported_contract' | 'unexpected_response' | 'http_error' | 'network_error'
  | 'timeout' | 'aborted' | 'invalid_request' | 'invalid_headers';

/** Diagnostics contain bounded correlation metadata, never a response body, URL or token. */
export class ApiClientError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number | undefined;
  readonly requestId: string | undefined;
  readonly serverCode: string | undefined;

  constructor(code: ApiErrorCode, metadata: { status?: number; requestId?: string; serverCode?: string } = {}) {
    super(`Web API request failed (${code}).`);
    this.name = 'ApiClientError';
    this.code = code;
    this.status = metadata.status;
    this.requestId = metadata.requestId;
    this.serverCode = metadata.serverCode;
  }
}

// The server generates lowercase UUID request IDs. Transport-valid opaque IDs are
// deliberately not suitable for display: only this known diagnostic shape may
// cross into user-facing text.
const canonicalRequestId = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function apiFailureReference(error: unknown): string | undefined {
  return error instanceof ApiClientError && error.requestId && canonicalRequestId.test(error.requestId)
    ? error.requestId : undefined;
}

/** Append only a vetted correlation ID to a fixed, locally authored message. */
export function withApiFailureReference(message: string, error: unknown): string {
  const requestId = apiFailureReference(error);
  return requestId ? `${message} Reference ID: ${requestId}.` : message;
}
