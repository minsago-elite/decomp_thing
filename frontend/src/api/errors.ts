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
