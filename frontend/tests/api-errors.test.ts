import { expect, it } from 'vitest';
import { ApiClientError, apiFailureReference, withApiFailureReference } from '../src/api/errors';

const canonical = '123e4567-e89b-42d3-a456-426614174000';
const message = 'The request could not be completed.';

it('adds only a canonical UUID from an API failure to a fixed user message', () => {
  const failure = new ApiClientError('http_error', { status: 500, serverCode: 'INTERNAL', requestId: canonical });
  expect(apiFailureReference(failure)).toBe(canonical);
  expect(withApiFailureReference(message, failure)).toBe(`${message} Reference ID: ${canonical}.`);
  expect(withApiFailureReference(message, new Error(`private ${canonical}`))).toBe(message);
});

it.each([
  'request_example_1', canonical.toUpperCase(), `${canonical}\nprivate detail`,
  '123e4567-e89b-02d3-a456-426614174000', '123e4567-e89b-42d3-7456-426614174000',
  '123e4567-e89b-42d3-a456-426614174000/secret',
])('never displays a noncanonical or decorated request ID: %s', requestId => {
  const failure = new ApiClientError('http_error', { requestId });
  expect(apiFailureReference(failure)).toBeUndefined();
  expect(withApiFailureReference(message, failure)).toBe(message);
});

it('omits absent IDs and private response metadata', () => {
  expect(withApiFailureReference(message, new ApiClientError('network_error'))).toBe(message);
  const failure = new ApiClientError('http_error', { requestId: canonical, serverCode: 'PRIVATE_DIAGNOSTIC' });
  expect(withApiFailureReference(message, failure)).not.toContain('PRIVATE_DIAGNOSTIC');
});
