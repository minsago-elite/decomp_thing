import { answerHighlightRequest } from './highlight';

// This entry has no DOM, network, HTML, evaluation or source-loading operation.
const scope = globalThis as unknown as {
  onmessage: ((event: { data: unknown }) => void) | null;
  postMessage(value: unknown): void;
  close(): void;
};
scope.onmessage = event => {
  try {
    scope.postMessage(answerHighlightRequest(event.data));
  }
  finally { scope.close(); }
};
