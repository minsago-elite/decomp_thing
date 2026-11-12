import { render } from 'preact';
import '../styles/app.css';
import { ProposalReview } from './ProposalReview';

const fixtureUrl = new URL('../../tests/fixtures/proposal-review/valid.json', import.meta.url);

async function loadFixture(signal: AbortSignal): Promise<unknown> {
  const response = await fetch(fixtureUrl, { signal, cache: 'no-store' });
  if (!response.ok) throw new Error('fixture load failed');
  return response.json();
}

const root = document.getElementById('proposal-review-preview');
if (!root) throw new Error('Proposal review preview root is missing.');
render(<ProposalReview basePath="/nested" loadReview={loadFixture} />, root);
