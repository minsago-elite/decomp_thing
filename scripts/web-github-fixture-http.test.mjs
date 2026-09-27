import assert from 'node:assert/strict';
import test from 'node:test';
import { createFakeGitHubFixture } from './web-github-fixture.mjs';

test('the fake provider serves only a disposable loopback PR API', async () => {
  const provider = createFakeGitHubFixture();
  const listener = await provider.listen();
  const pulls = `${listener.baseUrl}${provider.repository}/pulls`;
  const request = { head: 'feature', base: 'main', title: 'Fixture review', body: 'Synthetic only.' };
  const options = {
    method: 'POST', headers: { Authorization: `Bearer ${provider.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(request), signal: AbortSignal.timeout(5000),
  };
  try {
    assert.match(listener.baseUrl, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
    const unauthorized = await fetch(pulls, { ...options, headers: { 'Content-Type': 'application/json' } });
    assert.equal(unauthorized.status, 401);
    const created = await fetch(pulls, options);
    assert.equal(created.status, 201);
    assert.equal((await created.json()).html_url, 'https://fixture.invalid/fixture-owner/fixture-repo/pull/1');
    const duplicate = await fetch(pulls, options);
    assert.equal(duplicate.status, 422);
    assert.equal((await duplicate.json()).errors[0].code, 'already_exists');
    const listed = await fetch(`${pulls}?head=fixture-owner%3Afeature&base=main`, { signal: AbortSignal.timeout(5000) });
    assert.equal(listed.status, 200);
    assert.equal((await listed.json()).length, 1);
    assert.equal(provider.requests.length, 4);
    assert.equal(JSON.stringify(provider.requests).includes(provider.token), false);
  } finally {
    await listener.close();
    await provider.dispose();
  }
});
