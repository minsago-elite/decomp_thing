import assert from 'node:assert/strict';

// A different manifest alone does not exercise a stale lazy import: the old
// Runtime path must actually disappear from the replacement server inventory.
export function qualifyUpgrade(previous, current) {
  assert.ok(typeof previous.buildId === 'string' && previous.buildId.length > 0, 'Previous manifest needs a build identity');
  assert.ok(typeof current.buildId === 'string' && current.buildId.length > 0, 'Current manifest needs a build identity');
  assert.notEqual(previous.buildId, current.buildId, 'Upgrade requires distinct previous/current manifest build identities');
  const runtime = (manifest, label) => {
    assert.ok(Array.isArray(manifest.files), `${label} manifest needs a resource inventory`);
    const matches = manifest.files.filter((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.equal(matches.length, 1, `${label} manifest must contain exactly one Runtime lazy chunk`);
    return matches[0];
  };
  const previousRuntime = runtime(previous, 'Previous');
  const currentRuntime = runtime(current, 'Current');
  assert.ok(!current.files.some((entry) => entry.path === previousRuntime.path),
    'Previous Runtime chunk is still inventoried by the current package; choose a qualified archive pair');
  return { previousRuntime, currentRuntime };
}
