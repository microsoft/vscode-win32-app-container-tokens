import test from 'node:test';
import assert from 'node:assert/strict';
import { getAppContainerProcessTokens } from './index.js';

test('getAppContainerProcessTokens returns an array', (t) => {
  const tokens = getAppContainerProcessTokens();
  assert.ok(Array.isArray(tokens));
  // Note: This test only verifies we get an array back
  // The actual contents will depend on what app containers are running
});
