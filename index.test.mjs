import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { getAppContainerProcessTokens, getProcessInfo } from './index.js';
import { spawn } from 'node:child_process';

test('getAppContainerProcessTokens returns an array', () => {
  const tokens = getAppContainerProcessTokens();
  assert.ok(Array.isArray(tokens));
  // Note: This test only verifies we get an array back
  // The actual contents will depend on what app containers are running
});

test('getProcessInfo', async () => {
  const uuid = randomUUID();
  const child = spawn(process.argv0, [
    '-e',
    `setTimeout(()=>console.log(${JSON.stringify(uuid)}),60000)`,
  ]);
  await new Promise((r) => child.on('spawn', r));

  const processes = getProcessInfo();
  const match = processes.find((p) => p.commandLine.includes(uuid));
  try {
    assert.ok(match, 'Process not found in process list');
  } finally {
    child.kill();
  }
});
