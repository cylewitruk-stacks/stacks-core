import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {dirname, normalize, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../../..');
const ENTRY = 'contrib/helm/hacknet/run-operator/controller.mjs';

function copiedSources() {
  const dockerfile = readFileSync(resolve(HERE, 'Dockerfile'), 'utf8');
  return new Set([...dockerfile.matchAll(/^COPY\s+(\S+)\s+\S+$/gm)].map(match => normalize(match[1])));
}

function relativeImports(source) {
  const text = readFileSync(resolve(REPO, source), 'utf8');
  return [...text.matchAll(/\b(?:import|export)\s+(?:[^'";]+?\s+from\s+)?['"](\.[^'"]+)['"]/g)]
    .map(match => normalize(relative(REPO, resolve(REPO, dirname(source), match[1]))));
}

test('run-operator image contains the complete transitive local import graph', () => {
  const copied = copiedSources();
  const pending = [ENTRY];
  const visited = new Set();
  while (pending.length > 0) {
    const source = pending.pop();
    if (visited.has(source)) continue;
    visited.add(source);
    assert.equal(copied.has(source), true, `${source} is imported but absent from the image context`);
    pending.push(...relativeImports(source));
  }
  assert.ok(visited.has('contrib/attacknet/signer-set-parity.mjs'));
});
