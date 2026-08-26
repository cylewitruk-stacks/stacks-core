import {createHash} from 'node:crypto';
import {readFileSync, readdirSync, realpathSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/equivalence/v1alpha1');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RUNTIME_REVISION = '52e0d2812c514cad29d9fd2603eb2b8b3d93b0c3';
const WORKLOAD_REVISION = 'f8a853a0f21c9edebec92398fb56500ae10e1a22';

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function filesBelow(directory) {
  return readdirSync(directory, {withFileTypes: true}).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesBelow(path) : [relative(ROOT, path)];
  });
}

// loadEquivalenceFixtures verifies every immutable v1alpha1 fixture before a test
// consumes it. The generator is intentionally not part of the normal test path.
export function loadEquivalenceFixtures() {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  if (manifest?.schema !== 'stacks-attacknet-v1alpha1-equivalence-fixtures/v1') {
    throw new Error('unsupported equivalence-fixture manifest');
  }
  if (manifest.origin?.runtimeRevision !== RUNTIME_REVISION
    || manifest.origin?.workloadRevision !== WORKLOAD_REVISION) {
    throw new Error('equivalence fixtures are not bound to the approved runtime revisions');
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    throw new Error('equivalence-fixture manifest has no entries');
  }
  const paths = new Set();
  for (const entry of manifest.entries) {
    if (typeof entry?.path !== 'string' || entry.path.startsWith('/')
      || entry.path.includes('\\') || entry.path.split('/').includes('..')) {
      throw new Error(`invalid equivalence-fixture path ${entry?.path}`);
    }
    if (!DIGEST.test(entry.digest ?? '') || paths.has(entry.path)) {
      throw new Error(`invalid or duplicate equivalence fixture ${entry.path}`);
    }
    paths.add(entry.path);
    const path = join(ROOT, entry.path);
    if (!realpathSync(path).startsWith(`${realpathSync(ROOT)}/`)) {
      throw new Error(`equivalence fixture escapes its root: ${entry.path}`);
    }
    if (sha256(readFileSync(path)) !== entry.digest) {
      throw new Error(`equivalence fixture digest mismatch: ${entry.path}`);
    }
  }
  const actualPaths = filesBelow(ROOT)
    .filter(path => path !== 'manifest.json')
    .sort();
  if (JSON.stringify(actualPaths) !== JSON.stringify([...paths].sort())) {
    throw new Error('equivalence-fixture directory contains undeclared or missing files');
  }
  return {
    manifest,
    json(path) {
      if (!paths.has(path)) throw new Error(`undeclared equivalence fixture ${path}`);
      return JSON.parse(readFileSync(join(ROOT, path), 'utf8'));
    },
  };
}
