import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {readManifestIdentity} from './manifest-identity.mjs';

function fixture(manifest = {}, metadata = {}) {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-identity-'));
  mkdirSync(root, {recursive: true});
  writeFileSync(join(root, 'manifest.json'), JSON.stringify({
    network: 'scenario-a', namespace: 'hacknet-system', ...manifest,
  }));
  writeFileSync(join(root, 'stacksnetwork.json'), JSON.stringify({
    metadata: {name: 'scenario-a', namespace: 'hacknet-system', ...metadata},
  }));
  return root;
}

test('derives the exact network and namespace shared by rendered artifacts', () => {
  assert.deepEqual(readManifestIdentity(fixture()), {
    network: 'scenario-a', namespace: 'hacknet-system',
  });
});

test('rejects mismatched names, namespaces, and invalid labels before mutation', () => {
  assert.throws(() => readManifestIdentity(fixture({}, {name: 'other'})), /does not match/);
  assert.throws(() => readManifestIdentity(fixture({}, {namespace: 'other'})), /does not match/);
  assert.throws(() => readManifestIdentity(fixture({network: 'Not_A_Label'})), /DNS label/);
});

