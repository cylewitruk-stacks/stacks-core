import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';

import {joinImageAdmissionEvidence} from './image-admission-evidence.mjs';

const sha = letter => `sha256:${letter.repeat(64)}`;
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function seal(record) {
  record.recordDigest = `sha256:${createHash('sha256').update(JSON.stringify(canonical(record))).digest('hex')}`;
  return record;
}
function fixture() {
  const localRef = 'stacks-core-attacknet:content-abc';
  const buildRecord = seal({
    schema: 'stacks-attacknet-image-build-record/v1', pipelineId: 'release', profileId: 'v4',
    source: {revision: '1'.repeat(40)}, localRef, imageDigest: sha('a'),
    immutableRef: `stacks-core-attacknet@${sha('a')}`,
    imageIdentity: {
      imageIndexDigest: sha('a'), platformManifestDigest: sha('b'), runtimeConfigDigest: sha('c'),
      expectedRuntimeImageID: sha('c'), platform: 'linux/arm64',
    },
  });
  const network = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    metadata: {name: 'net', uid: 'network-uid', generation: 2},
    spec: {actors: [{name: 'follower-5', image: localRef}]},
    status: {phase: 'Ready', observedGeneration: 2, actors: [{name: 'follower-5', image: localRef, ready: true}]},
  };
  const pod = {
    metadata: {name: 'net-follower-5-0', uid: 'pod-uid', labels: {'testing.stacks.org/network': 'net', 'testing.stacks.org/actor': 'follower-5'}},
    spec: {nodeName: 'worker-1', containers: [{name: 'actor', image: localRef}]},
    status: {phase: 'Running', conditions: [{type: 'Ready', status: 'True'}], containerStatuses: [{name: 'actor', image: `docker.io/library/${localRef}`, imageID: sha('c'), ready: true, restartCount: 0}]},
  };
  return {buildRecord, network, pod};
}

test('joins a sealed local build to an observed Ready generation and exact CRI runtime config', () => {
  const input = fixture();
  const evidence = joinImageAdmissionEvidence({...input, actor: 'follower-5'});
  assert.equal(evidence.result, 'Passed');
  assert.equal(evidence.build.imageIndexDigest, sha('a'));
  assert.equal(evidence.admission.runtimeDigest, sha('c'));
  assert.match(evidence.evidenceDigest, /^sha256:[0-9a-f]{64}$/);
});

test('fails closed on stale controller status, wrong runtime bytes, or tampered build provenance', () => {
  const stale = fixture();
  stale.network.metadata.generation = 3;
  assert.throws(() => joinImageAdmissionEvidence({...stale, actor: 'follower-5'}), /not observed/);

  const wrongRuntime = fixture();
  wrongRuntime.pod.status.containerStatuses[0].imageID = sha('d');
  assert.throws(() => joinImageAdmissionEvidence({...wrongRuntime, actor: 'follower-5'}), /does not match/);

  const tampered = fixture();
  tampered.buildRecord.source.revision = '2'.repeat(40);
  assert.throws(() => joinImageAdmissionEvidence({...tampered, actor: 'follower-5'}), /does not verify/);
});
