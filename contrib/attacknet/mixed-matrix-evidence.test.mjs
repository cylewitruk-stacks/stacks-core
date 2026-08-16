import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {classifyMixedMatrixEvidence} from './mixed-matrix-evidence.mjs';

const digest = digit => `sha256:${digit.repeat(64)}`;
function json(path, value) { writeFileSync(path, `${JSON.stringify(value)}\n`); }
function metric(path, received, accepted, rejected, validated = accepted) {
  writeFileSync(path, [
    `stacks_signer_block_proposals_received ${received}`,
    `stacks_signer_block_responses_sent{response_type="accepted"} ${accepted}`,
    `stacks_signer_block_responses_sent{response_type="rejected"} ${rejected}`,
    `stacks_signer_block_validation_responses{response_type="accepted"} ${validated}`,
  ].join('\n'));
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'mixed-matrix-'));
  for (const path of ['baseline/metrics', 'final/metrics', 'baseline/nodes', 'final/nodes']) mkdirSync(join(root, path), {recursive: true});
  json(join(root, 'manifest.json'), {actors: [
    {service: 'signer-1', type: 'signer', signerWeight: 1},
    {service: 'signer-2', type: 'signer', signerWeight: 3},
    {service: 'follower-5', type: 'node'},
  ]});
  const pod = (actor, image, imageID, env = []) => ({
    metadata: {name: `${actor}-0`, uid: `${actor}-uid`, labels: {'testing.stacks.org/actor': actor}},
    spec: {containers: [{name: 'actor', image, env}]},
    status: {containerStatuses: [{name: 'actor', imageID}]},
  });
  json(join(root, 'pods.json'), {items: [
    pod('signer-1', 'modified:content', digest('1'), [{name: 'STACKS_SIGNER_TEST_DIRECTIVE', value: 'reject-all'}]),
    pod('follower-5', 'released:content', digest('2')),
  ]});
  json(join(root, 'modified.json'), {localRef: 'modified:content', imageIdentity: {expectedRuntimeImageID: digest('1')}, recordDigest: digest('3'), source: {kind: 'localModified'}});
  json(join(root, 'released.json'), {localRef: 'released:content', imageIdentity: {expectedRuntimeImageID: digest('2')}, recordDigest: digest('4'), source: {kind: 'releasedGitRef'}});
  metric(join(root, 'baseline/metrics/signer-1.txt'), 0, 0, 0, 0);
  metric(join(root, 'baseline/metrics/signer-2.txt'), 0, 0, 0, 0);
  metric(join(root, 'final/metrics/signer-1.txt'), 3, 0, 3, 0);
  metric(join(root, 'final/metrics/signer-2.txt'), 3, 3, 0, 3);
  const info = (burn, stacks, version = 'current') => ({burn_block_height: burn, stacks_tip_height: stacks, stacks_tip: `tip-${stacks}`, server_version: version});
  json(join(root, 'baseline/nodes/follower-5-info.json'), info(10, 20, 'released'));
  json(join(root, 'final/nodes/follower-5-info.json'), info(12, 23, 'released'));
  writeFileSync(join(root, 'start.txt'), '2026-01-01T00:00:00Z\n');
  writeFileSync(join(root, 'signer.log'), '2026-01-01T00:00:01Z WARN Rejecting block proposal automatically due to testing directive\n');
  return {
    root,
    config: {
      manifest: join(root, 'manifest.json'), admittedPods: join(root, 'pods.json'),
      modifiedBuildRecord: join(root, 'modified.json'), releasedBuildRecord: join(root, 'released.json'),
      modifiedSigner: 'signer-1', releasedActor: 'follower-5',
      baselineMetrics: join(root, 'baseline/metrics'), finalMetrics: join(root, 'final/metrics'),
      baselineNodeInfo: join(root, 'baseline/nodes'), finalNodeInfo: join(root, 'final/nodes'),
      windowStart: join(root, 'start.txt'), modifiedSignerLog: join(root, 'signer.log'),
      minimumBurnProgress: 2, minimumStacksProgress: 3,
    },
  };
}

test('proves immutable mixed images, deliberate rejection, and surviving progress', () => {
  const {config} = fixture();
  const result = classifyMixedMatrixEvidence(config);
  assert.equal(result.ok, true);
  assert.equal(result.adversarialBehavior.directiveRejections, 1);
  assert.equal(result.signerSet.remainingWeight, 3);
  assert.equal(result.window.stacksProgress, 3);
});

test('fails closed when the admitted runtime image does not match the build record', () => {
  const {root, config} = fixture();
  const pods = JSON.parse(readFileSync(join(root, 'pods.json'), 'utf8'));
  pods.items[0].status.containerStatuses[0].imageID = digest('9');
  json(join(root, 'pods.json'), pods);
  const result = classifyMixedMatrixEvidence(config);
  assert.equal(result.ok, false);
  assert.equal(result.checks.modifiedImage, false);
});
