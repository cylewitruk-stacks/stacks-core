#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {REVIEW_PACKET_SCHEMA_V1, sealReviewPacket} from './phase-review.mjs';

const releaseDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(releaseDir, '../../..');

function load(path, root = repoRoot) {
  return JSON.parse(readFileSync(resolve(root, path), 'utf8'));
}

function item(id, kind, path, root = repoRoot) {
  return {
    id,
    kind,
    path,
    digest: `sha256:${createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex')}`,
  };
}

export function deriveGitCandidate(root = repoRoot) {
  const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root, encoding: 'utf8'}).trim();
  const trackedPatch = execFileSync('git', ['diff', '--binary', 'HEAD', '--'], {cwd: root});
  const status = execFileSync('git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'], {cwd: root});
  const untracked = status.toString('utf8').split('\0').filter(Boolean)
    .filter(record => record.startsWith('?? ')).map(record => record.slice(3)).sort();
  const hash = createHash('sha256').update(trackedPatch);
  for (const path of untracked) {
    hash.update(`\0untracked\0${path}\0`);
    hash.update(readFileSync(resolve(root, path)));
  }
  return {
    sourceRevision,
    commitPending: trackedPatch.length > 0 || untracked.length > 0,
    dirtyPatchDigest: `sha256:${hash.digest('hex')}`,
  };
}

export function phaseZeroInventorySpec(offlineResultPath) {
  if (!offlineResultPath) throw new Error('offlineResultPath is required; generate it from the actual offline check');
  return [
    ['source:baseline-validator', 'source', 'contrib/attacknet/release/baseline.mjs'],
    ['source:review-gate', 'source', 'contrib/attacknet/release/phase-review.mjs'],
    ['source:schema-validator', 'source', 'contrib/attacknet/release/schema-validator.mjs'],
    ['source:packet-builder', 'source', 'contrib/attacknet/release/phase-zero-packet.mjs'],
    ['source:offline-result', 'source', 'contrib/attacknet/release/offline-result.mjs'],
    ['source:phase-zero-tests', 'source', 'contrib/attacknet/release/phase-zero.test.mjs'],
    ['source:offline-check', 'source', 'contrib/attacknet/check.sh'],
    ['source:contract-schema', 'source', 'contrib/attacknet/release/review-contract-v1.schema.json'],
    ['source:packet-schema', 'source', 'contrib/attacknet/release/review-packet-v1.schema.json'],
    ['source:verdict-schema', 'source', 'contrib/attacknet/release/review-verdict.schema.json'],
    ['source:phase-contract', 'source', 'contrib/attacknet/release/phase-0-contract.json'],
    ['evidence:baseline-manifest', 'evidence', 'contrib/attacknet/release/baseline-v1.json'],
    ['document:review-contract', 'document', 'contrib/attacknet/release/PHASE-REVIEWS.md'],
    ['document:attacknet-readme', 'document', 'contrib/attacknet/README.md'],
    ['document:hacknet-readme', 'document', 'contrib/helm/hacknet/README.md'],
    ['document:phase-handoff', 'document', 'contrib/attacknet/release/PHASE-0-HANDOFF.md'],
    ['evidence:accepted-soak', 'evidence', 'contrib/attacknet/evidence/final-soak-20260815T232258Z/verified-soak-300/result.json'],
    ['evidence:accepted-fault-run', 'evidence', 'contrib/attacknet/evidence/final-soak-20260815T232258Z/verified-fault-run.json'],
    ['evidence:accepted-mixed-version', 'evidence', 'contrib/attacknet/evidence/mixed-current-release-modified-20260816/matrix-proof/result.json'],
    ['evidence:accepted-worker-outage', 'evidence', 'contrib/attacknet/evidence/worker-outage-recovery-20260815T192000Z/result.json'],
    ['evidence:accepted-clock', 'evidence', 'contrib/attacknet/evidence/application-clock-k8s-20260816T1134Z/acceptance.json'],
    ['evidence:accepted-pvc', 'evidence', 'contrib/attacknet/evidence/pvc-node-affinity-recovery-20260815T190500Z/result.json'],
    ['evidence:accepted-negative-control', 'evidence', 'contrib/attacknet/evidence/signer-partition-stall-negative-control-20260816/result.json'],
    ['evidence:accepted-ddmin', 'evidence', 'contrib/attacknet/evidence/ddmin-live-r5-20260815T214626Z/ddmin/policy-reclassification-v2/result.json'],
    ['test:attacknet-offline-check', 'test', offlineResultPath],
    ['analysis:compatibility-and-limitations', 'analysis', 'contrib/attacknet/release/PHASE-0-HANDOFF.md'],
    ['instructions:reproduction', 'instructions', 'contrib/attacknet/release/PHASE-0-HANDOFF.md'],
  ];
}

export function buildPhaseZeroPacket({
  root = repoRoot,
  candidate = deriveGitCandidate(root),
  inventory = undefined,
  offlineResultPath = undefined,
} = {}) {
  const contract = load('contrib/attacknet/release/phase-0-contract.json', root);
  const resolvedInventory = inventory ?? phaseZeroInventorySpec(offlineResultPath).map(parts => item(...parts, root));
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA_V1,
    phase: 0,
    tier: 'Reduced',
    candidate: {
      ...candidate,
    },
    requirements: [...contract.requirements],
    inventory: resolvedInventory,
    matrix: [
      {requirement: 'machine-readable-baseline', status: 'satisfied', evidence: ['evidence:baseline-manifest', 'source:baseline-validator']},
      {requirement: 'truthful-primary-readmes', status: 'satisfied', evidence: ['document:attacknet-readme', 'document:hacknet-readme']},
      {requirement: 'digest-bound-dual-review-gate', status: 'satisfied', evidence: ['source:review-gate', 'source:phase-zero-tests']},
      {requirement: 'immutable-evidence-verification', status: 'satisfied', evidence: ['source:baseline-validator', 'source:phase-zero-tests']},
      {requirement: 'clean-offline-verification', status: 'satisfied', evidence: ['test:attacknet-offline-check']},
      {requirement: 'admitted-kubernetes-state', status: 'not-applicable', evidence: [], reason: 'Reduced documentation/offline contract phase; no Kubernetes resources change.'},
      {requirement: 'live-fault-evidence', status: 'not-applicable', evidence: [], reason: 'No runtime or fault mechanism changes.'},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: false,
      notes: 'Historical evidence is indexed and verified without reclassifying its terminal outcomes.',
    },
    limitations: [
      ...(candidate.commitPending ? [{id: 'uncommitted-candidate', disposition: 'Regenerate after the hardware-signed commit before review.'}] : []),
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'gitignored-evidence', disposition: 'Referenced bundles must be archived outside Git.'},
    ],
    reproduction: [
      'node contrib/attacknet/release/baseline.mjs validate contrib/attacknet/release/baseline-v1.json --verify-evidence --root=.',
      'node --test contrib/attacknet/release/phase-zero.test.mjs',
      'contrib/attacknet/check.sh',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const unknown = args.filter(arg => !arg.startsWith('--output=') && !arg.startsWith('--offline-result='));
  if (unknown.length > 0) throw new Error(`unknown option ${unknown[0]}`);
  const output = args.find(arg => arg.startsWith('--output='))?.slice('--output='.length);
  const offlineResultPath = args.find(arg => arg.startsWith('--offline-result='))?.slice('--offline-result='.length);
  const serialized = `${JSON.stringify(buildPhaseZeroPacket({
    offlineResultPath,
  }), null, 2)}\n`;
  if (output) writeFileSync(resolve(repoRoot, output), serialized);
  else process.stdout.write(serialized);
}
