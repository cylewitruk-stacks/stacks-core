#!/usr/bin/env node

import {readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {summarizeSignerMetricDeltas} from './signer-metric-deltas.mjs';

function fail(message) { throw new Error(message); }
function readJson(path) { return JSON.parse(readFileSync(path, 'utf8')); }
function required(value, message) { if (!value) fail(message); return value; }

function actorPod(pods, actor) {
  return required(pods.items.find(item => item.metadata?.labels?.['testing.stacks.org/actor'] === actor),
    `admitted Pod for ${actor} is missing`);
}

function actorContainer(pod) {
  return required(pod.spec?.containers?.find(container => container.name === 'actor'),
    `${pod.metadata.name} has no actor container`);
}

function actorStatus(pod) {
  return required(pod.status?.containerStatuses?.find(container => container.name === 'actor'),
    `${pod.metadata.name} has no admitted actor status`);
}

function normalizeImageId(value) {
  const match = `${value ?? ''}`.match(/sha256:[0-9a-f]{64}$/);
  return match?.[0] ?? value;
}

function proveImage(pods, actor, buildRecord, expectedSourceKind) {
  const pod = actorPod(pods, actor);
  const container = actorContainer(pod);
  const status = actorStatus(pod);
  const expectedRuntimeImageID = buildRecord.imageIdentity?.expectedRuntimeImageID;
  const checks = {
    sourceKind: buildRecord.source?.kind === expectedSourceKind,
    declaredRef: container.image === buildRecord.localRef,
    runtimeImageID: normalizeImageId(status.imageID) === expectedRuntimeImageID,
    podUIDPresent: typeof pod.metadata?.uid === 'string' && pod.metadata.uid.length > 0,
    immutableBuildIdentity: /^sha256:[0-9a-f]{64}$/.test(expectedRuntimeImageID ?? '')
      && /^sha256:[0-9a-f]{64}$/.test(buildRecord.recordDigest ?? ''),
  };
  return {
    ok: Object.values(checks).every(Boolean),
    actor,
    pod: pod.metadata.name,
    podUID: pod.metadata.uid,
    declaredRef: container.image,
    runtimeImageID: normalizeImageId(status.imageID),
    source: buildRecord.source,
    buildRecordDigest: buildRecord.recordDigest,
    checks,
  };
}

function nodeRows(directory) {
  return readdirSync(directory).filter(name => /-info\.json$/.test(name)).sort().map(name => {
    const info = readJson(join(directory, name));
    return {
      actor: name.slice(0, -'-info.json'.length),
      burnHeight: Number(info.burn_block_height),
      stacksHeight: Number(info.stacks_tip_height),
      stacksTip: info.stacks_tip,
      serverVersion: info.server_version,
    };
  });
}

function cohort(rows) {
  if (rows.length === 0) fail('node evidence contains no actors');
  const burnHeights = new Set(rows.map(row => row.burnHeight));
  const stacksHeights = new Set(rows.map(row => row.stacksHeight));
  const stacksTips = new Set(rows.map(row => row.stacksTip));
  return {
    ok: rows.every(row => Number.isSafeInteger(row.burnHeight) && Number.isSafeInteger(row.stacksHeight)
      && typeof row.stacksTip === 'string' && row.stacksTip.length > 0)
      && burnHeights.size === 1 && stacksHeights.size === 1 && stacksTips.size === 1,
    actorCount: rows.length,
    burnHeight: Math.min(...rows.map(row => row.burnHeight)),
    stacksHeight: Math.min(...rows.map(row => row.stacksHeight)),
    stacksTip: stacksTips.size === 1 ? rows[0].stacksTip : null,
    rows,
  };
}

function countAfter(logPath, since, pattern) {
  const threshold = Date.parse(since);
  if (!Number.isFinite(threshold)) fail(`invalid window start ${since}`);
  let count = 0;
  for (const line of readFileSync(logPath, 'utf8').split('\n')) {
    const timestamp = Date.parse(line.split(' ', 1)[0]);
    if (Number.isFinite(timestamp) && timestamp >= threshold && pattern.test(line)) count += 1;
  }
  return count;
}

export function classifyMixedMatrixEvidence(config) {
  const manifest = readJson(config.manifest);
  const pods = readJson(config.admittedPods);
  const modifiedBuild = readJson(config.modifiedBuildRecord);
  const releasedBuild = readJson(config.releasedBuildRecord);
  const modified = proveImage(pods, config.modifiedSigner, modifiedBuild, 'localModified');
  const released = proveImage(pods, config.releasedActor, releasedBuild, 'releasedGitRef');

  const modifiedPod = actorPod(pods, config.modifiedSigner);
  const directive = actorContainer(modifiedPod).env?.find(item => item.name === 'STACKS_SIGNER_TEST_DIRECTIVE')?.value;
  const signerActors = manifest.actors.filter(actor => actor.type === 'signer');
  const modifiedManifest = required(signerActors.find(actor => actor.service === config.modifiedSigner),
    `${config.modifiedSigner} is not a declared signer`);
  const totalWeight = signerActors.reduce((sum, actor) => sum + Number(actor.signerWeight), 0);
  const thresholdWeight = Math.ceil(totalWeight * 0.7);
  const remainingWeight = totalWeight - Number(modifiedManifest.signerWeight);

  const metrics = summarizeSignerMetricDeltas(config.baselineMetrics, config.finalMetrics);
  const modifiedMetrics = required(metrics.actors.find(actor => actor.actor === config.modifiedSigner),
    `metrics for ${config.modifiedSigner} are missing`);
  const healthyAccepted = metrics.actors.filter(actor => actor.actor !== config.modifiedSigner)
    .reduce((sum, actor) => sum + actor.counters.responsesAccepted.delta, 0);

  const start = cohort(nodeRows(config.baselineNodeInfo));
  const end = cohort(nodeRows(config.finalNodeInfo));
  const releasedEnd = required(end.rows.find(row => row.actor === config.releasedActor),
    `${config.releasedActor} is absent from final cohort evidence`);
  const windowStart = readFileSync(config.windowStart, 'utf8').trim();
  const directiveActivations = countAfter(config.modifiedSignerLog, windowStart,
    /ATTACKNET TEST DIRECTIVE ACTIVE: signer will reject every block proposal/);
  // Activation normally predates the measured window.  The immutable admitted
  // env proves configuration; per-proposal directive logs prove runtime effect.
  const directiveRejections = countAfter(config.modifiedSignerLog, windowStart,
    /Rejecting block proposal automatically due to testing directive/);

  const modifiedCounters = modifiedMetrics.counters;
  const checks = {
    modifiedImage: modified.ok,
    releasedImage: released.ok,
    directiveAdmitted: directive === 'reject-all',
    adversaryBelowThreshold: remainingWeight >= thresholdWeight,
    modifiedRejectedProposals: modifiedCounters.proposalsReceived.delta > 0
      && modifiedCounters.responsesRejected.delta === modifiedCounters.proposalsReceived.delta
      && modifiedCounters.responsesAccepted.delta === 0
      && modifiedCounters.validationsAccepted.delta === 0,
    directiveRuntimeEvidence: directiveRejections > 0,
    healthyCohortAccepted: healthyAccepted > 0,
    startConverged: start.ok,
    endConverged: end.ok,
    burnProgress: end.burnHeight - start.burnHeight >= Number(config.minimumBurnProgress ?? 1),
    stacksProgress: end.stacksHeight - start.stacksHeight >= Number(config.minimumStacksProgress ?? 1),
    releasedFollowerConverged: releasedEnd.stacksTip === end.stacksTip,
    exactActorCount: end.actorCount === manifest.actors.filter(actor => actor.type === 'node').length,
  };

  return {
    schemaVersion: 'stacks-attacknet-mixed-matrix-evidence/v1',
    ok: Object.values(checks).every(Boolean),
    checks,
    window: {
      startedAt: windowStart,
      startBurnHeight: start.burnHeight,
      endBurnHeight: end.burnHeight,
      burnProgress: end.burnHeight - start.burnHeight,
      startStacksHeight: start.stacksHeight,
      endStacksHeight: end.stacksHeight,
      stacksProgress: end.stacksHeight - start.stacksHeight,
    },
    signerSet: {
      totalWeight,
      thresholdWeight,
      adversarialWeight: Number(modifiedManifest.signerWeight),
      remainingWeight,
    },
    modified,
    released,
    adversarialBehavior: {
      directive,
      directiveActivationsInWindow: directiveActivations,
      directiveRejections,
      counters: modifiedCounters,
    },
    healthyAcceptedResponses: healthyAccepted,
    signerMetricDeltas: metrics,
    observations: {
      validationRejections: metrics.validationRejectionsObserved,
      note: metrics.validationRejectionsObserved === 0
        ? 'No current-node validation rejection occurred in the measured window.'
        : 'Current-node validation rejections occurred independently of the deliberate signer directive and require separate triage.',
    },
    startCohort: start,
    endCohort: end,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [configPath, output] = process.argv.slice(2);
  if (!configPath || configPath === '--help') {
    process.stdout.write('usage: mixed-matrix-evidence.mjs CONFIG.json [OUTPUT.json]\n');
    process.exit(configPath === '--help' ? 0 : 2);
  }
  const result = classifyMixedMatrixEvidence(readJson(configPath));
  const encoded = `${JSON.stringify(result, null, 2)}\n`;
  if (output) writeFileSync(output, encoded); else process.stdout.write(encoded);
  if (!result.ok) process.exitCode = 1;
}
