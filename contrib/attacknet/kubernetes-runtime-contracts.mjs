import {sha256Value} from './run-descriptor.mjs';

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Build the bounded manifest used to correlate declared actors and signer ownership. */
export function networkManifest(network) {
  const metadata = network?.metadata ?? {};
  const actors = network?.spec?.actors;
  if (!metadata.name || !metadata.namespace || !metadata.uid || !Array.isArray(actors)) {
    throw new Error('referenced StacksNetwork is missing admitted identity or actors');
  }
  const signerWeights = new Map();
  const normalized = actors.map(actor => {
    if (!actor.name || !actor.role) throw new Error('StacksNetwork actor lacks name or role');
    const declaresSigner = actor.role === 'signer' || actor.signerIndex !== undefined
      || actor.signerWeight !== undefined || actor.signerPublicKey !== undefined;
    if (actor.signerIndex !== undefined) {
      if (!Number.isInteger(actor.signerIndex) || actor.signerIndex < 1
          || typeof actor.signerWeight !== 'number' || !Number.isFinite(actor.signerWeight)
          || actor.signerWeight <= 0
          || !/^(02|03)[0-9a-f]{64}$/.test(actor.signerPublicKey ?? '')) {
        throw new Error(`actor ${actor.name} has invalid authoritative signer ownership`);
      }
      const prior = signerWeights.get(actor.signerIndex);
      if (prior !== undefined
          && (prior.weight !== actor.signerWeight || prior.publicKey !== actor.signerPublicKey)) {
        throw new Error(`signer ${actor.signerIndex} has inconsistent authoritative weight`);
      }
      signerWeights.set(actor.signerIndex, {weight: actor.signerWeight, publicKey: actor.signerPublicKey});
    } else if (declaresSigner) {
      throw new Error(`actor ${actor.name} has an incomplete authoritative signer identity`);
    }
    return {
      service: actor.name, role: actor.role,
      ...(actor.signerIndex === undefined ? {} : {
        signerIndex: actor.signerIndex, signerWeight: actor.signerWeight,
        signerPublicKey: actor.signerPublicKey,
      }),
    };
  });
  return {schemaVersion: 1, network: metadata.name, namespace: metadata.namespace, actors: normalized};
}

function podReady(pod) {
  return pod?.status?.phase === 'Running'
    && (pod.status.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True')
    && (pod.status.containerStatuses ?? []).some(item => item.name === 'actor' && item.ready === true);
}

/** Resolve every declared actor to one Ready Pod and immutable runtime image. */
export function resolvedNetworkImages(network, pods) {
  const items = pods?.items ?? [];
  return (network.spec?.actors ?? []).map(actor => {
    const matches = items.filter(pod => !pod.metadata?.deletionTimestamp
      && pod.metadata?.labels?.['testing.stacks.org/network'] === network.metadata.name
      && pod.metadata?.labels?.['testing.stacks.org/actor'] === actor.name);
    if (matches.length !== 1 || !podReady(matches[0])) {
      throw new Error(`actor ${actor.name} does not resolve to one Ready admitted Pod`);
    }
    const container = matches[0].status?.containerStatuses?.find(item => item.name === 'actor');
    const resolvedRef = container?.imageID;
    const match = /sha256:[0-9a-f]{64}/.exec(resolvedRef ?? '');
    if (!match) throw new Error(`actor ${actor.name} lacks an immutable admitted image digest`);
    const requestedRef = actor.image ?? network.spec?.defaults?.image;
    if (typeof requestedRef !== 'string' || requestedRef.length === 0) {
      throw new Error(`actor ${actor.name} has no requested image`);
    }
    return {scope: actor.name, requestedRef, resolvedRef, resolvedDigest: match[0]};
  }).sort((left, right) => compareText(left.scope, right.scope));
}

/** Independently reproduce the run controller's bounded terminal classification. */
export function classifyTerminalAssertion(run, children, scheduleDigest) {
  const minimization = run.spec?.minimization;
  const replay = run.spec?.replay;
  const expectation = minimization?.enabled === true ? {
    attemptId: minimization.attemptId,
    candidateScheduleDigest: minimization.candidateScheduleDigest,
    expectedAssertion: minimization.expectedAssertion,
    expectedStatus: minimization.expectedStatus,
  } : replay?.enabled === true && replay.verifyExpectedFailure === true ? {
    attemptId: replay.attemptId,
    candidateScheduleDigest: replay.descriptorDigest,
    expectedAssertion: replay.expectedAssertion,
    expectedStatus: replay.expectedStatus,
  } : null;
  if (!expectation) return null;
  if (!expectation.expectedAssertion || !expectation.expectedStatus || !scheduleDigest) {
    throw new Error('minimization assertion classification lacks an immutable expected assertion or schedule');
  }
  const evidence = children.map(child => ({
    name: child.metadata.name, uid: child.metadata.uid,
    phase: child.status?.phase ?? 'Pending', reason: child.status?.reason ?? '',
    effectResults: child.status?.effectResults ?? [],
    recoveryResults: child.status?.recoveryResults ?? [],
  })).sort((left, right) => compareText(left.name, right.name));
  const observations = evidence.flatMap(child => [
    ...child.effectResults.map(result => ({...result, child: child.name, source: 'effect'})),
    ...child.recoveryResults.map(result => ({...result, child: child.name, source: 'recovery'})),
  ]).filter(result => result.assertion === expectation.expectedAssertion);
  let outcome = 'Inconclusive';
  let reason = 'ExpectedAssertionNotEvaluated';
  if (observations.length > 256) {
    reason = 'AssertionEvidenceLimitExceeded';
  } else if (observations.length > 0 && observations.every(result => result.outcome === expectation.expectedStatus)) {
    outcome = 'FailureReproduced'; reason = 'ExpectedAssertionObserved';
  } else if (observations.some(result => result.outcome === expectation.expectedStatus)) {
    reason = 'ConflictingExpectedAssertionEvidence';
  } else if (observations.length > 0
      && observations.every(result => new Set(['Proven', 'Failed']).has(result.outcome))) {
    outcome = 'FailureAbsent'; reason = 'ExpectedAssertionEvaluatedWithoutExpectedStatus';
  } else if (observations.length > 0) {
    reason = 'ExpectedAssertionInconclusive';
  }
  return {
    ...expectation, outcome, reason, observationCount: observations.length,
    observations: observations.slice(0, 256).map(result => ({
      child: result.child, source: result.source, outcome: result.outcome,
      ...(result.actor ? {actor: result.actor} : {}),
    })),
    evidenceDigest: sha256Value({
      runUID: run.metadata.uid, scheduleDigest, attemptId: expectation.attemptId,
      expectedAssertion: expectation.expectedAssertion, expectedStatus: expectation.expectedStatus, evidence,
    }),
    evidenceURI: `k8s://attacknetruns/${run.metadata.name}/terminal-assertion-evidence`,
    causalMinimalityClaimed: false,
  };
}
