#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const RESULT_SCHEMA = 'stacks-attacknet-release-1-a3-clock-policy/v1';
const zeroOffset = '+0s\n';

function fail(message) {
  throw new Error(message);
}

function kubectl(arguments_, {input, allowFailure = false} = {}) {
  try {
    return execFileSync(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, {
      cwd: repositoryRoot,
      encoding: 'utf8',
      input,
      maxBuffer: 16 << 20,
      stdio: ['pipe', 'pipe', allowFailure ? 'pipe' : 'inherit'],
    });
  } catch (error) {
    if (allowFailure) return undefined;
    throw error;
  }
}

function getJSON(namespace, kind, name) {
  return JSON.parse(kubectl(['-n', namespace, 'get', kind, name, '-o', 'json']));
}

function getOptionalJSON(namespace, kind, name) {
  const value = kubectl(['-n', namespace, 'get', kind, name, '-o', 'json', '--ignore-not-found']);
  return value.trim() ? JSON.parse(value) : undefined;
}

function patchPolicy(namespace, name, actor, value) {
  kubectl(['-n', namespace, 'patch', 'configmap', name, '--type=merge', '--patch', JSON.stringify({data: {[actor]: value}})]);
}

function sleep(milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(250, deadline - Date.now()));
}

function waitFor(namespace, kind, name, predicate, timeoutSeconds, label) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = getOptionalJSON(namespace, kind, name);
    if (predicate(last)) return last;
    sleep(1000);
  }
  fail(`${label} did not converge within ${timeoutSeconds}s; last value: ${JSON.stringify(last?.status ?? last)}`);
}

function immutableImageID(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable sha256 image ID`);
  return value;
}

function activeCampaigns(namespace, network) {
  const terminal = new Set(['Failed', 'Inconclusive', 'Passed']);
  const list = JSON.parse(kubectl(['-n', namespace, 'get', 'faultcampaigns.testing.stacks.org', '-o', 'json']));
  return list.items.filter(item => item.spec?.networkRef === network && !item.spec?.template
    && !terminal.has(item.status?.phase));
}

/** Validate the fail-closed result before it is recorded as passed evidence. */
export function validateClockPolicyProof(result) {
  if (result?.schema !== RESULT_SCHEMA || result.outcome !== 'Passed') fail('clock-policy proof is not passed A3 evidence');
  if (!/^[0-9a-f]{40}$/.test(result.candidateRevision ?? '')) fail('clock-policy proof does not pin a candidate');
  if (!/^kind-/.test(result.cluster?.context ?? '') || result.cluster?.nodes?.length !== 3
    || result.cluster.nodes.some(node => !String(node.providerID).startsWith('kind://docker/')
      || node.operatingSystem !== 'linux' || node.architecture !== 'arm64')) {
    fail('clock-policy proof did not run on the supported three-node arm64 kind profile');
  }
  if (result.network?.phase !== 'Ready' || result.network.inventoryReady !== true
    || !/^sha256:[0-9a-f]{64}$/.test(result.network.inventoryDigest ?? '')) {
    fail('clock-policy proof did not use a complete admitted network inventory');
  }
  immutableImageID(result.candidateRuntime?.expectedRuntimeImageID, 'expectedRuntimeImageID');
  if (!/^[0-9a-f]{40}$/.test(result.candidateRuntime?.operatorContextTree ?? '')) {
    fail('clock-policy proof omits the candidate operator context tree');
  }
  if (result.candidateRuntime.runtimeImageID !== result.candidateRuntime.expectedRuntimeImageID
    || result.candidateRuntime.buildAnnotation !== result.candidateRuntime.expectedImageIndex) {
    fail('clock-policy proof did not run the expected candidate controller image');
  }
  if (result.campaign?.phase !== 'Failed' || result.campaign.reason !== 'FaultCapabilityUnavailable'
    || !String(result.campaign.message).includes('application clock policy is not globally at zero offset')) {
    fail('contaminated shared policy did not fail at capability admission');
  }
  const capability = result.campaign.capabilityEvidence?.[0];
  if (capability?.supported !== false
    || capability.reason !== 'application clock policy is not globally at zero offset') {
    fail('campaign omitted the expected negative capability evidence');
  }
  if (result.observedDuringFailure?.target !== zeroOffset
    || result.observedDuringFailure?.control === zeroOffset) {
    fail('campaign mutated the policy despite failed capability admission');
  }
  if (result.cleanup?.campaignAbsent !== true || result.cleanup?.mutationLeaseAbsent !== true
    || result.cleanup?.policyRestored !== true) {
    fail('clock-policy proof did not cleanly restore the test environment');
  }
  return result;
}

/** Exercise the signed run operator against a deliberately contaminated policy. */
export function runClockPolicyProof({
  candidateRevision,
  namespace,
  network,
  runDeployment,
  target,
  control,
  output,
  expectedRuntimeImageID,
  expectedImageIndex,
  operatorContextTree,
  timeoutSeconds = 120,
}) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) fail('candidate must be a full Git SHA');
  if (!/^[0-9a-f]{40}$/.test(operatorContextTree ?? '')) fail('operator context tree must be a full Git object ID');
  immutableImageID(expectedRuntimeImageID, 'expected runtime image ID');
  immutableImageID(expectedImageIndex, 'expected image index');
  if (activeCampaigns(namespace, network).length > 0) fail('the network has another active FaultCampaign');

  const networkObject = getJSON(namespace, 'stacksnetwork.testing.stacks.org', network);
  if (networkObject.status?.phase !== 'Ready' || networkObject.status?.inventoryReady !== true
    || networkObject.status?.observedGeneration !== networkObject.metadata?.generation) {
    fail('StacksNetwork is not ready at its current generation');
  }
  const policyName = `${network}-clock-policy`;
  const policy = getJSON(namespace, 'configmap', policyName);
  if (policy.metadata?.labels?.['testing.stacks.org/network'] !== network
    || policy.metadata?.labels?.['testing.stacks.org/clock-policy'] !== 'true') {
    fail('clock policy identity labels are invalid');
  }
  if (target === control || policy.data?.[target] !== zeroOffset || policy.data?.[control] !== zeroOffset) {
    fail('target and distinct control must both begin at zero offset');
  }
  const environment = getJSON(namespace, 'configmap', 'attacknet-environment-lease');
  if (environment.data?.network !== network) fail('the active environment lease belongs to another network');

  const runDeploymentObject = getJSON(namespace, 'deployment.apps', runDeployment);
  const runSelector = Object.entries(runDeploymentObject.spec.selector.matchLabels)
    .map(([key, value]) => `${key}=${value}`).join(',');
  const runPods = JSON.parse(kubectl(['-n', namespace, 'get', 'pods', '-l', runSelector, '-o', 'json'])).items;
  if (runPods.length !== 1 || !runPods[0].status?.containerStatuses?.[0]?.ready) {
    fail('exactly one Ready run-operator Pod is required');
  }
  const runPod = runPods[0];
  const runtimeImageID = immutableImageID(
    String(runPod.status.containerStatuses[0].imageID).replace(/^.*@(?=sha256:)/, ''),
    'run-operator runtime image ID',
  );
  const buildAnnotation = runPod.metadata.annotations?.['testing.stacks.org/build-index'];
  if (runtimeImageID !== expectedRuntimeImageID || buildAnnotation !== expectedImageIndex) {
    fail('admitted run-operator Pod does not match the expected candidate image');
  }

  const campaignName = `a3-clock-policy-${candidateRevision.slice(0, 12)}`;
  if (getOptionalJSON(namespace, 'faultcampaign.testing.stacks.org', campaignName)) {
    fail(`FaultCampaign ${campaignName} already exists`);
  }
  const campaign = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'FaultCampaign',
    metadata: {name: campaignName, namespace},
    spec: {
      networkRef: network,
      target: {actors: [target]},
      fault: {
        type: 'clock-skew', mode: 'all', duration: '5s',
        parameters: {timeOffset: '-30s', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor']},
      },
      safety: {maxUnavailableSignerPercent: 30, maxUnavailableMinerPercent: 50},
      effectAssertions: [{type: 'ClockSkewObserved', timeoutSeconds: 30}],
      recoveryAssertions: [{type: 'ClockSkewCleared', timeoutSeconds: 30}],
    },
  };
  let terminal;
  let observedDuringFailure;
  let cleanup = {campaignAbsent: false, mutationLeaseAbsent: false, policyRestored: false};
  try {
    patchPolicy(namespace, policyName, control, '+1s\n');
    kubectl(['create', '-f', '-'], {input: JSON.stringify(campaign)});
    terminal = waitFor(namespace, 'faultcampaign.testing.stacks.org', campaignName,
      value => value?.status?.phase === 'Failed', timeoutSeconds, 'clock policy campaign');
    const during = getJSON(namespace, 'configmap', policyName);
    observedDuringFailure = {target: during.data[target], control: during.data[control]};
    waitFor(namespace, 'configmap', 'attacknet-mutation-lease', value => value === undefined,
      timeoutSeconds, 'mutation lease cleanup');
  } finally {
    kubectl(['-n', namespace, 'delete', 'faultcampaign.testing.stacks.org', campaignName,
      '--ignore-not-found', '--wait=true', `--timeout=${timeoutSeconds}s`], {allowFailure: true});
    patchPolicy(namespace, policyName, control, zeroOffset);
    const restored = getJSON(namespace, 'configmap', policyName);
    cleanup = {
      campaignAbsent: getOptionalJSON(namespace, 'faultcampaign.testing.stacks.org', campaignName) === undefined,
      mutationLeaseAbsent: getOptionalJSON(namespace, 'configmap', 'attacknet-mutation-lease') === undefined,
      policyRestored: restored.data[target] === zeroOffset && restored.data[control] === zeroOffset,
    };
  }

  const result = validateClockPolicyProof({
    schema: RESULT_SCHEMA,
    candidateRevision,
    outcome: 'Passed',
    capturedAt: new Date().toISOString(),
    cluster: {
      context: kubectl(['config', 'current-context']).trim(),
      nodes: JSON.parse(kubectl(['get', 'nodes', '-o', 'json'])).items.map(node => ({
        name: node.metadata.name,
        providerID: node.spec.providerID,
        operatingSystem: node.status.nodeInfo.operatingSystem,
        architecture: node.status.nodeInfo.architecture,
      })),
    },
    network: {
      name: network,
      uid: networkObject.metadata.uid,
      generation: networkObject.metadata.generation,
      observedGeneration: networkObject.status.observedGeneration,
      phase: networkObject.status.phase,
      inventoryReady: networkObject.status.inventoryReady,
      inventoryDigest: networkObject.status.inventoryDigest,
    },
    candidateRuntime: {
      component: 'run-operator',
      pod: runPod.metadata.name,
      podUID: runPod.metadata.uid,
      requestedImage: runPod.spec.containers[0].image,
      runtimeImageID,
      expectedRuntimeImageID,
      buildAnnotation,
      expectedImageIndex,
      operatorContextTree,
    },
    policy: {name: policyName, target, control},
    campaign: {
      name: campaignName,
      uid: terminal.metadata.uid,
      phase: terminal.status.phase,
      reason: terminal.status.reason,
      message: terminal.status.message,
      capabilityEvidence: (terminal.status.capabilityEvidence ?? []).map(value => (
        typeof value === 'string' ? JSON.parse(value) : value
      )),
      cleanup: terminal.status.cleanup,
    },
    observedDuringFailure,
    cleanup,
  });
  writeFileSync(resolve(output), `${JSON.stringify(result, null, 2)}\n`);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = [
    '--candidate=', '--namespace=', '--network=', '--run-deployment=', '--target=', '--control=', '--output=',
    '--expected-runtime-image-id=', '--expected-image-index=', '--timeout-seconds=',
    '--operator-context-tree=',
  ];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  const options = {
    candidateRevision: value('--candidate='),
    namespace: value('--namespace='),
    network: value('--network='),
    runDeployment: value('--run-deployment='),
    target: value('--target='),
    control: value('--control='),
    output: value('--output='),
    expectedRuntimeImageID: value('--expected-runtime-image-id='),
    expectedImageIndex: value('--expected-image-index='),
    operatorContextTree: value('--operator-context-tree='),
    timeoutSeconds: Number(value('--timeout-seconds=') ?? 120),
  };
  for (const [name, option] of Object.entries(options)) if (name !== 'timeoutSeconds' && !option) fail(`${name} is required`);
  if (!Number.isSafeInteger(options.timeoutSeconds) || options.timeoutSeconds < 30 || options.timeoutSeconds > 600) {
    fail('timeout-seconds must be an integer from 30 through 600');
  }
  runClockPolicyProof(options);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
