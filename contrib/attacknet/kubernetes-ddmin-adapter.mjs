#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';

import {
  classifyTerminalAssertion, networkManifest, resolvedNetworkImages,
} from '../helm/hacknet/run-operator/controller.mjs';
import {describeDdminCandidate} from './attacknet-run-schedule.mjs';
import {
  admittedInputContract, evidenceDigestFor, executeDdmin,
} from './ddmin-executor.mjs';
import {readManifestIdentity} from './manifest-identity.mjs';
import {canonicalJson, sha256Value} from './run-descriptor.mjs';

const TERMINAL = new Set(['Passed', 'Failed', 'Inconclusive']);
const ACTIVE = new Set(['Pending', 'Preparing', 'Running', 'Minimizing']);

function object(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function string(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function integer(value, field, {minimum = 0, maximum = Number.MAX_SAFE_INTEGER} = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${field} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  const temporary = join(dirname(path), `.${path.split('/').at(-1)}.${process.pid}.tmp`);
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
  renameSync(temporary, path);
}

function safeName(value) {
  const name = value.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  if (name.length <= 63) return name;
  return `${name.slice(0, 50).replace(/-+$/g, '')}-${sha256Value(name).slice(7, 19)}`;
}

export class ProcessRunner {
  run(command, args, {env = {}, input, allowFailure = false} = {}) {
    const result = spawnSync(command, args, {
      encoding: 'utf8', input,
      env: {...process.env, ...env},
      maxBuffer: 32 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    if (!allowFailure && result.status !== 0) {
      throw new Error(`${command} ${args.join(' ')} failed (${result.status}): ${result.stderr.trim()}`);
    }
    return {status: result.status, stdout: result.stdout, stderr: result.stderr};
  }
}

export class KubernetesDdminAdapter {
  constructor(config, runner = new ProcessRunner()) {
    object(config, 'adapter config');
    this.namespace = string(config.namespace, 'adapter config.namespace');
    this.network = string(config.network, 'adapter config.network');
    this.sourceRunRef = string(config.sourceRunRef, 'adapter config.sourceRunRef');
    this.generatedDirectory = resolve(string(config.generatedDirectory, 'adapter config.generatedDirectory'));
    this.timeoutSeconds = integer(config.timeoutSeconds ?? 7200, 'adapter config.timeoutSeconds', {minimum: 60, maximum: 86400});
    this.pollSeconds = integer(config.pollSeconds ?? 5, 'adapter config.pollSeconds', {minimum: 1, maximum: 60});
    // Executable paths are implementation-owned, not agent-provided input.
    // The bounded config may select evidence/topology inputs, never a command.
    this.kubectl = 'kubectl';
    this.attacknetDirectory = dirname(fileURLToPath(import.meta.url));
    this.runner = runner;
    this.sourceRun = null;
    this.sourceSchedule = null;
  }

  kube(args, options = {}) {
    return this.runner.run(this.kubectl, ['-n', this.namespace, ...args], options);
  }

  getJson(resource, name) {
    return JSON.parse(this.kube(['get', resource, name, '-o', 'json']).stdout);
  }

  listJson(resource, labels) {
    const args = ['get', resource, ...(labels ? ['-l', labels] : []), '-o', 'json'];
    return JSON.parse(this.kube(args).stdout);
  }

  networkExists() {
    const result = this.kube(['get', 'stacksnetwork', this.network, '-o', 'name'], {allowFailure: true});
    if (result.status === 0) return true;
    if (result.status === 1 && /\bNotFound\b/.test(result.stderr)) return false;
    throw new Error(`could not determine whether source network exists: ${result.stderr.trim()}`);
  }

  loadSource() {
    const run = this.getJson('attacknetrun', this.sourceRunRef);
    if (!TERMINAL.has(run.status?.phase)) throw new Error('source AttacknetRun must be terminal');
    const reference = object(run.status?.scheduleRef, 'source AttacknetRun status.scheduleRef');
    const configMap = this.getJson('configmap', string(reference.name, 'source schedule ConfigMap name'));
    const owner = configMap.metadata?.ownerReferences?.find(item => item.controller === true);
    if (!owner || owner.uid !== run.metadata.uid || configMap.metadata.uid !== reference.uid) {
      throw new Error('source schedule ConfigMap ownership or UID changed');
    }
    const payload = configMap.binaryData?.['schedule.json.gz'];
    if (!payload) throw new Error('source schedule ConfigMap lacks schedule.json.gz');
    const schedule = JSON.parse(gunzipSync(Buffer.from(payload, 'base64')).toString('utf8'));
    if (schedule.integrity?.digest !== reference.digest) throw new Error('source schedule digest changed');
    if (configMap.metadata.annotations?.['testing.stacks.org/schedule-digest'] !== reference.digest) {
      throw new Error('source schedule ConfigMap digest annotation changed');
    }
    if (schedule.network?.name !== this.network || run.spec?.networkRef !== this.network) {
      throw new Error('source run and schedule must use the configured logical network name');
    }
    this.sourceRun = run;
    this.sourceSchedule = schedule;
    return {run, schedule};
  }

  storagePreflight({evidenceDirectory}) {
    const path = join(evidenceDirectory, 'storage-preflight.json');
    const result = this.runner.run(join(this.attacknetDirectory, 'observability', 'storage-preflight.sh'), [path], {
      env: {KUBE_NAMESPACE: this.namespace}, allowFailure: true,
    });
    if (result.status !== 0 && !readFileSync(path, {encoding: 'utf8', flag: 'r'})) {
      throw new Error(`storage preflight failed without a report: ${result.stderr.trim()}`);
    }
    const report = JSON.parse(readFileSync(path, 'utf8'));
    return {...report, evidenceDigest: evidenceDigestFor(report)};
  }

  assertExclusive({maxActive}) {
    if (maxActive !== 1) throw new Error('Kubernetes ddmin supports maxActive=1 only');
    const active = this.listJson('attacknetruns').items
      .filter(run => ACTIVE.has(run.status?.phase ?? 'Pending'));
    if (active.length > 0) {
      throw new Error(`refusing to start a second active AttacknetRun beside: ${active.map(run => run.metadata.name).join(', ')}`);
    }
  }

  captureSourceEvidence(evidenceDirectory) {
    const directory = join(evidenceDirectory, 'source');
    mkdirSync(directory, {recursive: true});
    const network = this.getJson('stacksnetwork', this.network);
    const campaigns = this.listJson('faultcampaigns', `testing.stacks.org/run=${this.sourceRunRef}`);
    const receipt = {
      sourceRun: this.sourceRun,
      sourceSchedule: this.sourceSchedule,
      network,
      campaigns,
    };
    atomicWrite(join(directory, 'source-evidence.json'), receipt);
    const digest = evidenceDigestFor(receipt);
    atomicWrite(join(directory, 'receipt.json'), {
      schemaVersion: 'stacks-attacknet-source-evidence/v1', digest,
      uri: `file://${join(directory, 'source-evidence.json')}`,
    });
    return digest;
  }

  verifySourceEvidence(evidenceDirectory) {
    if (!this.sourceRun || !this.sourceSchedule) throw new Error('source run was not loaded');
    const directory = join(evidenceDirectory, 'source');
    const evidencePath = join(directory, 'source-evidence.json');
    const receiptPath = join(directory, 'receipt.json');
    const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
    const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
    if (receipt.schemaVersion !== 'stacks-attacknet-source-evidence/v1'
        || receipt.uri !== `file://${evidencePath}`
        || receipt.digest !== evidenceDigestFor(evidence)) {
      throw new Error('source evidence receipt is missing, moved, or does not match its payload');
    }
    if (evidence.sourceRun?.metadata?.uid !== this.sourceRun.metadata.uid
        || evidence.sourceSchedule?.integrity?.digest !== this.sourceSchedule.integrity.digest
        || evidence.network?.metadata?.uid !== this.sourceSchedule.network.uid
        || evidence.network?.metadata?.name !== this.network) {
      throw new Error('source evidence does not identify the loaded source run, schedule, and network');
    }
    return receipt.digest;
  }

  validateRenderedNetwork(contract) {
    const identity = readManifestIdentity(this.generatedDirectory);
    if (identity.network !== this.network || identity.namespace !== this.namespace) {
      throw new Error('rendered network identity differs from the configured ddmin environment');
    }
    const rendered = JSON.parse(readFileSync(join(this.generatedDirectory, 'stacksnetwork.json'), 'utf8'));
    rendered.metadata.uid = 'pre-admission-ddmin-validation';
    rendered.metadata.generation ??= 1;
    const manifestDigest = sha256Value(networkManifest(rendered));
    if (manifestDigest !== contract.manifestDigest) {
      throw new Error('rendered StacksNetwork manifest differs from the source before teardown');
    }
    const requested = new Map(this.sourceSchedule.imageConstraints.map(image => [image.scope, image.requestedRef]));
    for (const actor of rendered.spec?.actors ?? []) {
      const image = actor.image ?? rendered.spec?.defaults?.image;
      if (requested.get(actor.name) !== image) {
        throw new Error(`rendered actor ${actor.name} requested image differs from the source before teardown`);
      }
    }
  }

  recreateNetwork({attempt, contract, attemptDirectory, evidenceDirectory}) {
    if (!this.sourceRun || !this.sourceSchedule) throw new Error('source run was not loaded');
    this.validateRenderedNetwork(contract);
    const sourceRoot = resolve(string(evidenceDirectory, 'recreateNetwork evidenceDirectory'));
    const sourceReceipt = join(sourceRoot, 'source', 'receipt.json');
    const sourceEvidence = join(sourceRoot, 'source', 'source-evidence.json');
    if (!existsSync(sourceReceipt) && !existsSync(sourceEvidence)) {
      this.captureSourceEvidence(sourceRoot);
    } else if (!existsSync(sourceReceipt) || !existsSync(sourceEvidence)) {
      throw new Error('source evidence is incomplete; refusing to recapture over a partial record');
    }
    this.verifySourceEvidence(sourceRoot);
    const lifecycle = join(this.attacknetDirectory, 'lifecycle.sh');
    const common = {
      KUBE_NAMESPACE: this.namespace,
      KUBE_NETWORK: this.network,
      ATTACKNET_LOCK_OWNER: `ddmin:${attempt.id}`,
    };
    if (this.networkExists()) {
      this.runner.run(lifecycle, ['delete'], {env: {
        ...common,
        ATTACKNET_RUN_FINAL_STATUS: 'aborted',
        ATTACKNET_RUN_EXPORT_DIR: join(attemptDirectory, 'prior-network-export'),
      }});
    }
    this.runner.run(lifecycle, ['apply', this.generatedDirectory], {env: {
      ...common,
      ATTACKNET_RUN_ID: `${attempt.id}-network`,
      ATTACKNET_RUN_SEED: this.sourceRun.spec.seed,
    }});
    const network = this.getJson('stacksnetwork', this.network);
    const manifest = networkManifest(network);
    const pods = this.listJson('pods', `testing.stacks.org/network=${this.network}`);
    const images = resolvedNetworkImages(network, pods);
    const sourceTemplates = new Map([...new Set(this.sourceSchedule.actions.map(action => action.source.name))]
      .map(name => [name, this.getJson('faultcampaign', name)]));
    const templatesDigest = sha256Value(this.sourceSchedule.actions.map(action => ({
      name: action.source.name, uid: action.source.uid,
      generation: action.source.generation, specDigest: action.source.specDigest,
    })).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))));
    const actualTemplateDigest = sha256Value(this.sourceSchedule.actions.map(action => {
      const template = sourceTemplates.get(action.source.name);
      return {
      name: template.metadata.name, uid: template.metadata.uid,
      generation: template.metadata.generation,
      specDigest: sha256Value(template.spec),
      };
    }).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))));
    if (templatesDigest !== actualTemplateDigest) throw new Error('fresh network campaign templates changed');
    return {
      uid: network.metadata.uid,
      generation: network.metadata.generation,
      cleanStart: true,
      logicalNetworkName: network.metadata.name,
      manifestDigest: sha256Value(manifest),
      imagesDigest: sha256Value(images),
      sourceTemplatesDigest: actualTemplateDigest,
    };
  }

  submitRun({attempt, admitted}) {
    const reduction = describeDdminCandidate(this.sourceSchedule, attempt.schedule);
    const value = structuredClone(this.sourceRun);
    delete value.status;
    value.metadata = {
      name: safeName(`${this.sourceRunRef}-${attempt.id}`), namespace: this.namespace,
      labels: {
        'testing.stacks.org/network': this.network,
        'testing.stacks.org/ddmin-source-run': this.sourceRunRef,
        'testing.stacks.org/ddmin-attempt': attempt.id,
      },
    };
    value.spec.stopPolicy = {
      ...value.spec.stopPolicy,
      onCampaignFailure: 'Stop', onInconclusive: 'Stop', onBudgetExhausted: 'Stop', onSuccess: 'Continue',
    };
    value.spec.replay = {enabled: false, requireSameResolvedImages: true, verifyExpectedFailure: true};
    value.spec.resume = {enabled: false, requireSameSeed: true, requireSameResolvedImages: true};
    value.spec.minimization = {
      enabled: true, strategy: 'DeltaDebug', maxAttempts: 1, requireFreshNetwork: true,
      sourceRunRef: this.sourceRunRef,
      sourceScheduleDigest: reduction.sourceScheduleDigest,
      attemptId: attempt.id,
      candidateScheduleDigest: reduction.candidateScheduleDigest,
      expectedAssertion: attempt.expectedFailure.assertion,
      expectedStatus: attempt.expectedFailure.status,
      retained: reduction.retained,
    };
    return this.createAndWaitForSchedule(value, reduction.candidateScheduleDigest, admitted);
  }

  submitReplay({attempt, admitted}) {
    const value = structuredClone(this.sourceRun);
    delete value.status;
    value.metadata = {
      name: safeName(`${this.sourceRunRef}-${attempt.id}`), namespace: this.namespace,
      labels: {
        'testing.stacks.org/network': this.network,
        'testing.stacks.org/replay-source-run': this.sourceRunRef,
        'testing.stacks.org/replay-attempt': attempt.id,
      },
    };
    value.spec.stopPolicy = {
      ...value.spec.stopPolicy,
      onCampaignFailure: 'Stop', onInconclusive: 'Stop', onBudgetExhausted: 'Stop', onSuccess: 'Continue',
    };
    value.spec.replay = {
      enabled: true,
      sourceRunRef: this.sourceRunRef,
      descriptorURI: `k8s://attacknetruns/${this.sourceRunRef}/resolved-schedule`,
      descriptorDigest: this.sourceSchedule.integrity.digest,
      attemptId: attempt.id,
      expectedAssertion: attempt.expectedFailure.assertion,
      expectedStatus: attempt.expectedFailure.status,
      requireSameResolvedImages: true,
      verifyExpectedFailure: true,
    };
    value.spec.resume = {enabled: false, requireSameSeed: true, requireSameResolvedImages: true};
    value.spec.minimization = {
      enabled: false, strategy: 'DeltaDebug', maxAttempts: 0, requireFreshNetwork: true,
    };
    return this.createAndWaitForSchedule(value, this.sourceSchedule.integrity.digest, admitted);
  }

  createAndWaitForSchedule(value, candidateScheduleDigest, admitted) {
    const created = JSON.parse(this.kube(['create', '-f', '-', '-o', 'json'], {
      input: `${JSON.stringify(value)}\n`,
    }).stdout);
    const deadline = Date.now() + this.timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      const current = this.getJson('attacknetrun', created.metadata.name);
      if (current.status?.scheduleRef) {
        return {
          name: current.metadata.name,
          uid: current.metadata.uid,
          scheduleDigest: current.status.scheduleRef.digest,
          candidateScheduleDigest,
          freshNetworkUID: admitted.uid,
        };
      }
      if (TERMINAL.has(current.status?.phase)) {
        throw new Error(`ddmin AttacknetRun failed admission: ${current.status.reason ?? current.status.phase}`);
      }
      this.runner.run('sleep', [String(this.pollSeconds)]);
    }
    throw new Error('timed out waiting for ddmin AttacknetRun schedule admission');
  }

  waitForRun({run}) {
    const deadline = Date.now() + this.timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      const current = this.getJson('attacknetrun', run.name);
      if (TERMINAL.has(current.status?.phase) || current.status?.phase === 'Paused') return current;
      this.runner.run('sleep', [String(this.pollSeconds)]);
    }
    return {metadata: {name: run.name, uid: run.uid}, status: {
      phase: 'Inconclusive', reason: 'ExecutorWaitTimeout',
    }};
  }

  exportEvidence({attempt, admitted, run, terminal, attemptDirectory}) {
    const campaigns = this.listJson('faultcampaigns', `testing.stacks.org/run=${run.name}`);
    const network = this.getJson('stacksnetwork', this.network);
    const pods = this.listJson('pods', `testing.stacks.org/network=${this.network}`);
    const evidence = {
      schemaVersion: 'stacks-attacknet-ddmin-attempt-evidence/v1',
      attempt: {id: attempt.id, candidateDigest: attempt.schedule.integrity.digest},
      admitted, run, terminal, network, campaigns, pods,
    };
    const path = join(attemptDirectory, 'evidence.json');
    atomicWrite(path, evidence);
    const evidenceDigest = evidenceDigestFor(evidence);
    const classification = terminal.status?.terminalClassification;
    let locallyVerifiedClassification = false;
    if (classification) {
      const recomputed = classifyTerminalAssertion(terminal, campaigns.items, run.scheduleDigest);
      locallyVerifiedClassification = canonicalJson(recomputed) === canonicalJson(classification);
    }
    let verdict;
    if (!classification || !locallyVerifiedClassification || classification.attemptId !== attempt.id
        || classification.candidateScheduleDigest !== attempt.schedule.integrity.digest) {
      verdict = {
        expectedFailureObserved: null, assertionEvaluated: false,
        experimentCompleted: TERMINAL.has(terminal.status?.phase),
        reason: 'MissingOrMismatchedTrustedTerminalClassification',
      };
    } else if (classification.outcome === 'FailureReproduced') {
      verdict = {
        expectedFailureObserved: true, assertionEvaluated: true, experimentCompleted: true,
        assertion: classification.expectedAssertion, status: classification.expectedStatus,
      };
    } else if (classification.outcome === 'FailureAbsent') {
      verdict = {
        expectedFailureObserved: false, assertionEvaluated: true, experimentCompleted: true,
        assertion: classification.expectedAssertion, status: 'absent',
      };
    } else {
      verdict = {
        expectedFailureObserved: null, assertionEvaluated: classification.observations?.length > 0,
        experimentCompleted: TERMINAL.has(terminal.status?.phase), reason: classification.reason,
      };
    }
    atomicWrite(join(attemptDirectory, 'evidence-receipt.json'), {
      evidenceDigest, evidenceURI: `file://${path}`,
      terminalClassificationDigest: classification?.evidenceDigest ?? null,
      terminalClassificationLocallyVerified: locallyVerifiedClassification,
    });
    return {
      evidenceExported: true, evidenceDigest, evidenceURI: `file://${path}`, verdict,
    };
  }

  deleteAttemptNetwork({attempt, run, attemptDirectory}) {
    // Foreground cascading waits for controller-owned FaultCampaign finalizers
    // to remove their Chaos resources before this network can be called clean.
    this.kube(['delete', 'attacknetrun', run.name, '--cascade=foreground', '--wait=true']);
    this.runner.run(join(this.attacknetDirectory, 'lifecycle.sh'), ['delete'], {env: {
      KUBE_NAMESPACE: this.namespace,
      KUBE_NETWORK: this.network,
      ATTACKNET_LOCK_OWNER: `ddmin:${attempt.id}:cleanup`,
      ATTACKNET_RUN_FINAL_STATUS: 'passed',
      ATTACKNET_RUN_EXPORT_DIR: join(attemptDirectory, 'network-export'),
    }});
  }

  preserveForTriage({attempt, admitted, reason, attemptDirectory}) {
    atomicWrite(join(attemptDirectory, 'PRESERVED-FOR-TRIAGE.json'), {
      attemptId: attempt.id,
      networkUID: admitted?.uid ?? null,
      reason,
      statement: 'The executor intentionally made no teardown request after an unexplained or inconclusive result.',
    });
  }
}

export function createAdapter(config, runner) {
  return new KubernetesDdminAdapter(config, runner);
}

export async function runKubernetesDdmin(config, runner = new ProcessRunner()) {
  const adapter = new KubernetesDdminAdapter(config.adapter ?? config, runner);
  const {schedule} = adapter.loadSource();
  const contract = admittedInputContract(schedule);
  if (contract.logicalNetworkName !== adapter.network) throw new Error('source contract network mismatch');
  const expectedFailure = object(config.expectedFailure, 'config.expectedFailure');
  if (!new Set(['Proven', 'Failed', 'Inconclusive']).has(expectedFailure.status)) {
    throw new Error('config.expectedFailure.status must be Proven, Failed, or Inconclusive');
  }
  return executeDdmin({
    schedule,
    expectedFailure,
    maxAttempts: integer(config.maxAttempts, 'config.maxAttempts', {minimum: 1, maximum: 64}),
    evidenceDirectory: string(config.evidenceDirectory, 'config.evidenceDirectory'),
  }, adapter);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  if (!path) {
    process.stderr.write('usage: kubernetes-ddmin-adapter.mjs CONFIG\n');
    process.exitCode = 2;
  } else {
    runKubernetesDdmin(JSON.parse(readFileSync(path, 'utf8'))).then(result => {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    }).catch(error => {
      process.stderr.write(`${error.stack ?? error}\n`);
      process.exitCode = 1;
    });
  }
}
