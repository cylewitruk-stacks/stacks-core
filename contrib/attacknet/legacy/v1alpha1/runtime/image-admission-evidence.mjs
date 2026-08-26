#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const DIGEST = /^sha256:[0-9a-f]{64}$/;

function fail(message) { throw new Error(message); }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex')}`;
}
function runtimeDigest(imageID) {
  const match = `${imageID ?? ''}`.match(/(?:^|@)(sha256:[0-9a-f]{64})$/);
  if (!match) fail(`Pod actor imageID is not immutable: ${imageID ?? '<missing>'}`);
  return match[1];
}
function equivalentRef(actual, expected) {
  if (actual === expected) return true;
  return actual === `docker.io/library/${expected}`;
}

export function joinImageAdmissionEvidence({buildRecord, network, pod, actor}) {
  if (buildRecord?.schema !== 'stacks-attacknet-image-build-record/v1') fail('invalid build record schema');
  const sealed = {...buildRecord};
  delete sealed.recordDigest;
  if (!DIGEST.test(buildRecord.recordDigest ?? '') || digest(sealed) !== buildRecord.recordDigest) {
    fail('build record digest is missing or does not verify');
  }
  const identity = buildRecord.imageIdentity;
  if (identity?.imageIndexDigest !== buildRecord.imageDigest
    || !DIGEST.test(identity?.platformManifestDigest ?? '')
    || !DIGEST.test(identity?.expectedRuntimeImageID ?? '')
    || identity.expectedRuntimeImageID !== identity.runtimeConfigDigest) {
    fail('build record image identity is incomplete or inconsistent');
  }
  if (!actor) fail('actor is required');
  if (network?.kind !== 'StacksNetwork') fail('network input is not a StacksNetwork');
  if (network.metadata?.generation !== network.status?.observedGeneration) {
    fail(`StacksNetwork generation ${network.metadata?.generation} is not observed (${network.status?.observedGeneration})`);
  }
  if (network.status?.phase !== 'Ready') fail(`StacksNetwork is ${network.status?.phase ?? 'unknown'}, not Ready`);
  const declarations = (network.spec?.actors ?? []).filter(item => item.name === actor);
  if (declarations.length !== 1) fail(`StacksNetwork must declare actor ${actor} exactly once`);
  const declaration = declarations[0];
  const allowedRefs = [buildRecord.localRef, buildRecord.immutableRef];
  if (!allowedRefs.includes(declaration.image)) {
    fail(`actor ${actor} declares ${declaration.image}, not a reference sealed by the build record`);
  }
  const actorStatus = (network.status?.actors ?? []).find(item => item.name === actor);
  if (!actorStatus?.ready || actorStatus.image !== declaration.image) {
    fail(`StacksNetwork status has not admitted the declared image for Ready actor ${actor}`);
  }
  if (pod?.metadata?.labels?.['testing.stacks.org/actor'] !== actor
    || pod.metadata?.labels?.['testing.stacks.org/network'] !== network.metadata?.name) {
    fail('Pod labels do not bind it to the requested network actor');
  }
  const declaredContainer = (pod.spec?.containers ?? []).find(item => item.name === 'actor');
  const runtimeContainer = (pod.status?.containerStatuses ?? []).find(item => item.name === 'actor');
  if (!declaredContainer || !equivalentRef(declaredContainer.image, declaration.image)) {
    fail('Pod actor container does not declare the StacksNetwork image');
  }
  if (!runtimeContainer?.ready) fail('Pod actor container is not Ready');
  const admittedRuntimeDigest = runtimeDigest(runtimeContainer.imageID);
  if (admittedRuntimeDigest !== identity.expectedRuntimeImageID) {
    fail(`Pod runtime image ${admittedRuntimeDigest} does not match build config ${identity.expectedRuntimeImageID}`);
  }
  const podReady = (pod.status?.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True');
  if (!podReady || pod.status?.phase !== 'Running') fail('Pod is not Running and Ready');
  const evidence = {
    schema: 'stacks-attacknet-image-admission-evidence/v1',
    result: 'Passed',
    build: {
      recordDigest: buildRecord.recordDigest,
      pipelineId: buildRecord.pipelineId,
      profileId: buildRecord.profileId,
      sourceRevision: buildRecord.source?.revision,
      imageIndexDigest: identity.imageIndexDigest,
      platformManifestDigest: identity.platformManifestDigest,
      runtimeConfigDigest: identity.runtimeConfigDigest,
      platform: identity.platform,
    },
    admission: {
      network: network.metadata.name,
      networkUID: network.metadata.uid,
      generation: network.metadata.generation,
      actor,
      declaredImage: declaration.image,
      pod: pod.metadata.name,
      podUID: pod.metadata.uid,
      node: pod.spec?.nodeName,
      containerImage: runtimeContainer.image,
      containerImageID: runtimeContainer.imageID,
      runtimeDigest: admittedRuntimeDigest,
      restartCount: runtimeContainer.restartCount,
    },
  };
  evidence.evidenceDigest = digest(evidence);
  return evidence;
}

function main() {
  const [buildPath, networkPath, podPath, actor, outputPath] = process.argv.slice(2);
  if (!buildPath || !networkPath || !podPath || !actor) {
    fail('usage: image-admission-evidence.mjs BUILD_RECORD NETWORK_JSON POD_JSON ACTOR [OUTPUT]');
  }
  const evidence = joinImageAdmissionEvidence({
    buildRecord: JSON.parse(readFileSync(resolve(buildPath), 'utf8')),
    network: JSON.parse(readFileSync(resolve(networkPath), 'utf8')),
    pod: JSON.parse(readFileSync(resolve(podPath), 'utf8')),
    actor,
  });
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (outputPath) writeFileSync(resolve(outputPath), serialized);
  else process.stdout.write(serialized);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`image-admission-evidence: ${error.message}`);
    process.exitCode = 1;
  }
}
