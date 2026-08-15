#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';

const NETWORK_LABEL = 'testing.stacks.org/network';
const ACTOR_LABEL = 'testing.stacks.org/actor';
const ROLE_LABEL = 'testing.stacks.org/role';

export function resolveCampaignTargets(manifest, evidence, podList) {
  const selected = evidence?.selectedActors;
  if (!Array.isArray(selected) || selected.length === 0
      || selected.some(actor => typeof actor !== 'string' || actor.length === 0)) {
    throw new Error('campaign evidence must contain at least one selected actor');
  }
  if (!Array.isArray(podList?.items)) throw new Error('admitted Pod list is malformed');
  const records = selected.map(actor => {
    const matches = podList.items.filter(pod => {
      const metadata = pod.metadata ?? {};
      const labels = metadata.labels ?? {};
      return !metadata.deletionTimestamp
        && labels[NETWORK_LABEL] === manifest.network
        && labels[ACTOR_LABEL] === actor;
    });
    if (matches.length !== 1) {
      throw new Error(`selected actor ${actor} resolves to ${matches.length} admitted Pods`);
    }
    const pod = matches[0];
    const metadata = pod.metadata ?? {};
    const status = pod.status ?? {};
    const actorStatus = (status.containerStatuses ?? []).find(item => item.name === 'actor');
    const ready = (status.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True');
    if (status.phase !== 'Running' || !ready || !actorStatus?.ready) {
      throw new Error(`selected actor ${actor} is not admitted Running and Ready`);
    }
    if (!metadata.uid || !metadata.name || !pod.spec?.nodeName || !status.podIP) {
      throw new Error(`selected actor ${actor} lacks Pod uid, name, IP, or node placement`);
    }
    return {
      actor,
      role: (metadata.labels ?? {})[ROLE_LABEL] ?? 'unknown',
      pod: metadata.name,
      podUid: metadata.uid,
      podIP: status.podIP,
      node: pod.spec.nodeName,
      requestedImage: actorStatus.image ?? null,
      resolvedImageId: actorStatus.imageID ?? null,
      restartCount: Number(actorStatus.restartCount ?? 0),
    };
  });
  return {
    schemaVersion: 1,
    network: manifest.network,
    namespace: manifest.namespace,
    resolvedAt: new Date().toISOString(),
    targets: records,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [manifestPath, evidencePath, podsPath, outputPath] = process.argv.slice(2);
  if (!manifestPath || !evidencePath || !podsPath || !outputPath) {
    throw new Error('usage: campaign-targets.mjs MANIFEST EVIDENCE PODS OUTPUT');
  }
  const result = resolveCampaignTargets(
    JSON.parse(readFileSync(manifestPath, 'utf8')),
    JSON.parse(readFileSync(evidencePath, 'utf8')),
    JSON.parse(readFileSync(podsPath, 'utf8')),
  );
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
}
