#!/usr/bin/env node

import {readFileSync} from 'node:fs';

function readyCondition(pod) {
  return pod.status?.conditions?.find(condition => condition.type === 'Ready')?.status === 'True';
}

export function actorStateEvents(podList) {
  if (!Array.isArray(podList?.items)) throw new Error('PodList items are required');
  return podList.items.flatMap(pod => {
    const labels = pod.metadata?.labels ?? {};
    const actor = labels['testing.stacks.org/actor'];
    if (!actor) return [];
    const statuses = pod.status?.containerStatuses ?? [];
    return [{
      actor,
      role: labels['testing.stacks.org/role'] ?? 'unknown',
      details: {
        ready: readyCondition(pod),
        restarts: statuses.reduce((sum, status) => sum + Number(status.restartCount ?? 0), 0),
        pod: pod.metadata?.name ?? 'unknown',
        podUid: pod.metadata?.uid ?? 'unknown',
        node: pod.spec?.nodeName ?? 'unassigned',
        phase: pod.status?.phase ?? 'Unknown',
        containers: statuses.map(status => ({
          name: status.name,
          ready: status.ready === true,
          imageId: status.imageID ?? 'unknown',
          restarts: Number(status.restartCount ?? 0),
        })),
      },
    }];
  }).sort((left, right) => left.actor.localeCompare(right.actor));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [input] = process.argv.slice(2);
  if (!input) throw new Error('usage: actor-states.mjs POD_LIST_JSON');
  for (const event of actorStateEvents(JSON.parse(readFileSync(input, 'utf8')))) {
    process.stdout.write(`${JSON.stringify(event)}\n`);
  }
}
