#!/usr/bin/env node

import {readFileSync} from 'node:fs';

const TERMINAL_CAMPAIGNS = new Set(['Passed', 'Failed', 'Inconclusive']);

function podReady(pod) {
  return pod.status?.phase === 'Running'
    && pod.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True');
}

export function evaluatePodHealth(podList, campaignList, baselinePodList = podList) {
  const activeCampaigns = (campaignList?.items ?? []).filter(campaign =>
    campaign.spec?.template !== true && !TERMINAL_CAMPAIGNS.has(campaign.status?.phase));
  const expectedActors = new Set(activeCampaigns.flatMap(campaign => campaign.spec?.target?.actors ?? []));
  const rows = (podList?.items ?? []).map(pod => {
    const actor = pod.metadata?.labels?.['testing.stacks.org/actor'] ?? null;
    const ready = podReady(pod);
    const expectedDisruption = !ready && actor !== null && expectedActors.has(actor);
    return {
      pod: pod.metadata?.name ?? '<unknown>',
      uid: pod.metadata?.uid ?? null,
      actor,
      node: pod.spec?.nodeName ?? null,
      phase: pod.status?.phase ?? 'Unknown',
      ready,
      expectedDisruption,
      restarts: (pod.status?.containerStatuses ?? [])
        .reduce((sum, status) => sum + Number(status.restartCount ?? 0), 0),
    };
  });
  const currentNames = new Set(rows.map(row => row.pod));
  const missing = (baselinePodList?.items ?? [])
    .filter(pod => !currentNames.has(pod.metadata?.name))
    .map(pod => {
      const actor = pod.metadata?.labels?.['testing.stacks.org/actor'] ?? null;
      return {
        pod: pod.metadata?.name ?? '<unknown>',
        uid: pod.metadata?.uid ?? null,
        actor,
        node: pod.spec?.nodeName ?? null,
        phase: 'Missing',
        ready: false,
        expectedDisruption: actor !== null && expectedActors.has(actor),
        restarts: null,
      };
    });
  rows.push(...missing);
  const unready = rows.filter(row => !row.ready);
  const unexplained = unready.filter(row => !row.expectedDisruption);
  return {
    ok: unexplained.length === 0,
    observedAt: new Date().toISOString(),
    activeCampaigns: activeCampaigns.map(campaign => ({
      name: campaign.metadata?.name,
      phase: campaign.status?.phase ?? 'Pending',
      targets: campaign.spec?.target?.actors ?? [],
    })),
    readyPods: rows.length - unready.length,
    totalPods: rows.length,
    unready,
    unexplained,
    rows,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [podsPath, campaignsPath, baselinePath] = process.argv.slice(2);
  if (!podsPath || !campaignsPath) {
    throw new Error('usage: soak-observation.mjs PODS.json CAMPAIGNS.json');
  }
  const result = evaluatePodHealth(
    JSON.parse(readFileSync(podsPath, 'utf8')),
    JSON.parse(readFileSync(campaignsPath, 'utf8')),
    baselinePath ? JSON.parse(readFileSync(baselinePath, 'utf8')) : undefined,
  );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
