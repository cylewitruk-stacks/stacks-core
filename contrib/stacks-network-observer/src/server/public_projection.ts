import type {PublicNetworkState, PublicPortalSnapshot} from '../shared/model.js';

/**
 * Construct the unauthenticated response by explicit allowlist. This function
 * deliberately cannot see actor telemetry, quorum rounds, incidents, links,
 * enrollment IDs, internal endpoint URLs, or backend errors.
 */
export function projectPublicPortal(
  network: PublicNetworkState,
  networkLabel: string,
  now = Date.now(),
): PublicPortalSnapshot {
  const current = network.rewardCycles.find(cycle => cycle.phase === 'current');
  return {
    summary: {
      network: networkLabel,
      generatedAt: new Date(now).toISOString(),
      health: network.health,
      burnHeight: network.burnHeight,
      currentEpoch: network.currentEpoch,
      currentRewardCycle: network.currentRewardCycle,
      signerCount: current?.signerKeys.length ?? 0,
      totalWeight: current?.totalWeight ?? 0,
      totalStackedMicroStx: current?.totalStackedMicroStx ?? '0',
    },
    publicNetwork: {
      health: network.health,
      observedAt: network.observedAt,
      currentEpoch: network.currentEpoch,
      burnHeight: network.burnHeight,
      currentRewardCycle: network.currentRewardCycle,
      nextRewardCycle: network.nextRewardCycle,
      rewardCycles: network.rewardCycles.map(cycle => ({
        ...cycle,
        signerKeys: [...cycle.signerKeys],
      })),
      signers: network.signers.map(signer => ({
        publicKey: signer.publicKey,
        entityName: signer.entityName,
        weight: signer.weight,
        stackedAmountMicroStx: signer.stackedAmountMicroStx,
        rewardCycles: [...signer.rewardCycles],
      })),
    },
  };
}
