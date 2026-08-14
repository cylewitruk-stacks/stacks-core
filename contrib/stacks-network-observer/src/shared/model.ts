export type NodeRole = 'miner' | 'signer' | 'follower' | 'bootstrap' | 'companion' | 'unknown';
export type Transport = 'libp2p' | 'legacy' | 'both';
export type Health = 'healthy' | 'degraded' | 'critical' | 'unknown';
export type Severity = 'info' | 'warning' | 'critical';
export const COARSE_REGIONS = [
  'north-america',
  'south-america',
  'europe',
  'africa',
  'asia-pacific',
  'local',
  'unknown',
] as const;
export type CoarseRegion = (typeof COARSE_REGIONS)[number];
export type StallKind =
  | 'none'
  | 'burnchain'
  | 'signer-quorum'
  | 'propagation'
  | 'sync'
  | 'resource-pressure'
  | 'telemetry-blind-spot';

export type SignerLifecycle = 'uninitialized' | 'pending' | 'initialized' | 'unknown';
export type SignerMinerState = 'active_miner' | 'no_valid_miner' | 'unknown';

export interface SignerStateObservation {
  lifecycle: SignerLifecycle;
  minerState: SignerMinerState;
  rewardCycle: number | null;
  burnBlockHeight: number | null;
  protocolVersion: number | null;
  lastChangedAt: string | null;
  transitionCounts: Array<{reason: string; count: number}>;
  conflictCounts: Array<{conflict: string; count: number}>;
  source: 'authenticated-telemetry';
}

export interface PublicSigner {
  publicKey: string;
  entityName: string | null;
  weight: number;
  stackedAmountMicroStx: string;
  rewardCycles: number[];
  enrolledActorId: string | null;
}

export interface PublicRewardCycle {
  id: number;
  phase: 'current' | 'next';
  status: 'available' | 'pending' | 'unavailable';
  totalWeight: number;
  totalStackedMicroStx: string;
  signerKeys: string[];
}

export interface PublicNetworkState {
  source: string;
  health: Health;
  observedAt: string;
  currentEpoch: string;
  burnHeight: number;
  currentRewardCycle: number | null;
  nextRewardCycle: number | null;
  rewardCycles: PublicRewardCycle[];
  signers: PublicSigner[];
  error: string | null;
}

export interface PublicSafeSigner {
  publicKey: string;
  entityName: string | null;
  weight: number;
  stackedAmountMicroStx: string;
  rewardCycles: number[];
}

export interface PublicSafeNetworkState {
  health: Health;
  observedAt: string;
  currentEpoch: string;
  burnHeight: number;
  currentRewardCycle: number | null;
  nextRewardCycle: number | null;
  rewardCycles: PublicRewardCycle[];
  signers: PublicSafeSigner[];
}

export interface PublicPortalSummary {
  network: string;
  generatedAt: string;
  health: Health;
  burnHeight: number;
  currentEpoch: string;
  currentRewardCycle: number | null;
  signerCount: number;
  totalWeight: number;
  totalStackedMicroStx: string;
}

export interface PublicPortalSnapshot {
  summary: PublicPortalSummary;
  publicNetwork: PublicSafeNetworkState;
}

export type ViewerRole = 'federation-operator';

export interface ViewerPrincipal {
  subject: string;
  email: string;
  roles: ViewerRole[];
}

export interface ViewerSession {
  authenticated: boolean;
  principal: ViewerPrincipal | null;
}

export type SignerRoundStatus = 'collecting' | 'approved' | 'rejected' | 'timed-out';
export type SignerVoteDecision = 'approved' | 'rejected' | 'unavailable' | 'missing';

export interface SignerQuorumVote {
  signerPublicKey: string;
  entityName: string | null;
  weight: number;
  decision: SignerVoteDecision;
  latencyMs: number | null;
}

export interface SignerQuorumRound {
  minerActorId: string;
  minerLabel: string;
  blockHeight: number;
  startedAt: string;
  observedAt: string;
  status: SignerRoundStatus;
  thresholdWeight: number;
  totalWeight: number;
  approvedWeight: number;
  rejectedWeight: number;
  unavailableWeight: number;
  votes: SignerQuorumVote[];
  source: 'authenticated-miner-telemetry';
}

export interface NodeObservation {
  id: string;
  label: string;
  role: NodeRole;
  transport: Transport;
  health: Health;
  region: CoarseRegion;
  burnHeight: number;
  stacksHeight: number;
  /** When this actor last obtained the displayed height from its node. */
  stacksTipObservedAt: string | null;
  canonicalTip: string;
  inboundPeers: number | null;
  outboundPeers: number | null;
  dhtPeers: number | null;
  queueResidenceP95Ms: number;
  queueUtilization: number;
  cpuUtilization: number;
  memoryMb: number;
  syncLag: number;
  blockedOn: string;
  signerProposals: number;
  signerResponses: number;
  signerPublicKey: string | null;
  signerEntityName: string | null;
  signerWeight: number | null;
  /** Server-enrolled service binding; this is not connectivity evidence. */
  companionActorId: string | null;
  signerState: SignerStateObservation | null;
  lastSeen: string;
}

export interface LinkObservation {
  source: string;
  target: string;
  transport: Transport;
  direction: 'inbound' | 'outbound';
  rttP50Ms: number | null;
  rttP95Ms: number | null;
  deliveryP95Ms: number | null;
  errorRate: number | null;
  connected: boolean;
  evidence: Array<'enrolled-transport-peer' | 'authenticated-signer-envelope'>;
  reportedBy: string[];
  corroborated: boolean;
  observedAt: string;
}

export interface PropagationHop {
  nodeId: string;
  firstSeenMs: number;
  validatedMs: number;
  source: 'gossip' | 'direct-push' | 'fetch' | 'legacy' | 'tip-observation';
  accepted: boolean;
}

export type MetricDomain =
  | 'chain'
  | 'transport'
  | 'content'
  | 'sync'
  | 'resources'
  | 'signer'
  | 'quorum'
  | 'telemetry';

/** One reviewed, endpoint-free metric reading in the authenticated view. */
export interface MetricReading {
  id: string;
  name: string;
  label: string;
  domain: MetricDomain;
  value: number;
  unit: 'count' | 'bytes' | 'seconds' | 'height' | 'weight' | 'timestamp' | 'state';
  attributes: Array<{key: string; value: string}>;
  observedAt: string;
}

export interface ActorMetricInventory {
  actorId: string;
  actorLabel: string;
  role: NodeRole;
  readings: MetricReading[];
}

export interface PropagationTrace {
  id: string;
  objectKind: 'nakamoto-block' | 'transaction' | 'signer-envelope';
  objectId: string;
  /** Canonical public chain identifier, when the object is an accepted block. */
  publicBlockId?: string;
  originNode: string;
  startedAt: string;
  p50Ms: number;
  p95Ms: number;
  coverage: number;
  hops: PropagationHop[];
}

export interface Incident {
  id: string;
  severity: Severity;
  kind: StallKind;
  title: string;
  evidence: string[];
  affectedNodes: string[];
  detectedAt: string;
  status: 'active' | 'watching' | 'resolved';
}

export interface ReporterState {
  id: string;
  label: string;
  role: NodeRole;
  health: Health;
  lastSeen: string;
  acceptedBatches: number;
  rejectedBatches: number;
  clockSkewMs: number;
  observedNodes: number;
}

export interface NetworkSummary {
  network: string;
  generatedAt: string;
  health: Health;
  stall: StallKind;
  burnHeight: number;
  stacksHeight: number;
  heightAgreement: number;
  reportingNodes: number;
  observedNodes: number;
  observedLinks: number;
  propagationP95Ms: number;
  signerQuorumMs: number;
  maxSyncLag: number;
  queueResidenceP95Ms: number;
  burnProgressAgeSeconds: number;
  stacksProgressAgeSeconds: number;
}

export interface NetworkSnapshot {
  summary: NetworkSummary;
  nodes: NodeObservation[];
  links: LinkObservation[];
  propagation: PropagationTrace[];
  incidents: Incident[];
  reporters: ReporterState[];
  publicNetwork: PublicNetworkState;
  signerQuorumRounds: SignerQuorumRound[];
  actorMetrics: ActorMetricInventory[];
}

export interface ApiError {
  error: string;
  code: string;
}
