import type {Health, PublicNetworkState, PublicRewardCycle, PublicSigner} from '../shared/model.js';
import {SIGNER_PUBLIC_KEY} from './enrollment.js';

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_SIGNERS = 4_000;

interface PoxResponse {
  current_burnchain_block_height?: unknown;
  current_epoch?: unknown;
  current_cycle?: {id?: unknown};
  next_cycle?: {id?: unknown};
}

interface RewardSetSigner {
  signing_key?: unknown;
  stacked_amt?: unknown;
  weight?: unknown;
}

interface RewardSetResponse {
  stacker_set?: {signers?: unknown};
}

/** Fetches only public chain data; it never receives federation credentials. */
export class StacksPublicDataClient {
  constructor(
    private readonly endpoint: string,
    private readonly timeoutMs = 2_000,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  async snapshot(now = Date.now()): Promise<PublicNetworkState> {
    const pox = await this.getJson<PoxResponse>('/v2/pox');
    const currentRewardCycle = safeInteger(pox.current_cycle?.id);
    const nextRewardCycle = safeInteger(pox.next_cycle?.id);
    const requested = [
      currentRewardCycle === null ? null : {id: currentRewardCycle, phase: 'current' as const},
      nextRewardCycle === null ? null : {id: nextRewardCycle, phase: 'next' as const},
    ].filter((item): item is {id: number; phase: 'current' | 'next'} => item !== null);
    const cycles = await Promise.all(requested.map(item => this.rewardCycle(item.id, item.phase)));
    return {
      source: this.endpoint,
      health: cycles.some(cycle => cycle.summary.phase === 'current' && cycle.summary.status !== 'available')
        ? 'degraded' : 'healthy',
      observedAt: new Date(now).toISOString(),
      currentEpoch: typeof pox.current_epoch === 'string' ? pox.current_epoch : 'unknown',
      burnHeight: safeInteger(pox.current_burnchain_block_height) ?? 0,
      currentRewardCycle,
      nextRewardCycle,
      rewardCycles: cycles.map(cycle => cycle.summary),
      signers: mergeSigners(cycles.flatMap(cycle => cycle.signers.map(signer => ({...signer, cycle: cycle.summary.id})))),
      error: null,
    };
  }

  private async rewardCycle(id: number, phase: 'current' | 'next'): Promise<{
    summary: PublicRewardCycle;
    signers: Omit<PublicSigner, 'rewardCycles' | 'entityName' | 'enrolledActorId'>[];
  }> {
    let decoded: RewardSetResponse;
    try {
      decoded = await this.getJson<RewardSetResponse>(`/v3/stacker_set/${id}`);
    } catch (error) {
      const pending = error instanceof HttpStatusError && error.status === 400;
      return {
        summary: {id, phase, status: pending ? 'pending' : 'unavailable', totalWeight: 0, totalStackedMicroStx: '0', signerKeys: []},
        signers: [],
      };
    }
    const values = decoded.stacker_set?.signers;
    if (!Array.isArray(values) || values.length > MAX_SIGNERS) throw new Error('public reward set has an invalid signer list');
    const signers = values.map((value, index) => parseSigner(value, index));
    return {
      summary: {
        id,
        phase,
        status: 'available',
        totalWeight: signers.reduce((sum, signer) => sum + signer.weight, 0),
        totalStackedMicroStx: signers.reduce((sum, signer) => sum + BigInt(signer.stackedAmountMicroStx), 0n).toString(),
        signerKeys: signers.map(signer => signer.publicKey),
      },
      signers,
    };
  }

  private async getJson<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetcher(new URL(path, this.endpoint), {signal: controller.signal});
      if (!response.ok) throw new HttpStatusError(response.status);
      const declared = Number(response.headers.get('content-length') ?? 0);
      if (declared > MAX_RESPONSE_BYTES) throw new Error('public chain response exceeds the byte limit');
      return JSON.parse(await boundedText(response, MAX_RESPONSE_BYTES)) as T;
    } finally {
      clearTimeout(timeout);
    }
  }
}

class HttpStatusError extends Error {
  constructor(readonly status: number) {
    super(`public Stacks API returned HTTP ${status}`);
  }
}

async function boundedText(response: Response, limit: number): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > limit) {
      await reader.cancel();
      throw new Error('public chain response exceeds the byte limit');
    }
    chunks.push(value);
  }
  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

function parseSigner(value: unknown, index: number): Omit<PublicSigner, 'rewardCycles' | 'entityName' | 'enrolledActorId'> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`reward signer ${index} is invalid`);
  const signer = value as RewardSetSigner;
  const publicKey = typeof signer.signing_key === 'string' ? signer.signing_key.toLowerCase() : '';
  if (!SIGNER_PUBLIC_KEY.test(publicKey)) throw new Error(`reward signer ${index} has an invalid public key`);
  const weight = safeInteger(signer.weight);
  if (weight === null || weight <= 0) throw new Error(`reward signer ${index} has an invalid weight`);
  const stackedAmountMicroStx = unsignedIntegerString(signer.stacked_amt);
  return {publicKey, weight, stackedAmountMicroStx};
}

function mergeSigners(values: Array<Omit<PublicSigner, 'rewardCycles' | 'entityName' | 'enrolledActorId'> & {cycle: number}>): PublicSigner[] {
  const merged = new Map<string, PublicSigner>();
  for (const value of values) {
    const existing = merged.get(value.publicKey);
    if (existing) {
      if (!existing.rewardCycles.includes(value.cycle)) existing.rewardCycles.push(value.cycle);
      continue;
    }
    merged.set(value.publicKey, {
      publicKey: value.publicKey,
      entityName: null,
      weight: value.weight,
      stackedAmountMicroStx: value.stackedAmountMicroStx,
      rewardCycles: [value.cycle],
      enrolledActorId: null,
    });
  }
  return [...merged.values()].sort((left, right) => right.weight - left.weight || left.publicKey.localeCompare(right.publicKey));
}

function safeInteger(value: unknown): number | null {
  const number = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : Number.NaN;
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function unsignedIntegerString(value: unknown): string {
  const text = typeof value === 'number' || typeof value === 'bigint' || typeof value === 'string' ? String(value) : '';
  if (!/^[0-9]+$/.test(text)) throw new Error('reward signer has an invalid stacked amount');
  return BigInt(text).toString();
}

export function unavailablePublicNetwork(source: string, now = Date.now(), error = 'public chain data unavailable'): PublicNetworkState {
  return {
    source,
    health: 'unknown' as Health,
    observedAt: new Date(now).toISOString(),
    currentEpoch: 'unknown',
    burnHeight: 0,
    currentRewardCycle: null,
    nextRewardCycle: null,
    rewardCycles: [],
    signers: [],
    error,
  };
}
