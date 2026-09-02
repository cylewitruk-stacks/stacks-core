import { getPublicKeyFromPrivate, publicKeyToBtcAddress } from '@stacks/encryption';
import { STACKS_TESTNET, type StacksNetwork } from '@stacks/network';
import { StackingClient } from '@stacks/stacking';
import { getAddressFromPrivateKey } from '@stacks/transactions';

export const nodeUrl = `http://${process.env.STACKS_CORE_RPC_HOST}:${process.env.STACKS_CORE_RPC_PORT}`;
export const network: StacksNetwork = {
  ...STACKS_TESTNET,
  client: { baseUrl: nodeUrl },
};

export function requiredInteger(name: string): number {
  const value = process.env[name];
  if (value === undefined) throw new Error(`missing ${name}`);
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed)) throw new Error(`invalid ${name}: ${value}`);
  return parsed;
}

const keys = process.env.STACKING_KEYS;
if (!keys) throw new Error('missing STACKING_KEYS');
const expectedAddresses = process.env.STACKING_ADDRESSES?.split(',');
if (!expectedAddresses) throw new Error('missing STACKING_ADDRESSES');

const privateKeys = keys.split(',');
if (privateKeys.length !== expectedAddresses.length) {
  throw new Error(
    `STACKING_KEYS has ${privateKeys.length} entries but STACKING_ADDRESSES has ${expectedAddresses.length}`,
  );
}

export const accounts = privateKeys.map((privateKey, index) => {
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const address = getAddressFromPrivateKey(privateKey, STACKS_TESTNET);
  if (address !== expectedAddresses[index]) {
    throw new Error(
      `signer ${index} private key derives ${address}, but genesis funds ${expectedAddresses[index]}`,
    );
  }
  return {
    index,
    privateKey,
    publicKey,
    address,
    poxAddress: publicKeyToBtcAddress(publicKey),
    // Keep a non-uniform quorum without making the highest signer grow with
    // topology size. stacking.ts locks 1.5 times the minimum per target slot,
    // so consensus floors these multipliers to weights 1, 3, and 4. At the
    // ten-signer ceiling this yields 25 total weight and no actor controls more
    // than 4/25.
    targetSlots: (index % 3) + 1,
    client: new StackingClient({ address, network }),
  };
});

export async function waitForNode(): Promise<void> {
  for (;;) {
    try {
      await accounts[0].client.getPoxInfo();
      return;
    } catch {
      console.log('Stacks RPC is not ready; retrying');
      await new Promise(resolve => setTimeout(resolve, 1_000));
    }
  }
}
