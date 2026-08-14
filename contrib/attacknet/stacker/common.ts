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

export const accounts = keys.split(',').map((privateKey, index) => {
  const publicKey = getPublicKeyFromPrivate(privateKey);
  const address = getAddressFromPrivateKey(privateKey, STACKS_TESTNET);
  return {
    index,
    privateKey,
    publicKey,
    address,
    poxAddress: publicKeyToBtcAddress(publicKey),
    // Keep a non-uniform quorum without making the highest signer grow with
    // topology size. At the ten-signer ceiling this yields 19 total slots and
    // no actor controls more than 3/19 of the weight.
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
