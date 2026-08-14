// Adapted from stacks-sbtc/sbtc docker/stacker/stacking under its ISC license.
import crypto from 'node:crypto';
import { type PoxInfo, Pox4SignatureTopic } from '@stacks/stacking';
import {
  Cl,
  ClarityVersion,
  broadcastTransaction,
  encodeStructuredDataBytes,
  makeContractCall,
  makeContractDeploy,
  PostConditionMode,
  signWithKey,
  type ClarityValue,
} from '@stacks/transactions';
import { accounts, network, nodeUrl, requiredInteger, waitForNode } from './common';

const intervalSeconds = requiredInteger('STACKING_INTERVAL');
const stackingCycles = requiredInteger('STACKING_CYCLES');
const pox5StackingCycles = requiredInteger('POX5_STACKING_CYCLES');
const pox5RenewalWindowCycles = requiredInteger('POX5_RENEWAL_WINDOW_CYCLES');
const epoch4FixtureDeployHeight = requiredInteger('EPOCH_4_FIXTURE_DEPLOY_HEIGHT');
const maxAmount = 2n ** 128n - 1n;
let nextFee = 1_000;
let stackingComplete = false;
let epoch4FixturesComplete = false;

if (pox5StackingCycles < 1 || pox5StackingCycles > 96) {
  throw new Error('POX5_STACKING_CYCLES must be within the PoX-5 [1, 96] range');
}
if (pox5RenewalWindowCycles < 1 || pox5RenewalWindowCycles >= pox5StackingCycles) {
  throw new Error('POX5_RENEWAL_WINDOW_CYCLES must be positive and below POX5_STACKING_CYCLES');
}

const pox5ContractAddress = 'ST000000000000000000002AMW42H';
const pox5StakeAmount = 100_000_000_000n;

const pox5SignerManager = `
(impl-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)
(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

(define-public (validate-stake!
        (staker principal)
        (first-index uint)
        (num-indexes uint)
        (amount-ustx uint)
        (amount-sats uint)
        (is-bond bool)
        (signer-calldata (optional (buff 500))))
    (ok true))

(define-public (register-self
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
        (auth-id uint)
        (signer-sig (buff 65)))
    (as-contract? ()
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 grant-signer-key
            signer-key current-contract auth-id signer-sig))
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-signer
            signer-manager signer-key))))

(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint))
    (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-rewards
        bond-periods reward-cycle))

(define-read-only (get-earned-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint)))
    (contract-call? 'ST000000000000000000002AMW42H.pox-5 get-earned-staker-rewards
        current-contract reward-cycle bond-index staker))
`;

const sbtcTokenStub = `
(define-fungible-token sbtc-token)

(define-public (transfer
        (amount uint)
        (sender principal)
        (recipient principal)
        (memo (optional (buff 34))))
    (begin
        (try! (ft-transfer? sbtc-token amount sender recipient))
        (ok true)))

(define-read-only (get-balance (who principal))
    (ok (ft-get-balance sbtc-token who)))

(define-public (mint (amount uint) (recipient principal))
    (ft-mint? sbtc-token amount recipient))
`;

const sbtcRegistryStub = `
(define-read-only (get-current-aggregate-pubkey)
    0x${accounts[0].publicKey})
`;

async function contractExists(contractName: string): Promise<boolean> {
  const response = await fetch(
    `${nodeUrl}/v2/contracts/source/${accounts[0].address}/${contractName}`,
  );
  if (response.status === 404) return false;
  if (!response.ok) {
    throw new Error(`contract lookup for ${contractName} failed: HTTP ${response.status}`);
  }
  return true;
}

async function waitForContract(contractName: string, timeoutSeconds: number): Promise<boolean> {
  const deadline = Date.now() + timeoutSeconds * 1_000;
  while (Date.now() < deadline) {
    if (await contractExists(contractName)) return true;
    console.log(`Waiting for ${contractName} deployment to confirm`);
    await new Promise(resolve => setTimeout(resolve, intervalSeconds * 1_000));
  }
  return contractExists(contractName);
}

async function deployContract(contractName: string, codeBody: string): Promise<void> {
  for (;;) {
    if (await contractExists(contractName)) return;
    const status = await accounts[0].client.getAccountStatus();
    const transaction = await makeContractDeploy({
      contractName,
      codeBody,
      senderKey: accounts[0].privateKey,
      nonce: BigInt(status.nonce),
      fee: 3_000n,
      network,
      // A restarted node can expose HTTP before it has replayed the compact
      // burnchain schedule through Epoch 3.  These fixtures do not require a
      // newer language version, so make the wire transaction valid under the
      // oldest epoch from which the bootstrap may resume.
      clarityVersion: ClarityVersion.Clarity2,
    });
    const result = await broadcastTransaction({ transaction, network });
    if (!('txid' in result)) {
      console.warn(`failed to publish ${contractName}; retrying: ${JSON.stringify(result)}`);
      await new Promise(resolve => setTimeout(resolve, intervalSeconds * 1_000));
      continue;
    }
    console.log(`Submitted Epoch 4 fixture ${contractName}: ${result.txid}`);
    // A txid response is not proof that the transaction entered the canonical
    // mempool (notably while a node is still replaying after restart).  Bound
    // the wait and rebuild from the latest account nonce on retry.
    if (await waitForContract(contractName, 30)) return;
    console.warn(`${contractName} was not confirmed; rebuilding and retrying`);
  }
}

async function waitForNonce(account: (typeof accounts)[number], nonce: number): Promise<void> {
  for (;;) {
    const status = await account.client.getAccountStatus();
    if (status.nonce > nonce) return;
    await new Promise(resolve => setTimeout(resolve, intervalSeconds * 1_000));
  }
}

async function submitContractCall(
  account: (typeof accounts)[number],
  contractAddress: string,
  contractName: string,
  functionName: string,
  functionArgs: ClarityValue[],
  postConditionMode = PostConditionMode.Deny,
): Promise<void> {
  const status = await account.client.getAccountStatus();
  const nonce = status.nonce;
  const transaction = await makeContractCall({
    contractAddress,
    contractName,
    functionName,
    functionArgs,
    senderKey: account.privateKey,
    nonce: BigInt(nonce),
    fee: 3_000n,
    postConditionMode,
    network,
  });
  const result = await broadcastTransaction({ transaction, network });
  if (!('txid' in result)) {
    throw new Error(`failed to publish ${contractName}.${functionName}: ${JSON.stringify(result)}`);
  }
  console.log(`Submitted ${contractName}.${functionName} for signer ${account.index}: ${result.txid}`);
  await waitForNonce(account, nonce);
}

function signerGrantSignature(signerManager: string, authId: bigint, privateKey: string): Uint8Array {
  const message = Cl.tuple({
    'signer-manager': Cl.principal(signerManager),
    topic: Cl.stringAscii('grant-authorization'),
    'auth-id': Cl.uint(authId),
  });
  const encoded = encodeStructuredDataBytes({
    message,
    domain: Cl.tuple({
      name: Cl.stringAscii('pox-5-signer'),
      version: Cl.stringAscii('1.0.0'),
      'chain-id': Cl.uint(network.chainId),
    }),
  });
  const digest = crypto.createHash('sha256').update(encoded).digest('hex');
  const secret = Uint8Array.from(Buffer.from(privateKey.slice(0, 64), 'hex'));
  const recoverable = signWithKey(secret, digest);
  return Uint8Array.from(Buffer.from(recoverable.slice(2) + recoverable.slice(0, 2), 'hex'));
}

async function ensurePox5Signer(account: (typeof accounts)[number], burnHeight: number): Promise<void> {
  const contractName = `pox5-signer-${account.index}`;
  const signerManager = `${account.address}.${contractName}`;
  if (!(await contractExistsAt(account.address, contractName))) {
    await deployContractForAccount(account, contractName, pox5SignerManager);
  }

  const authId = BigInt(account.index);
  const signature = signerGrantSignature(signerManager, authId, account.privateKey);
  await submitContractCall(account, account.address, contractName, 'register-self', [
    Cl.principal(signerManager),
    Cl.bufferFromHex(account.publicKey),
    Cl.uint(authId),
    Cl.buffer(signature),
  ]);
  // PoX-5's stake entry point intentionally locks STX. Keep deny mode for all
  // other calls and opt into allow mode narrowly for this transaction.
  await submitContractCall(account, pox5ContractAddress, 'pox-5', 'stake', [
    Cl.principal(signerManager),
    Cl.uint(pox5StakeAmount * BigInt(account.targetSlots)),
    Cl.uint(BigInt(pox5StackingCycles)),
    Cl.uint(BigInt(burnHeight)),
    Cl.none(),
  ], PostConditionMode.Allow);
}

async function deployContractForAccount(
  account: (typeof accounts)[number],
  contractName: string,
  codeBody: string,
): Promise<void> {
  const status = await account.client.getAccountStatus();
  const transaction = await makeContractDeploy({
    contractName,
    codeBody,
    senderKey: account.privateKey,
    nonce: BigInt(status.nonce),
    fee: 3_000n,
    network,
  });
  const result = await broadcastTransaction({ transaction, network });
  if (!('txid' in result)) {
    throw new Error(`failed to publish ${contractName}: ${JSON.stringify(result)}`);
  }
  console.log(`Submitted PoX-5 signer manager ${contractName}: ${result.txid}`);
  await waitForContractAt(account.address, contractName);
}

async function waitForContractAt(address: string, contractName: string): Promise<void> {
  for (;;) {
    const response = await fetch(`${nodeUrl}/v2/contracts/source/${address}/${contractName}`);
    if (response.ok) return;
    if (response.status !== 404) {
      throw new Error(`contract lookup for ${address}.${contractName} failed: HTTP ${response.status}`);
    }
    await new Promise(resolve => setTimeout(resolve, intervalSeconds * 1_000));
  }
}

async function contractExistsAt(address: string, contractName: string): Promise<boolean> {
  const response = await fetch(`${nodeUrl}/v2/contracts/source/${address}/${contractName}`);
  if (response.status === 404) return false;
  if (!response.ok) {
    throw new Error(`contract lookup for ${address}.${contractName} failed: HTTP ${response.status}`);
  }
  return true;
}

async function ensurePox5Signers(burnHeight: number): Promise<void> {
  const poxInfo = await accounts[0].client.getPoxInfo();
  await Promise.all(accounts.map(async account => {
    const status = await account.client.getAccountStatus();
    if (BigInt(status.locked) === 0n) {
      await ensurePox5Signer(account, burnHeight);
      return;
    }

    // PoX-5 permits at most 96 cycles per active lock. Keep the disposable
    // regtest signer set continuously available by restoring that horizon
    // before the next-cycle snapshot is taken. This must remain a real
    // `stake-update` transaction: changing the miner loop to skip an empty
    // signer set would conceal precisely the liveness failure this PoC is
    // intended to expose.
    const unlockHeight = status.unlock_height;
    const rewardCycleLength = poxInfo.reward_cycle_length;
    const remainingBurnBlocks = Math.max(0, unlockHeight - burnHeight);
    const remainingCycles = Math.ceil(remainingBurnBlocks / rewardCycleLength);
    if (remainingCycles > pox5RenewalWindowCycles) return;

    // PoX-5 rejects next-cycle mutation during prepare phase. The bootstrap
    // loop retries every STACKING_INTERVAL, so wait for a reward phase rather
    // than generating a transaction known to abort.
    if (poxInfo.next_cycle.blocks_until_prepare_phase <= 0) return;

    const cyclesToExtend = pox5StackingCycles - remainingCycles;
    const contractName = `pox5-signer-${account.index}`;
    const signerManager = `${account.address}.${contractName}`;
    await submitContractCall(account, pox5ContractAddress, 'pox-5', 'stake-update', [
      Cl.principal(signerManager),
      Cl.principal(signerManager),
      Cl.uint(BigInt(cyclesToExtend)),
      Cl.uint(0n),
      Cl.none(),
    ]);
    console.log(
      `Extended PoX-5 signer ${account.index} by ${cyclesToExtend} cycles `
      + `(previously ${remainingCycles} remaining)`,
    );
  }));
  const statuses = await Promise.all(accounts.map(account => account.client.getAccountStatus()));
  if (statuses.every(status => BigInt(status.locked) !== 0n)) {
    console.log(`All ${accounts.length} PoX-5 signer registrations and stakes are confirmed`);
  } else {
    throw new Error('PoX-5 signer stakes have not all confirmed');
  }
}

async function ensureEpoch4Fixtures(): Promise<void> {
  await deployContract('sbtc-token', sbtcTokenStub);
  await deployContract('sbtc-registry', sbtcRegistryStub);
}

async function stackAccount(poxInfo: PoxInfo, account: (typeof accounts)[number]): Promise<void> {
  const status = await account.client.getAccountStatus();
  if (BigInt(status.locked) !== 0n) {
    return;
  }

  // The target is deliberately above the reported next-cycle threshold and below the
  // genesis balance. This produces a non-uniform reward-set weight for quorum tests.
  const amountMicroStx = BigInt(Math.floor(poxInfo.next_cycle.min_threshold_ustx * 1.5))
    * BigInt(account.targetSlots);
  const balance = BigInt(status.balance);
  if (amountMicroStx > balance) {
    throw new Error(`signer ${account.index} needs ${amountMicroStx} uSTX, has ${balance}`);
  }

  const authId = crypto.randomInt(0, 0xffff_ffff_ffff);
  const signatureArguments = {
    topic: Pox4SignatureTopic.StackStx,
    rewardCycle: poxInfo.reward_cycle_id,
    poxAddress: account.poxAddress,
    period: stackingCycles,
    signerPrivateKey: account.privateKey,
    authId,
    maxAmount,
  } as const;
  const signerSignature = account.client.signPoxSignature(signatureArguments);
  const result = await account.client.stack({
    poxAddress: account.poxAddress,
    privateKey: account.privateKey,
    amountMicroStx,
    burnBlockHeight: poxInfo.current_burnchain_block_height,
    cycles: stackingCycles,
    fee: nextFee++,
    signerKey: account.publicKey,
    signerSignature,
    authId,
    maxAmount,
  });
  console.log(`Submitted signer ${account.index} stack-stx`, result);
}

async function registrationsConfirmed(): Promise<boolean> {
  const statuses = await Promise.all(accounts.map(account => account.client.getAccountStatus()));
  return statuses.every(status => BigInt(status.locked) !== 0n);
}

async function currentBurnHeight(): Promise<number> {
  const response = await fetch(`${nodeUrl}/v2/info`);
  if (!response.ok) throw new Error(`chain info lookup failed: HTTP ${response.status}`);
  const info = await response.json() as { burn_block_height?: unknown };
  if (typeof info.burn_block_height !== 'number') {
    throw new Error('chain info response omitted numeric burn_block_height');
  }
  return info.burn_block_height;
}

async function runOnce(): Promise<void> {
  if (!stackingComplete) {
    const poxInfo = await accounts[0].client.getPoxInfo();
    if (poxInfo.contract_id.endsWith('.pox-5')) {
      // The helper is stateless and may be restarted after the PoX-4 phase.
      // PoX-5 enrollment below is the authoritative readiness condition now.
      stackingComplete = true;
      console.log('PoX-4 phase has passed; resuming bootstrap at PoX-5');
    } else if (!poxInfo.contract_id.endsWith('.pox-4')) {
      console.log(`Waiting for PoX-4; current contract is ${poxInfo.contract_id}`);
      return;
    } else {
      await Promise.all(accounts.map(account => stackAccount(poxInfo, account)));
      stackingComplete = await registrationsConfirmed();
      if (!stackingComplete) return;
      console.log(`All ${accounts.length} PoX-4 signer registrations are confirmed`);
    }
  }

  if (!epoch4FixturesComplete && await currentBurnHeight() >= epoch4FixtureDeployHeight) {
    await ensureEpoch4Fixtures();
    epoch4FixturesComplete = true;
    console.log('Both Epoch 4 sBTC interface fixtures are confirmed');
  }

  const poxInfo = await accounts[0].client.getPoxInfo();
  if (poxInfo.contract_id.endsWith('.pox-5')) {
    await ensurePox5Signers(poxInfo.current_burnchain_block_height);
  }
}

await waitForNode();
for (;;) {
  try {
    await runOnce();
  } catch (error) {
    console.error('Stacking bootstrap failed; retrying', error);
  }
  await new Promise(resolve => setTimeout(resolve, intervalSeconds * 1_000));
}
