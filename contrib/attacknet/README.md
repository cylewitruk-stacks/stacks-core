# Stacks Attacknet

This directory contains the transport-independent test harness for adversarial
Stacks regtest networks. The default profile follows the node and signer code
on current `main`; it uses the production StackerDB signer transport. A future
libp2p build can be supplied as another actor image/profile without becoming a
dependency of the harness or operator.

The Helm chart in `contrib/helm/hacknet` supplies the reliable namespaced
control plane. This directory supplies the system-under-test topology,
burnchain policy, backend adapter, assertions, and evidence capture.

## Design boundaries

- Bitcoin Core, its Stacks-blind block clock, and the policy that steers the
  clock are separate failure domains.
- Actor counts and inventories come from `manifest.json`; harness scripts do
  not encode a ten-signer assumption.
- Kubernetes is canonical for adversarial runs. Compose remains a future small
  smoke adapter, using the same manifest and assertions.
- Baseline resources are bounded. Adversarial profiles may opt out, but the
  evidence bundle must capture the admitted Pod spec so LimitRange/Quota
  mutation cannot be mistaken for an unbounded run.
- Control-plane hardening does not constrain what actor Pods may experience.
  Actor Pods have no service-account token.

## Local images

Build current main's node and signer binaries:

```bash
docker build -t stacks-core-attacknet:main .
docker build -t stacks-attacknet-stacker:local contrib/attacknet/stacker
```

Docker Desktop's kind cluster can use images from its local image store with
`imagePullPolicy: IfNotPresent`. Other kind installations may need
`kind load docker-image` for every node.

## Render and run

Start with a capacity stage before attempting the 31-workload full topology:

```bash
node contrib/attacknet/topology.mjs \
  --miners=1 --signers=1 --followers=1 \
  --output=contrib/attacknet/generated/stage-1

KUBE_NETWORK=attacknet-stage-1 \
  contrib/attacknet/lifecycle.sh apply contrib/attacknet/generated/stage-1
```

The full protocol topology has 28 actors (3 miners, 10 signer/companion pairs,
and 5 followers) plus Bitcoin, the burnchain clock, and the stacker bootstrap:

```bash
node contrib/attacknet/topology.mjs \
  --network=attacknet --miners=3 --signers=10 --followers=5 \
  --output=contrib/attacknet/generated/full
contrib/attacknet/lifecycle.sh apply contrib/attacknet/generated/full
```

Steer cadence without restarting Bitcoin or coupling the clock to Stacks:

```bash
contrib/attacknet/burnchain-policy.sh pause
contrib/attacknet/burnchain-policy.sh run 20 0
contrib/attacknet/burnchain-policy.sh burst 3
```

Capture Kubernetes-admitted resources and runtime evidence:

```bash
contrib/attacknet/lifecycle.sh capture evidence/admitted
ATTACKNET_BACKEND=kubernetes \
  contrib/attacknet/evidence-harness.sh evidence/behavior \
  contrib/attacknet/generated/full/manifest.json 1h
```

Run static and behavioral renderer checks with:

```bash
contrib/attacknet/check.sh
```

## Current milestone

The operator and current-main topology renderer are functional. The next
milestone is a staged live capacity/parity run, followed by first-class
`AttacknetRun` and `FaultCampaign` resources backed by Chaos Mesh. Fault
controls must cover process/Pod failure, partitions and latency, DNS, I/O, and
wall-clock skew, while recording each actor's resolved admitted configuration.
