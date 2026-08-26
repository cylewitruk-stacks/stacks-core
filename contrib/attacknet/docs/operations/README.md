# Attacknet operations

This guide covers routine Release 1 operation after the typed Go client and
local control plane pass the [README quickstart](../../README.md). Attacknet is
disposable regtest infrastructure; never use valuable keys or funds.

## Public boundary

Build the client once and use it for supported host and Kubernetes workflows:

```bash
(cd contrib/helm/hacknet/operator && \
  go build -o /tmp/stacks-attacknet ./cmd/attacknet)
ATTACKNET=/tmp/stacks-attacknet

$ATTACKNET commands --json
$ATTACKNET doctor --output json
```

The controllers own topology reconciliation, fault admission, scheduling,
injection, rollback, recovery, replay, minimization, and terminal
classification. The client submits desired state, observes status, manages
local images/Helm/port-forwards, and captures bounded evidence. The shell and
Node files under [`../../legacy/`](../../legacy/README.md) are historical
qualification inputs, not an operator API.

## Control-plane lifecycle

Build and install exact local images:

```bash
$ATTACKNET image build --repo-root "$(pwd)" --stacks
$ATTACKNET install local \
  --chart-dir contrib/helm/hacknet \
  --namespace hacknet-system \
  --release hacknet \
  --kind-image-load require
$ATTACKNET image load --mode require \
  stacks-core-attacknet:main \
  stacks-attacknet-stacker:local
```

The installer refuses failed Helm releases and field conflicts unless the
corresponding recovery flag is explicit. It applies CRDs separately, waits for
`Established`, content-tags chart images by immutable Docker ID, and verifies
their import on every kind node.

## Network lifecycle

Human-authored resources are YAML. Start with the minimal network:

```bash
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal-burnchain-policy.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal.yaml

$ATTACKNET wait --namespace hacknet-system --for condition=Ready \
  BurnchainPolicy minimal
$ATTACKNET wait --namespace hacknet-system --for condition=Ready \
  StacksNetwork minimal
```

Use `submit --dry-run` before mutation when server-side schema and admission
validation are desired. Dry-run does not execute a controller workflow.

The qualified full protocol shape is
[`accepted-28.yaml`](../../../helm/hacknet/examples/accepted-28.yaml).
It requires the referenced ConfigMaps and Secrets. Actor and signer identities
come from `StacksNetwork.status`; never infer them from names alone.

Delete runs and campaigns before their network:

```bash
$ATTACKNET delete --namespace hacknet-system --wait AttacknetRun bounded-run
$ATTACKNET delete --namespace hacknet-system --wait FaultCampaign partition
$ATTACKNET delete --namespace hacknet-system --wait BurnchainPolicy minimal
$ATTACKNET delete --namespace hacknet-system --wait StacksNetwork minimal
```

Foreground deletion waits for controller finalizers. Deleting a
`StacksNetwork` deletes actor PVCs; suspension retains them.

## Burnchain cadence

Bitcoin Core and the Stacks-blind clock are separate failure domains. Change
clock policy without replacing Bitcoin Core:

```bash
$ATTACKNET burnchain status --namespace hacknet-system minimal
$ATTACKNET burnchain pause --namespace hacknet-system minimal
$ATTACKNET burnchain cadence --namespace hacknet-system --interval 20s minimal
$ATTACKNET burnchain resume --namespace hacknet-system minimal
$ATTACKNET burnchain flash --namespace hacknet-system \
  --blocks 3 --request-id operator-flash-3 minimal
```

Flash request IDs are idempotency keys. Status distinguishes requested policy,
observed generation, Bitcoin height, acknowledgement, and errors.

## Faults and runs

A `FaultCampaign` contains stages; each stage may contain multiple actions.
The controller admits the union of potentially overlapping signer weight,
miners, burnchain actors, resources, and mechanisms. A partial injection must
roll back and cannot pass.

```bash
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign-concurrent.yaml
$ATTACKNET wait --namespace hacknet-system --for terminal \
  FaultCampaign concurrent-network-and-dns
```

An `AttacknetRun` seals its execution DAG, trusted trigger receipts, budgets,
network inventory digest, and template digests before starting children. It
may overlap declared independent executions, replay on a fresh network with
the same immutable actor images, and run bounded removal-only minimization.
Ambiguous marginal effects remain `Inconclusive`.

Do not create raw Chaos Mesh resources for product workflows. They bypass
Attacknet admission, attribution, cleanup, and evidence semantics.

## Dashboards

Start loopback-only forwards through the typed client:

```bash
$ATTACKNET dashboard start --target grafana --namespace hacknet-system
$ATTACKNET dashboard start --target chaos
$ATTACKNET dashboard status --target grafana
$ATTACKNET dashboard stop --target grafana
```

The client discovers an exact Service, proves the listener, and records the
owned PID plus command. `stop` refuses to signal a reused or mismatched PID.
Forwards do not auto-reconnect after process or cluster restart; inspect
`status` and start them again explicitly.

Chaos Dashboard authorization remains a cluster installation decision. Never
disable authentication or grant cluster-wide Chaos permissions on a shared
cluster.

## Evidence and incident response

Capture evidence before deleting or replacing the network:

```bash
$ATTACKNET evidence snapshot --namespace hacknet-system \
  --output /tmp/run.json AttacknetRun bounded-run

$ATTACKNET evidence incident --namespace hacknet-system \
  --output /tmp/attacknet-incident-minimal minimal
```

The incident collector binds to the admitted inventory, verifies exact Pod
UIDs before reading logs, captures exactly owned resources and UID-scoped
Events, enforces resource/byte/time bounds, and records omissions rather than
silently substituting replacement data. External Prometheus/Loki artifacts and
terminal run records still need separate preservation.

On a failed or inconclusive run, do not restart the target merely to clear a
check. Preserve controller status, admitted Pods, mutations, logs, metrics,
events, and PVCs until root-cause attribution is complete. See
[`evidence.md`](evidence.md) and
[`failure-attribution.md`](failure-attribution.md).

## Troubleshooting

| Symptom | First action |
| --- | --- |
| Missing v1beta1 API | Run `attacknet doctor`; inspect CRDs and both controller Deployments. |
| Image pull failure | Rebuild, then use `attacknet image load` for every actor image. |
| Network Pending | Inspect the referenced `BurnchainPolicy`, Pod status, and Conditions. |
| Campaign waiting | Inspect its admitted inventory, shared mutation lease, and cumulative run budget. |
| Inconclusive result | Preserve evidence; inspect identity divergence, effect ambiguity, and rollback. |
| Pod Pending after node loss | Inspect PVC node affinity; portable cross-node CSI is outside Release 1. |
| Unsupported native fault | Use `io-pressure` or application `clock-skew`; do not bypass capability admission. |

Headlamp or another cluster viewer may be installed independently. Give it a
bounded viewer identity; actor Pods remain credential-free.
