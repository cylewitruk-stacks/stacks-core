# Bitcoin split-view campaigns

A Bitcoin split view requires multiple Bitcoin nodes, an explicit Bitcoin P2P
graph, and Stacks actors bound to those independent views. Attacknet composes
the existing mechanisms instead of introducing a special split-view fault:

1. `StacksNetwork` admits the Bitcoin graph and Stacks-to-Bitcoin bindings.
2. `NetworkChaos` keeps selected Bitcoin peer links partitioned or delayed.
3. A bounded A9 `burnchain-reorg` action constructs a competing higher-work
   branch on an isolated regtest node.
4. Protocol assertions prove divergence and stable recovery independently on
   the Bitcoin and Stacks layers.

The complete example consists of:

- [`multi-bitcoin-policy-a.yaml`](../../../helm/hacknet/examples/multi-bitcoin-policy-a.yaml);
- [`multi-bitcoin-policy-b.yaml`](../../../helm/hacknet/examples/multi-bitcoin-policy-b.yaml);
- [`multi-bitcoin.yaml`](../../../helm/hacknet/examples/multi-bitcoin.yaml);
- [`bitcoin-competing-branches.yaml`](../../examples/campaigns/bitcoin-competing-branches.yaml);
- [`bitcoin-propagation-delay.yaml`](../../examples/campaigns/bitcoin-propagation-delay.yaml); and
- [`bitcoin-split-view.yaml`](../../examples/runs/bitcoin-split-view.yaml).

## Topology contract

`peerRefs` are directed persistent Bitcoin `addnode` edges. They affect peer
discovery and reconnection, not Pod startup ordering. Use two directed edges
for a symmetric link. Each multi-Bitcoin node needs a distinct
`BurnchainPolicy`, and each Stacks actor selects its view with
`burnchainNodeRef`. Exactly one policy should establish a fresh shared regtest
chain. Secondary follower policies use `bootstrapHeight: 0`,
`reserveOutputs: 0`, and `paused: true`; otherwise their default reserve blocks
can create a competing suffix before Bitcoin P2P converges.

`rpcPort` and `p2pPort` are optional per-node overrides. When supplied, the
operator applies them consistently to the Bitcoin Service and process, peer
edges, bound Stacks node configuration, cadence clock, startup dependencies,
and admitted topology. Omit them to use regtest ports `18443` and `18444`.

The topology controller publishes `status.burnchainTopology` after every
Bitcoin workload and policy identity is admitted. Unrelated Stacks actor
availability does not change that structural graph; the complete admitted
actor inventory remains a separate campaign-admission requirement. The graph
digest covers normalized edges, policy names and UIDs, and Stacks bindings,
but not timestamps, resource versions, or the separately reported network
generation. Therefore removing and restoring an edge restores the graph digest
while admission still detects the intermediate generation change. Semantic
mutation and protocol observation recheck the relevant live Pod and policy
identities. A changed graph or unplanned replacement fails closed rather than
retargeting the campaign.

The R1 generated Stacks profile effectively remains at Epoch 3.4 by parking
Epoch 4 at reward-phase burn height 1,000,005. It does not deploy the sBTC
contracts needed for the transition. An Epoch 4 split-view scenario must
provide complete node configs and provision those contracts independently.

## Run the example

Install Attacknet and load the Stacks image first. Submit each Kubernetes
resource separately; the CLI deliberately accepts exactly one document per
file so that validation and receipts remain unambiguous:

```bash
attacknet submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/multi-bitcoin-policy-a.yaml
attacknet submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/multi-bitcoin-policy-b.yaml
attacknet submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/multi-bitcoin.yaml
attacknet wait --namespace hacknet-system --for condition=Ready \
  StacksNetwork multi-bitcoin

attacknet submit --namespace hacknet-system \
  --file contrib/attacknet/examples/campaigns/bitcoin-competing-branches.yaml
attacknet submit --namespace hacknet-system \
  --file contrib/attacknet/examples/runs/bitcoin-split-view.yaml
attacknet wait --namespace hacknet-system --for terminal \
  AttacknetRun bitcoin-split-view
```

The propagation-delay template exercises an admitted Bitcoin edge without
changing chain state. The competing-branch template holds the partition while
the A9 worker replaces two blocks with three on `bitcoin-b`. The run passes
only after both Bitcoin nodes report distinct tips, their bound Stacks
followers report distinct burn views at their respective Bitcoin nodes' current
heights, and both cohorts later remain converged for their declared stable
windows.

## Evidence and safety

Bitcoin branch evidence includes height, full best-block hash, chainwork, chain
tips, peer identity and last block/transaction receipt times, policy identity,
and observation time. Stacks evidence
includes the bound Bitcoin actor plus burn block height and consensus hash.
These values are actor-self-reported but are collected through an
identity-bracketed controller path; Kubernetes identity and topology bindings
remain orchestrator-observed.

Prometheus exports the admitted nodes, directed edges, and Stacks bindings as
orchestrator-observed info metrics. Actor clocks export bounded numeric branch
fingerprints, chainwork, height, tip counts, and peer counts for visualization. Full
hashes stay in structured evidence rather than metric labels, avoiding
unbounded cardinality. Missing, stale, malformed, or identity-shifted evidence
is `Pending` and eventually `Inconclusive`; it is never a pass.

All branch mutation is regtest-only. The campaign still requires A9's explicit
burnchain opt-in, reorganization bounds, protocol-boundary policy, mutation
lease, and typed RPC surface. A partition without distinct tips does not prove
a split, and a healed Chaos Mesh resource does not prove protocol recovery.

The overview dashboard correlates the admitted graph, Bitcoin heights, branch
fingerprints and cumulative work, bound Stacks burn-view fingerprints, and the
shared fault/assertion timeline. Numeric fingerprints are visual aids only;
the structured evidence remains authoritative.

After a terminal run, capture evidence before teardown:

```bash
attacknet evidence incident --namespace hacknet-system \
  --output evidence/bitcoin-split-view multi-bitcoin
attacknet teardown --namespace hacknet-system \
  --output evidence/bitcoin-split-view-teardown \
  --run bitcoin-split-view multi-bitcoin
```

Replay requires a fresh network identity and the same resolved images, graph,
policies, seed, campaign template, and schedule. The checked-in run leaves
automatic replay disabled because it does not provision a fresh network; use a
generated replay descriptor for qualification or reduction workflows.
