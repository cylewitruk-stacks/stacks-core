# Hacknet examples

These Kubernetes resources use YAML because they are intended for people to
read, edit, and submit with `kubectl`. JSON remains the canonical encoding for
digests, evidence, and other machine-generated artifacts.

The Go contract suite decodes each YAML resource through the production typed
CLI. Controller-generated CRDs are checked against the v1beta1 Go field model.

Apply `minimal-burnchain-policy.yaml` and `minimal.yaml` together for the first
live smoke. `accepted-28.yaml` demonstrates the accepted-scale topology but
requires the referenced miner, signer, and enrollment Secrets to exist first.
Apply `accepted-28-burnchain-policy.yaml` with it. Its bootstrap height is 101,
which releases actors after the first funding output matures while preserving
the pre-epoch interval for sync, stacking, signer startup, and initial Stacks
blocks. Releasing actors immediately before or after an epoch transition can
leave Kubernetes healthy while the protocol has no canonical anchor. The
shared bootstrap peer and `spec.genesis` make every
generated Stacks node join the same P2P and genesis networks. Complete miner
configs supplied by Secret must reproduce that genesis contract exactly.
`mixed-versions.yaml` demonstrates per-actor images and also requires the named
complete-config Secrets plus a compatible `BurnchainPolicy`.

`adversarial-signer-policy.yaml` and `adversarial-signer.yaml` demonstrate a
three-signer cohort with one explicitly patched testing signer and its separate
signed observer. The example records the exact testing patch and policy
digests, restricts both actors' egress, and requires the named private config
and enrollment Secrets. Submit the matching
[`signer-withhold-window.yaml`](../../attacknet/examples/campaigns/signer-withhold-window.yaml)
before the policy's Stacks-height window opens.

`multi-bitcoin.yaml` demonstrates two Bitcoin nodes with persistent directed
peer edges and one Stacks follower bound to each Bitcoin node. Apply
`multi-bitcoin-policy-a.yaml` and `multi-bitcoin-policy-b.yaml` first. The
primary policy bootstraps the shared chain. The secondary policy starts paused
at height zero so it follows that chain instead of mining an unrelated
equal-work bootstrap. Its Attacknet campaign and run are described in the
[Bitcoin split-view guide](../../attacknet/docs/concepts/bitcoin-split-views.md).

`peerRefs` are directed persistent `addnode` relationships, not startup
dependencies. Declare both directions when both nodes should reconnect after a
partition. Cycles are valid and do not create an init-container dependency
cycle. A multi-Bitcoin topology must bind each Bitcoin node to a distinct
`BurnchainPolicy`; `spec.burnchain.policyRef` remains the default for the
single-node case. Generated Stacks workloads wait for their selected policy's
bootstrap-ready endpoint before starting, while Bitcoin peer edges remain
ordinary discovery relationships and never become startup dependencies.

Complete Stacks node and signer configs can refer to logical actors as
`${SERVICE:actor-name}`; node configs can additionally use `__NODE_IP__`. The
actor Pod resolves these placeholders at startup, so Secret contents stay
opaque to the topology operator. An unknown actor reference prevents startup
instead of leaking an unresolved token into the process configuration.

Additional human-editable campaign and run examples live under
`contrib/attacknet/examples/`. Machine-generated evidence, digests, and build
or version-matrix plans intentionally remain canonical JSON.
