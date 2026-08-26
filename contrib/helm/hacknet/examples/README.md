# Hacknet examples

These Kubernetes resources use YAML because they are intended for people to
read, edit, and submit with `kubectl`. JSON remains the canonical encoding for
digests, evidence, and other machine-generated artifacts.

The Go contract suite decodes each YAML resource through the production typed
CLI. Controller-generated CRDs are checked against the v1beta1 Go field model.

Apply `minimal-burnchain-policy.yaml` and `minimal.yaml` together for the first
live smoke. `accepted-28.yaml` demonstrates the accepted-scale topology but
requires the referenced miner, signer, and enrollment Secrets to exist first.
Apply `accepted-28-burnchain-policy.yaml` with it. Its bootstrap height is 202
so Stacks actors observe the configured epoch transitions; pre-mining past
those transitions can leave Kubernetes healthy while the protocol has no
canonical anchor. The shared bootstrap peer and `spec.genesis` make every
generated Stacks node join the same P2P and genesis networks. Complete miner
configs supplied by Secret must reproduce that genesis contract exactly.
`mixed-versions.yaml` demonstrates per-actor images and also requires the named
complete-config Secrets plus a compatible `BurnchainPolicy`.

Complete Stacks node and signer configs can refer to logical actors as
`${SERVICE:actor-name}`; node configs can additionally use `__NODE_IP__`. The
actor Pod resolves these placeholders at startup, so Secret contents stay
opaque to the topology operator. An unknown actor reference prevents startup
instead of leaking an unresolved token into the process configuration.

Additional human-editable campaign and run examples live under
`contrib/attacknet/examples/`. Machine-generated evidence, digests, and build
or version-matrix plans intentionally remain canonical JSON.
