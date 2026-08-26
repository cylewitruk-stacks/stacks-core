# Attacknet configuration assets

Static inputs that are mounted or applied by the local product live here:

- [`bitcoin/bitcoin.conf`](bitcoin/bitcoin.conf) configures Bitcoin Core
  regtest actors.
- [`chaos/dashboard-cluster-access.yaml`](chaos/dashboard-cluster-access.yaml)
  is the optional local-only Chaos Mesh dashboard access policy.

Kubernetes authoring examples belong in [`../examples/`](../examples/), not in
this directory.
