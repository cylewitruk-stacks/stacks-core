# Typed Go CLI migration

The A5 CLI foundation lives in the Hacknet operator Go module at
`contrib/helm/hacknet/operator/cmd/attacknet`. This location lets the CLI import
the exact v1beta1 API and canonical packages used by the controllers without a
second copy of either contract. A later repository-layout change may move the
whole Go module; it must not create parallel API types.

## Responsibility boundary

The CLI is a typed Kubernetes and host client. It may:

- strictly decode one v1beta1 YAML or JSON resource;
- submit desired state through server-side apply;
- get, watch, or wait for fresh controller status;
- capture a bounded resource/status snapshot or admitted-identity incident bundle;
- diagnose Kubernetes and Attacknet API availability;
- manage Helm, local images, and port-forwards behind narrow host interfaces.

The CLI may not admit faults, advance phases, infer successful injection,
choose recovery, alter controller-owned status, or acquire a competing mutation
authority. Those are controller workflows.

## Commands

```text
attacknet submit --file network.yaml --namespace experiment
attacknet convert --file legacy-campaign.json --output yaml
attacknet get --namespace experiment StacksNetwork network
attacknet watch --namespace experiment AttacknetRun soak
attacknet wait --namespace experiment --for condition=Ready StacksNetwork network
attacknet wait --namespace experiment --for terminal AttacknetRun soak
attacknet delete --namespace experiment --wait FaultCampaign partition
attacknet evidence snapshot --namespace experiment --output run.json AttacknetRun soak
attacknet evidence incident --namespace experiment --output incident network
attacknet teardown --namespace experiment --output teardown \
  --run soak network
attacknet doctor --output json
attacknet image build --repo-root . --stacks
attacknet image load --mode require stacks-core-attacknet:main
attacknet install local --chart-dir contrib/helm/hacknet --kind-image-load require
attacknet dashboard start --target grafana --namespace experiment
attacknet dashboard start --target chaos
attacknet dashboard status --target grafana
attacknet dashboard stop --target grafana
attacknet burnchain pause --namespace experiment clock
attacknet burnchain cadence --namespace experiment --interval 2s clock
attacknet burnchain flash --namespace experiment --blocks 3 --request-id manual-3 clock
attacknet commands --json
```

Options precede positional `KIND NAME` arguments. Kind names and plurals are
accepted for reads; submitted documents require canonical Kubernetes Kind
spelling and `testing.stacks.org/v1beta1`.

`submit` rejects duplicate/unknown fields, multiple documents, status,
server-assigned metadata, owner references, and finalizers. It uses
server-side apply without force ownership takeover. `submit --dry-run` uses
Kubernetes server-side dry-run as a machine-readable admission plan; it does
not claim that a controller workflow executed. `wait` only accepts status
whose `observedGeneration` covers the current resource generation. `evidence
snapshot` explicitly does not claim to be a complete incident bundle.
`delete --wait` uses foreground deletion and waits for controller finalizers and
owned-resource garbage collection to remove the requested resource.
Use `teardown` rather than `delete StacksNetwork` for normal experiment
shutdown. It makes a complete identity-bound incident capture and retained
Loki interval export a deletion barrier. Incomplete evidence preserves the
network and returns a non-zero status; direct `delete` remains an explicit
administrative escape hatch.

Dashboard access is loopback-only. `dashboard start` resolves exactly one
Service through the Kubernetes API, starts `kubectl port-forward`, waits for
the local listener, and records its exact PID and command identity in a
per-user state directory. `stop` signals only a process whose command still
matches that identity, so stale PID reuse fails closed. `status` is read-only
and distinguishes a live listener, a starting process, stale state, and no
owned process. Grafana defaults to the active namespace and port 3000; Chaos
Mesh defaults to namespace `chaos-mesh` and port 2333. Local ports must remain
unprivileged.

`evidence incident` reads current API-server state, binds logs to exact
`StacksNetwork.status` Pod names and UIDs, captures exactly owned resources and
UID-scoped Events, and publishes a private directory atomically. Time,
concurrency, artifact count, per-artifact bytes, total bytes, resource count,
event count, and log lines are all bounded. Replacement-Pod logs are omitted
instead of being misattributed. The collector records observations and errors;
it does not decide whether an experiment passed.

`image build` executes Docker directly without a shell and emits immutable
local image IDs. `image load` derives each selected platform's runtime config
digest from the exported archive, replaces an existing mutable tag, imports it
into every discovered kind-on-Docker node, and verifies the resulting CRI image
ID. `install local` content-tags all five chart-selected images, optionally
loads them, applies CRDs explicitly, waits for `Established`, and then performs
a Helm 3 atomic or Helm 4 rollback-on-failure install. Conflict takeover and
failed-release recovery are conspicuous opt-ins.

`convert` is an offline compatibility aid for v1alpha1 single-fault
`FaultCampaign` and serial `AttacknetRun` resources. It preserves safety limits
and turns serial delays into explicit terminal dependencies. It refuses
`StacksNetwork` because the v1beta1 aggregate topology and burnchain-policy
choices cannot be inferred losslessly, and it refuses legacy semantics that
have no exact v1beta1 representation.

Help, `commands --json`, validation, conversion, and image builds work without
Kubernetes configuration. Runtime commands use the active kubeconfig context
and namespace unless `--namespace` is supplied.

## Legacy migration map

| Go command | Superseded compatibility inputs | Deliberately controller-owned |
| --- | --- | --- |
| Strict typed document loading | JSON-only compatibility readers | Controller status mutation |
| `submit`, `get`, `watch`, `wait`, `delete` | Generated-directory lifecycle wrappers | Bootstrap/readiness state machines |
| `evidence snapshot`, `evidence incident`, `teardown` | Host ledger and forensic shell collectors | Incident classification and runtime-effect proof |
| `doctor` API check | Process-output Kubernetes diagnostics | Controller readiness decisions |
| Generated command contract | The frozen Node command registry | Controller workflow descriptions |
| `dashboard start`, `status`, `stop` | Shell port-forward supervisors | Chaos Mesh authorization policy |
| `image build`, `image load`, `install local` | Shell image/build/install helpers | Workload reconciliation and image admission |
| `burnchain status`, `pause`, `resume`, `cadence`, `flash` | Shell clock-policy mutation | Clock execution and acknowledgement |

The Go binary is the supported public surface. The retired shell and Node
implementations are not shipped in the current tree; digest-verified
compatibility vectors preserve the bounded v1alpha1 contract. Historical
arguments remain available in their pinned Git revisions and are not a current
compatibility contract.

## Known risks and follow-up

- The current kind catalog is intentionally closed to the four v1beta1
  resources. Arbitrary Kubernetes apply would bypass the product boundary.
- `evidence incident` captures Kubernetes state and bounded Pod logs;
  `teardown` additionally exports the complete retained Loki interval before
  deleting the network. Prometheus range export remains separate.
- `doctor` checks the cluster and CRDs. Local install and image commands perform
  their own stronger Docker, Helm, kind, and immutable-image checks.
- Watch output reflects observed Kubernetes ordering and is not a deterministic
  replay artifact.
- Server-side apply preserves another manager's fields and refuses conflicts;
  the CLI never uses force implicitly.
- Dashboard forwards do not automatically reconnect after a Kubernetes or host
  restart; `status` reports the loss and a new explicit `start` recreates it.
