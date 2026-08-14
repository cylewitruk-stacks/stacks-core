# Stacks Network Observer

This ASTRYX-based operations console visualizes the enrolled Stacks telemetry
federation together with bounded public Stacks chain data. It reports joined-
actor coverage, chain progress, current/next reward sets, public signer keys and
weights, signer state-machine self-observation, evidence-qualified native
topology, queue pressure, bounded blocking causes, and explicit telemetry blind
spots. An enrolled signer is joined to its declared companion, and persistent
burn-height drift between a fresh companion and a stale signer state machine is
raised as a critical synchronization incident. It does not claim permissionless
whole-network coverage or invent an edge the v1 schema does not observe.

The **Topology** view deliberately separates aggregate and identity-qualified
evidence. Every actor reports a scalar native-connection count. It also exports
one bounded current-series label per connected transport PeerId; the central
projection draws an edge only when that public-key-derived identity has one
unique binding in the server-owned enrollment registry. Unknown external peers
remain represented only in the scalar count. One-sided reports are dashed and
reports from both enrolled endpoints are solid. Configured signer–companion
service bindings use a separate neutral tether and are never counted as
connectivity.

## Live libp2p PoC

From the repository root:

```bash
docker compose -f docker/libp2p-poc/compose.yaml down --volumes --remove-orphans
docker compose -f docker/libp2p-poc/compose.yaml up --build --detach
open http://localhost:4319
```

The landing page is intentionally public-safe. Sign in to the federation
operations view with the fixed development credentials:

```text
email:    user@host.com
password: stacks123
```

These credentials are committed fixtures and provide no security. The PoC
provider must be explicitly enabled and is isolated behind a provider-neutral
principal/session boundary so a deployment can replace it with Google or
GitHub OIDC. Production use also requires TLS, durable sessions, IdP issuer and
audience validation, organization/group authorization, and operational
offboarding.

The maximum Compose environment runs 28 isolated actor agents: three miners,
ten signer/companion pairs, and five outsider followers. Each agent scrapes only
its actor's private Prometheus endpoint, removes every resource and label
outside the machine schema, and exports OTLP/HTTP with a different development
bearer token. One isolated central Collector receiver per actor authenticates
those tokens and overwrites actor identity from server configuration.
Prometheus stores the resulting bounded series. Separately, the observer reads
public `/v2/pox` and
`/v3/stacker_set/{cycle}` data without a federation credential. A server-owned
enrollment registry binds signer actor IDs to their public keys and optional
entity names; the observer joins the two sources and publishes snapshots over
SSE.

The authenticated **Metrics** view projects every series in the exact machine
allowlist. It keeps one-hot states and bounded event classes visible per actor,
and reduces signer latency histograms to sample count, mean, and p95. Missing
series stay unknown. The block-propagation panel compares the processing
timestamps of enrolled nodes that report the same Stacks height and combines
that adoption spread with cumulative announcement, direct-push, object, and
fetch evidence. Because the v1 metric contract does not carry a block ID, the
UI explicitly describes this as height adoption and does not claim to
distinguish same-height forks.

Signer rows display the height most recently read from their configured local
node, not independent signer chainstate. The cheap node-tip observation is
refreshed every ten seconds and carries a separate last-observed timestamp;
account and PoX metadata retain their slower one-minute poll. The federation
also compares the signer's event-driven state-machine burn height with the
enrolled companion's node height. Drift beyond the configured bound is reported
only after the state has remained unchanged for a bounded grace period, avoiding
false incidents during ordinary event delivery while detecting a live but
miswired observer path.

Anonymous `/api/public/*` responses contain only copied public chain and
reward-set fields. `/api/federation/*` responses require an `HttpOnly`, bounded
server-side operator session; actor IDs, topology, incidents, signer state
machines, and the per-signer quorum flight recorder never cross the public
route. OTLP bearer tokens cannot be used to read the observer.

There is no observer reporter, protected-RPC polling, custom observation POST,
HMAC replay state, pseudonym adapter, or in-memory ingestion store. The Stacks
process never receives the federation token. The repository tokens are public
regtest fixtures and are not security controls; production deployments must
issue unique secret tokens and use TLS.

Trace federation is structurally disabled. Existing libp2p spans have not yet
passed the serialized-OTLP privacy gate, and some contain raw PeerIds. Building
with the local `otel` feature does not authorize a federation trace listener.

Run the clean-volume maximum-topology soak, including every required seeded
failure class and at least 300 newly observed burn blocks, with:

```bash
docker/libp2p-poc/poc.sh soak
```

The soak checks all 28 actor streams, cross-actor token rejection, at least 300
new burn blocks from the recorded start height, canonical convergence, signer
quorum, signer/companion drift, retry/queue amplification, companion-only
abstention and recovery, and that stopping the central Collector creates a
dashboard blind spot while mining and signing continue.

## Local dashboard development

```bash
npm ci
npm test
npm run check
npm run build
npm run dev
```

The Vite UI is available at <http://localhost:5173> and proxies the observer on
port 4319. The standalone Compose file starts an empty Collector, Prometheus,
and observer backend; use the top-level libp2p PoC for real actor data.

This `contrib/` toolchain is exact-pinned but is not part of required Rust CI.
Maintainers changing it must run the commands above and validate both Collector
configs with the pinned 0.158.0 image.

## Security boundary

- Actor identity, role, chain, network, and coarse region are overwritten by
  the authenticated receiver pipeline; caller agreement is not validation.
- Both actor and central pipelines enforce the exact metric-name and bounded
  label allowlists in `federation/schema.json`.
- Transport PeerIds are permitted only on the exact current-link metric. The
  server consumes them for the enrollment join and does not copy them into the
  client metric catalogue. Endpoints, addresses, private/miner keys, arbitrary
  payload identifiers, arbitrary errors, host/container labels, and tokens are
  forbidden.
- Compressed signer public keys are deliberately allowed only on the exact
  authenticated-link/quorum metrics and in the public reward-set view. They are
  public chain data, are curve-validated by Rust and format-validated at both
  Collector boundaries. Named
  decisions and latency are restricted to authenticated federation operators.
- Actor-to-actor lines require a current connected PeerId that resolves to one
  uniquely enrolled transport identity. Dashed lines are one-sided reports;
  solid lines are corroborated by both enrolled endpoints. Scalar connection
  counts and unknown identities are not converted into invented edges.
- Canonical public block IDs are the only pre-approved chain-correlation value,
  and are not currently emitted as metric labels.
- Collection, export, storage, and dashboard failures are bounded and cannot
  influence peering, mining, signing, scoring, or consensus.

The normative privacy review checklist and rollout decisions live in
`.docs/11-otlp-federation.md`.
