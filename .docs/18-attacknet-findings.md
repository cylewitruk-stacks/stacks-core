# Attacknet findings ledger

This ledger records pains and reliability, liveness, security, and operability
findings surfaced while bringing the current-main Stacks stack into the
Kubernetes attacknet. It deliberately includes harness defects: trustworthy
experiments require the apparatus to fail visibly and converge exactly.

## Classification

- **Upstream candidate**: behavior in today's Stacks/Signer code that may merit
  a standalone issue or fix.
- **Harness defect**: attacknet/operator behavior that can invalidate evidence.
- **Environment prerequisite**: a condition the preflight must measure and
  report, rather than misclassifying the resulting failure as a Stacks bug.
- **Resolved extraction mismatch**: branch/Compose assumptions removed while
  porting to current main.

## F-001: Docker Desktop's shared VM disk can be full while Kubernetes reports no DiskPressure

- Classification: environment prerequisite
- State: mitigation implemented manually; automated kubelet-filesystem
  preflight implemented and pending capacity-run verification
- Evidence: Bitcoin Core exited before writing regtest genesis with `Disk space
  is too low`; its new PVC contained 296 KiB and was Bound. The worker reported
  `DiskPressure=False`, while `df` inside the kind worker showed its shared
  95 GiB `/var` filesystem at 100%. Docker reported 17.92 GB of entirely
  reclaimable build cache. Pruning only unused build cache restored 12 GB free.
- Risk: a harness can attribute an infrastructure-capacity failure to Bitcoin,
  or enter CrashLoopBackOff before any experiment starts.
- Required action: capacity preflight must record filesystem free bytes from
  every kind node and fail early below a documented floor. Evidence must retain
  both Kubernetes conditions and actual filesystem capacity because they can
  disagree.

## F-015: Local kubectl is outside the supported client/server version skew

- Classification: environment prerequisite / tooling ambiguity
- State: recorded; matching-client packaging remains open
- Evidence: the local client is Kubernetes 1.34 while the reset Docker Desktop
  cluster is 1.36. Every version query warns that the difference exceeds the
  supported minor-version skew of plus or minus one.
- Risk: a failed command can be misclassified as an operator or CRD defect when
  its client serialization/behavior is unsupported by the API server version.
- Required action: capture both versions in every run descriptor and evidence
  bundle, warn or fail in strict preflight when skew exceeds one minor, and
  provide a matching kubectl through the attacknet tool image or documented
  local prerequisite.

## F-016: Nakamoto block ingress is absent from current-main node metrics

- Classification: production and attacknet observability gap
- State: confirmed in current main; bounded instrumentation pending
- Evidence: `stacks_node_stx_blocks_received_total` increments for legacy
  `StacksMessageType::Blocks`, while the `StacksMessageType::NakamotoBlocks`
  receive path has no receive counter. Existing tip-height and processed-block
  metrics show aftermath, not whether or how Nakamoto payloads arrived.
- Risk: during propagation or liveness incidents, a human cannot distinguish
  delivery failure from delayed processing through metrics alone. The gap is
  especially harmful in an adversarial network where receipt, validation,
  relay, and adoption are separate hypotheses.
- Required action: add bounded Nakamoto receive/serve/relay counters (with only
  low-cardinality source/outcome dimensions), expose them in the attacknet
  propagation dashboard, and retain logs/traces for per-block correlation.

## F-017: `private_neighbors=true` expands actor data-plane reach by design

- Classification: attacknet security boundary
- State: accepted for the isolated private cluster; network-policy control pending
- Evidence: the setting is required for kind Pod-to-Pod legacy P2P, but it also
  disables private-address filtering in peer registration, neighbor discovery,
  mempool sync, and StackerDB sync. A malicious actor may therefore advertise
  or attempt private/internal destinations.
- Risk: copying this profile outside an isolated attacknet could expose internal
  services or let malicious experiments reach the Kubernetes/API control plane.
- Required action: never present the option as a production default. Keep actor
  Pods credential-free and isolated; add scenario-aware egress NetworkPolicy
  that always protects the Kubernetes API/operator/control plane while allowing
  actor Pod CIDRs, DNS, Bitcoin, and deliberately selected adversarial targets.

## F-018: Capacity convergence was incorrectly sampled as an instantaneous invariant

- Classification: harness rigidity / false-negative finding
- State: fixed with a bounded, evidence-preserving convergence gate
- Evidence: stage one became Kubernetes Ready, released its 20-second Bitcoin
  cadence, and was sampled roughly five seconds later. All nodes correctly
  agreed at Stacks height zero, so the new nonzero-height invariant failed and
  aborted the entire capacity series before the first scheduled burn block.
- Risk: strict but mistimed assertions classify expected bootstrap latency as
  a protocol failure and make the harness sensitive to scheduler luck.
- Required action: poll strict invariants within an explicit convergence
  deadline. Preserve every failed attempt, the winning attempt, and attempt
  count so a slow-but-passing run remains visibly different from a fast pass.

## F-019: Post-activation actor readiness formed a cycle with paused cadence

- Classification: harness orchestration deadlock
- State: activation-aware lifecycle implemented; live verification pending
- Evidence: in the medium topology, miner 2 intentionally waited for burn
  height 223 before starting. The operator correctly reported 14/15 Ready, but
  lifecycle waited for 15/15 before releasing a Bitcoin clock paused at 202.
  Therefore the activation condition could never become true.
- Risk: delayed joins, upgrade-at-height scenarios, and future scheduled
  adversaries can deadlock before the experiment begins; a long startup timeout
  merely hides the causal cycle.
- Required action: record activation gates in the backend-neutral manifest.
  Wait only for the ungated bootstrap cohort, advance Bitcoin through policy at
  an explicit fast bootstrap cadence, require the full cohort after activation,
  then restore the requested steady cadence. Record every transition for replay.

## F-020: Node `require()` is not a general JSON-file reader for relative paths

- Classification: harness portability defect
- State: fixed
- Evidence: activation-aware lifecycle passed a relative evidence-tree manifest
  to `require(process.argv[1])`; Node treated the path as a package specifier and
  failed with `MODULE_NOT_FOUND`. Absolute paths happened to work in prior ad
  hoc runs, hiding the assumption.
- Risk: identical rendered inputs behave differently depending on the caller's
  path spelling, aborting runs after resources are already created.
- Required action: read caller-supplied artifacts explicitly through `fs` and
  parse JSON. Reserve `require()` for actual modules, and test lifecycle entry
  points with relative as well as absolute evidence paths.
- Recurrence: the first Chaos Mesh campaign found six remaining instances in
  `campaign-runner.sh` and three in timeline export before any fault was
  injected. The check suite now rejects this pattern across all attacknet
  shell/JavaScript sources so it cannot migrate to another entry point.

## F-021: Shared network labels made observability deadlock actor activation

- Classification: harness accounting defect
- State: fixed; clean capacity rerun required
- Evidence: the activation-aware bootstrap gate compared the number of Pods
  carrying `testing.stacks.org/network` with the actor-only workload count in
  the topology manifest. Enabling Prometheus, Grafana, and the event journal
  produced 18 network-labelled Pods for a 15-actor manifest, so the equality
  could never hold and Bitcoin correctly remained paused at height 202.
- Risk: adding trusted instrumentation can silently change experiment control
  flow. A run then appears to expose a protocol bootstrap failure even though
  the harness is waiting on incompatible resource populations.
- Required action: inventory actors by the server-enrolled actor identity label
  (`testing.stacks.org/actor`), inventory observability separately, and keep all
  readiness/accounting denominators explicit in evidence and dashboards.

## F-022: Delayed actors inherited a Compose-only discovery name

- Classification: backend portability defect
- State: fixed; clean capacity rerun required
- Evidence: Bitcoin advanced beyond the configured burn-height gate and the
  source miner reported burn 240, but `miner-2` remained in its join loop. The
  script defaulted to `miner-1`, valid Compose DNS; Kubernetes exposes the same
  actor as `<network>-miner-1`. An in-Pod request to the scoped Service returned
  the expected activation height immediately.
- Risk: upgrade-at-height and missed-upgrade experiments can remain silently
  gated, so a version under test appears absent rather than incompatible. DNS
  and endpoint assumptions are part of a version profile's executable contract.
- Required action: inject the backend-resolved source Service through an actor
  environment variable, test both renderers, and record resolved endpoints in
  the admitted run descriptor.

## F-023: Failure evidence capture aborted on the failed actor

- Classification: forensic harness defect
- State: fixed and live negative control passed
- Evidence: capture of the F-022 state stopped at the first unavailable
  `/v2/info` endpoint under `set -e`, precisely because the delayed actor had
  not started its RPC server. Admitted Kubernetes state was preserved, but the
  remaining metrics and logs were skipped.
- Risk: the most causally useful evidence disappears in the runs that need it.
  This violates the attacknet's freeze/preserve/explain contract and can turn a
  reproducible product defect into an unactionable red build.
- Required action: make every actor probe bounded and independently fallible,
  write explicit error markers rather than empty files, capture live peers and
  diagnostics alongside tips, and prove the collector completes with one or
  more deliberately unreachable actors.
- Verification: the collector subsequently completed across all 15 actors with
  `miner-2` RPC deliberately unavailable, preserving 12 metric snapshots, 18
  bounded logs, runtime state, and explicit JSON error markers for all three
  failed miner probes.

## F-024: Kubernetes resource usage had no Metrics API

- Classification: local-cluster capability gap
- State: open; kubelet summary fallback is available but not dashboarded
- Evidence: `kubectl top pods` returned `Metrics API not available` on the
  three-node Docker Desktop kind cluster, while authenticated kubelet summary
  calls returned per-Pod CPU, memory, filesystem, placement, and inode data.
- Risk: a campaign can pass protocol invariants while one actor exhausts a
  worker, and humans cannot correlate protocol degradation with contention in
  the primary dashboard.
- Required action: capture kubelet summaries at every stage regardless of
  metrics-server availability. Decide explicitly between installing
  metrics-server and granting a trusted, non-actor resource observer narrowly
  scoped node/proxy access; never give this authority to adversarial actors.

## F-025: Progress verification emitted concatenated JSON documents

- Classification: forensic evidence defect
- State: fixed; rerun required
- Evidence: the successful companion-failure campaign wrote the network cohort
  object followed immediately by the burn-progress object to one `.json` file.
  Shell exit status proved both checks passed, but no JSON parser could consume
  the artifact as a single document.
- Risk: automated triage, report generation, replay minimization, and later
  audit cannot reliably interpret a result that was only human-readable in the
  live terminal.
- Required action: emit one schema-shaped result containing `{ok, cohort,
  progress}` and validate every evidence JSON file before a run is finalized.

## F-026: Recovery duration included the post-recovery observation window

- Classification: observability semantic defect
- State: fixed; rerun required
- Evidence: the companion became healthy on the first post-clear verification,
  but `recovery.complete` reported 41 seconds because its clock stopped only
  after a subsequent 30-second burn-progress check.
- Risk: recovery SLOs appear slower as the verification window becomes more
  rigorous, making the metric measure harness policy rather than system repair.
- Required action: record clearance-to-health immediately when recovery
  invariants pass; report post-recovery progress as a distinct assertion and
  retain both timestamps in the incident timeline.

## F-027: Bitcoin-only progress produced a false healthy/recovered result

- Classification: harness false-pass and attribution defect
- State: fixed in the shared verifier; preserved stalled run is the negative control
- Evidence: the first full 31-workload run advanced bitcoind from height 1287
  to 1288 during a 25-second verification window while every one of the 18
  Stacks nodes remained at Stacks height 17. The old progress invariant
  inspected only `bitcoin-cli getblockcount`, so the companion fault campaign
  was initially labelled recovered even though Stacks had stalled before the
  fault was injected.
- Risk: external-chain progress can conceal a completely halted Stacks network,
  contaminating every recovery claim and making the injected fault appear
  causal when it is not.
- Required action: temporal progress now requires both the configured burnchain
  delta and a cohort-wide minimum Stacks-tip delta. It captures start and end
  cohorts, preserves both dimensions in the result, emits failed evidence before
  exiting nonzero, and must remain a deliberate negative control.

## F-028: A signer private key and funded genesis address diverged

- Classification: topology fixture defect with protocol-liveness impact
- State: root-caused and fixed; clean-run validation pending
- Evidence: zero-based signer 9 used private key `4a…4a01`, which independently
  derives testnet address `ST3MWT31K0SX74MHJCEWGZY5MR05X61FC5HEVK3W1`.
  Genesis instead funded `ST350FBN4H0EKWQCW6BTFK97RGXFS5QJ78E9NST20`.
  The latter retained its full unlocked genesis balance; the derived address had
  zero. The stacker logged the insufficient balance before the chaos campaign,
  retried indefinitely, and miners later reported no canonical PoX anchor.
- Risk: a typographical identity-fixture error can admit a full topology, mine a
  few Stacks blocks, then halt at a protocol boundary. Without preserved timing,
  it is easily misattributed to the first subsequent fault.
- Required action: fund the derived address, pass the expected funded addresses
  to the stacker, and fail immediately if any private key derives a different
  address. The topology test also asserts that every expected address appears in
  every miner's genesis balances.

## F-029: Zero unauthenticated conversations is too strict for an adversarial baseline

- Classification: harness rigidity / false-failure finding
- State: fixed in the baseline connectivity invariant
- Evidence: one snapshot saw signer companion 10 with 32 authenticated and one
  unauthenticated conversation; 25 seconds later it had 32 authenticated and
  zero unauthenticated. Requiring the latter count to be identically zero made
  the starting cohort fail on a normal in-progress handshake.
- Risk: an unauthenticated scanner or malicious handshake can fail every run on
  demand, turning a useful signal into a denial of the test harness itself.
- Required action: baseline connectivity requires at least one authenticated
  live inbound/outbound conversation per node and records the unauthenticated
  maximum. Separate bounded rate, age, and resource-pressure assertions—not
  mere presence—must classify handshake abuse.

## F-002: Branch-only config fields make current-main actors fail at startup

- Classification: resolved extraction mismatch
- State: fixed in the current-main topology renderer
- Evidence: current main rejected `burnchain.allow_stale_bitcoin_tip` as an
  unknown field. The value came from the libp2p development branch.
- Risk: mixed-version experiments can accidentally test config incompatibility
  instead of protocol compatibility.
- Required action: render profiles by binary/version and add a config-startup
  smoke for every image used in a mixed-version campaign.

## F-003: Legacy P2P advertised addresses require numeric sockets

- Classification: resolved extraction mismatch; upstream diagnostics candidate
- State: fixed in the attacknet with runtime container-IP substitution
- Evidence: a Kubernetes Service DNS name in `node.p2p_address` passed initial
  config loading but later panicked in `StacksNode::setup_peer_db` with `Failed
  to parse socket`. `connection_options.public_ip_address` failed earlier with
  a normal config error for the same DNS form.
- Risk: Kubernetes and other dynamic schedulers cannot embed ephemeral Pod IPs
  in static config, and the two related fields fail at different phases—one by
  process panic.
- Required action: the harness resolves and substitutes the runtime IPv4 into a
  writable config. Consider an upstream issue to validate `node.p2p_address`
  during config parsing and return a structured error instead of panicking.

## F-004: Signer/companion startup has an intentional cyclic relationship

- Classification: harness defect exposed by topology port
- State: fixed in the topology model; live verification in progress
- Evidence: the companion's durable event dispatcher must reach the signer
  before companion RPC becomes Ready, while a signer init gate waiting for that
  RPC prevents the signer event server from starting. The prior Compose harness
  explicitly used `service_started` and documented that the signer node client
  retries while the companion boots.
- Risk: translating `depends_on` mechanically into readiness/TCP gates creates
  a permanent simultaneous-start deadlock and invalidates restart tests.
- Required action: start signers concurrently, publish signer endpoints before
  readiness, retain explicit cycle diagnostics, and keep per-edge startup gates
  separate from target Service endpoint publication.

## F-005: StatefulSet merge-patch retains removed dependency init containers

- Classification: harness defect
- State: fixed by rendering an explicit empty `initContainers` list; broader
  exact-convergence audit remains open
- Evidence: the admitted signer actor had `dependencies: []`, and the local
  resource builder rendered no init container, but the live StatefulSet kept
  the previous `wait-for-dependencies` entry because JSON merge-patch preserves
  omitted fields.
- Risk: the operator can report the latest CR generation as observed while a
  stale execution constraint remains active, producing false evidence.
- Required action: explicitly clear removable list/map fields and audit every
  merge-patched resource field for the same omission semantics. Longer term,
  adopt a deliberate exact-reconciliation strategy (careful replace, JSON
  patch diff, or server-side apply ownership) rather than relying on omission.

## F-006: Runtime endpoint publication and startup gates are different controls

- Classification: harness design finding
- State: first-class `runtimeExposure: ready|reachable` implemented
- Evidence: `publishNotReadyAddresses` belongs to the target Service, whereas a
  dependency wait belongs to an incoming edge. One target cannot implement two
  callers' different gate semantics through a single Service readiness flag.
- Risk: conflating the controls either forbids realistic reachable-but-broken
  states or creates accidental bootstrap cycles. Endpoint withdrawal also does
  not disrupt established P2P connections.
- Required action: preserve target-level runtime exposure as a discovery knob;
  implement per-edge startup gates separately; use Chaos Mesh/process controls
  for established-connection faults.

## F-007: Cadence must not advance protocol boundaries during harness bootstrap

- Classification: harness defect / policy-orchestration finding
- State: fixed for fresh Kubernetes runs; clean-volume verification pending
- Evidence: while config and dependency failures were being repaired, the
  independent Bitcoin clock continued from its base height through multiple
  protocol boundaries. Bitcoin reached 250, while all Stacks nodes repeatedly
  processed burn 241 with `Missing canonical anchor block`; the miner had three
  Stacks blocks and followers had none. Reusing that state would make every
  subsequent result invalid.
- Risk: a resilient Bitcoin clock correctly keeps running, but an experiment
  controller that releases cadence before the system under test is assembled
  can manufacture irrecoverable boundary failures and misleading liveness
  findings.
- Required action: keep Bitcoin and its clock Stacks-blind. Render initial
  cadence policy as paused, allow Bitcoin to bootstrap idempotently to the
  regtest base, and let lifecycle policy release cadence only after all roles
  are live plus a bounded settling window. Always recreate clean PVCs after a
  failed bootstrap; never call later recovery evidence a baseline.

## F-008: Evidence collection did not fail closed on invalid arguments

- Classification: harness defect
- State: fixed
- Evidence: an accidentally reversed `EVIDENCE_DIR MANIFEST` invocation emitted
  repeated file and manifest errors, but the collector lacked strict shell mode
  and continued through later capture functions. In a larger workflow its exit
  status could therefore appear successful.
- Risk: a bundle can exist without the evidence it claims to contain—the same
  false-pass class this harness is intended to eliminate.
- Required action: the standalone collector now uses `set -euo pipefail` and
  retains explicit best-effort handling only for optional metrics/log sources.
  Campaign and soak drivers must also write explicit classification-error
  markers for intentionally non-blocking analysis steps.

## F-009: A loopback `data_url` cannot serve a remote legacy peer

- Classification: resolved extraction mismatch; incomplete initial diagnosis
- State: fixed with runtime container-IP substitution; independently required,
  but it was not the cause of the empty peer sets in the live run
- Evidence: `/v2/neighbors` on companion and follower showed the miner bootstrap
  peer at its Pod IP with `authenticated: true` during an early observation,
  yet both remained at Stacks height zero while the miner reached height four.
  The rendered current-main
  config still advertised `data_url = http://127.0.0.1:20443`, inherited from
  the libp2p environment where object transfer did not depend on the legacy
  peer's advertised HTTP endpoint. A later clean observation showed the primary
  connection failure was F-011; the loopback advertisement would still have
  prevented remote HTTP transfer once a peer attempted it.
- Risk: peer-count and authentication checks can look healthy while the data
  plane is unusable. A topology-only assertion would miss this completely.
- Required action: substitute the runtime container IPv4 into both P2P and
  data URLs, and retain the behavioral equal-height adoption assertion as the
  acceptance gate.

## F-011: Legacy P2P rejects Kubernetes Pod peers unless private neighbors are enabled

- Classification: resolved environment/config mismatch
- State: fixed and verified in a clean-volume stage-one run
- Evidence: follower and companion could reach the miner's RPC endpoint and
  resolved its bootstrap identity and Pod IP, but all three `/v2/neighbors`
  collections were empty. Current main defaults
  `connection_options.private_neighbors` to `false`; the config documentation
  states that this rejects incoming private-IP peers, avoids initiating to
  them, filters them from walks, and skips private peers for data transfer.
  All kind Pod addresses in this run were in `10.244.0.0/16`.
- Risk: a private-cluster harness can report healthy RPC/readiness while its
  actual Stacks data plane is completely disconnected. Peer identity and
  endpoint correctness do not override the private-address policy.
- Required action: render `private_neighbors = true` explicitly for private
  attacknet profiles, assert non-empty authenticated peer sets, and require
  cross-node Stacks-tip adoption—not merely common burn height—before accepting
  a capacity stage.

## F-012: Diagnostic probes require their own deadlines

- Classification: harness reliability finding
- State: identified; evidence collector hardening pending
- Evidence: an in-Pod connectivity probe without a portable client/deadline
  caused a parallel diagnostic batch to remain blocked until the outer tool was
  terminated. The actor image also lacks `nc`, so diagnostics cannot assume a
  full troubleshooting toolset inside production-like containers.
- Risk: one wedged or minimally provisioned actor can stall evidence capture
  and prevent the harness from recording the failure that caused the stall.
- Required action: give every probe a bounded outer deadline, record timeout or
  missing-tool outcomes explicitly, and prefer a dedicated diagnostic workload
  or language/runtime already guaranteed by the actor image.

## F-013: `/v2/neighbors` bootstrap authentication is not live-connectivity evidence

- Classification: observability/API semantic ambiguity
- State: identified; attacknet interpretation and behavioral gates corrected
- Evidence: the endpoint constructs `bootstrap` and `sample` rows from PeerDB
  candidates and reports `authenticated: true` without consulting a live
  conversation. Only `inbound` and `outbound` enumerate conversations and use
  their actual authentication state. This made an early failed run appear to
  have an authenticated bootstrap connection even while every live connection
  set and neighbor gauge was empty.
- Risk: topology UIs and health gates can draw or count configured candidates
  as working data-plane edges, producing a false connected-network result.
- Required action: use only authenticated inbound/outbound conversations (or
  live neighbor gauges) for connectivity. Show bootstrap/sample separately as
  configured or learned candidates, never as active edges.

## F-014: Equal-height-at-zero is not a useful post-bootstrap health invariant

- Classification: harness false-pass finding
- State: fixed in the shared verifier
- Evidence: an early snapshot at burn height 203 reported zero drift because
  every node was at Stacks height zero, even though no follower had yet adopted
  a Stacks block. The drift arithmetic was correct but incomplete as a stage
  acceptance condition.
- Risk: a wholly stalled or disconnected cohort can satisfy agreement-only
  gates.
- Required action: post-bootstrap verification now requires a configurable
  minimum observed Stacks height (default one) in addition to bounded burn and
  Stacks drift. Long-run gates must also require forward progress over time.

## F-010: Old ready replicas can make a new StatefulSet revision look Ready

- Classification: harness defect
- State: fixed; live rollout regression pending
- Evidence: immediately after the data URL changed, the CR reported `Ready 7/7`
  and lifecycle released burn cadence even though node Pods had not yet rolled.
  The operator counted only `status.readyReplicas`, which still described the
  prior StatefulSet revision.
- Risk: configuration/fault transitions can be declared complete while the
  system under test is still running old code or config. This contaminates
  start timestamps, stabilization windows, and post-fault recovery evidence.
- Required action: readiness now also requires StatefulSet generation to be
  observed, at least one updated replica, and equal non-empty current/update
  revisions. A regression test supplies an old ready replica during a pending
  generation and requires `Progressing`.

## F-030: Capacity preflight did not reserve space for the cold-run write burst

- Classification: harness/infrastructure reliability finding
- State: identified; admission-capacity guard pending
- Evidence: the first corrected full-topology launch exhausted Docker
  Desktop's shared VM disk while bitcoind was writing genesis state and Grafana
  was creating its SQLite database. Kubernetes had admitted the workloads and
  did not report node `DiskPressure`; the preflight sampled capacity before the
  cold-build and cold-start write burst rather than proving adequate headroom
  for it.
- Risk: a protocol run can fail for an apparatus resource limit and look like a
  node or consensus failure. A passing point-in-time capacity check is not a
  reservation and does not bound the subsequent write amplification.
- Required action: record Docker VM and Kubernetes ephemeral-storage headroom,
  set actor ephemeral-storage requests/limits where useful, and require a
  conservative free-space margin before a full launch. Classify ENOSPC as an
  infrastructure failure and capture it automatically.

## F-031: Cold IBD can queue stale observer events across signer initialization

- Classification: harness ordering defect exposing a transport-independent
  signer liveness defect
- State: baseline fix implemented; clean-cluster verification pending
- Evidence: all ten signers were declared Ready by an executable probe that
  only tested `/proc/1/status`. Their companion nodes performed rapid IBD while
  signer initialization was still failing. The signer event socket was already
  bound before the companion registered its observer, proving that TCP
  readiness alone is insufficient: the receiver accepted historical events
  into its in-process channel while the RPC-dependent runloop was
  uninitialized. A signer later initialized against companion burn height 216,
  then drained queued event heights beginning around 12; events at 142/143 and
  onward logged `fork detected` against the much newer state. No signer received
  a Nakamoto proposal and the network stalled after Stacks height 17.
- Risk: a test baseline can deterministically corrupt signer state before any
  fault is injected. The underlying condition—observer delivery substantially
  lagging the node's live RPC view—is also realistic after receiver outages or
  backpressure and should remain an explicit adversarial scenario.
- Required action: `stacks_signer_runloop_ready` distinguishes successful
  runloop initialization from process/TCP availability, but initialization is
  not participation. The corrected lifecycle advances by exact burn-height
  barriers: companion IBD with observers disabled, observer enablement before
  the reward-cycle transition, one block to calculate and observe the signer
  set, and an explicit current-cycle-registration gate before Nakamoto
  activation. The underlying delayed-event behavior is recorded separately as
  GH issue candidate 14. Add a deliberate stale-observer/backlog campaign and
  require it to produce a classified recovery or captured signer defect, never
  an unexplained stall.

## F-032: Incident capture accepted positional arguments but failed opaquely with flags

- Classification: evidence-tool usability finding
- State: fixed; regression invocation pending
- Evidence: an initial diagnostic invocation supplied named flags to the
  positional-only capture script. The command did not create the expected
  evidence tree and the mistake was discovered only by inspecting its output;
  a second positional invocation captured the complete incident.
- Risk: under time pressure, a syntactically plausible invocation can lose the
  highest-value evidence window while appearing to have run.
- Required action: the collector now supports exact positional or named forms,
  rejects unknown/missing arguments before collection, prints the resolved
  network/namespace/phase/destination, and retains its machine-readable
  completeness marker.

## F-033: Attacknet image builds sent multi-gigabyte non-build assets to Docker

- Classification: harness build-efficiency and disk-reliability finding
- State: fixed; next cold-build context size verification pending
- Evidence: a cold `contrib/attacknet/Dockerfile` build transferred a 2.15 GiB
  context even though `target/`, generated topology, and evidence were already
  ignored. More than 1.8 GiB came from non-workspace fuzz corpora under
  `stacks-signer-bridge/` and `stacks-network/`; the dashboard source tree and
  legacy Docker harness added further unrelated data.
- Risk: each rebuild writes needless data into Docker Desktop's shared VM,
  lengthens the feedback loop, and increases the likelihood of the ENOSPC
  infrastructure failure in F-001/F-030.
- Required action: `.dockerignore` now excludes the non-workspace fuzz,
  dashboard, and legacy Docker trees from this root-context build. Retain a
  build regression that verifies required Cargo workspace inputs remain
  present, and record context transfer size during future cold builds.

## F-034: Kubernetes Ready did not mean a signer could vote in the current cycle

- Classification: harness false-readiness finding and production observability
  gap
- State: metric and attacknet gate implemented; clean live verification pending
- Evidence: all signer Pods passed their readiness probes once the outer
  runloop initialized, but the retained run initialized them only after
  Nakamoto activation. Logs then reported `NoRegisteredSigners`; every signer
  received zero proposals and emitted zero votes. At the next reward-cycle
  boundary all nodes stalled with no canonical PoX anchor.
- Risk: a healthy process, HTTP endpoint, and initialized runloop can all be
  true while the signer contributes no weight. Orchestration and operator
  dashboards can report full availability during a network-wide participation
  failure.
- Required action: export bounded gauges for current- and next-cycle
  registration, require current-cycle registration in the signer readiness
  probe and lifecycle gate, and keep transport reachability separate through
  the signer's `runtimeExposure: reachable` service.

## F-035: Apparent cadence failure was confounded by a missing StackerDB subscription

- Classification: superseded diagnostic hypothesis; retained as an evidence
  calibration warning
- State: disproved as the cause of the current-main Kubernetes failure by F-043
- Evidence: at burn 233 miner-2 wrote proposal slot 2 version 1 at
  `06:49:36.378`. It overwrote that slot with version 2 about 39.5 seconds
  later. The first peer-side attempt associated with the newer slot appeared
  roughly another 39 seconds later, after the canonical `.miners` signer had
  changed, and was correctly rejected. The exact version-1 signature appears
  only in miner-2's local write log and no signer received a proposal. The
  20-second burn interval was shorter than observed dissemination, whereas
  Bitcoin mainnet cadence is much longer than the default inventory periods.
- Counter-evidence: after enabling the missing subscriptions, all ten
  companions exposed `.miners`; a fresh burn-230 proposal reached a signer in
  tens of milliseconds, validated in 13 ms, and was accepted. Two subsequent
  same-tenure blocks were also validated and accepted within seconds. This is
  incompatible with the claim that a 60-second interval caused the observed
  total delivery failure.
- Risk: time compression can still selectively accelerate one protocol plane,
  but using a tainted run to calibrate cadence can lead to unnecessary sleeps
  that hide the real configuration defect.
- Required action: measure proposal-to-receipt and proposal-to-threshold on a
  fresh corrected run. Keep faster cadence as a named stress dimension, but do
  not cite the pre-F-043 latency samples as a healthy StackerDB baseline.

## F-036: `burst N` continued mining after N blocks

- Classification: harness policy-control defect
- State: fixed and behaviorally verified on the retained tainted run
- Evidence: the policy helper wrote `MODE=run` with `BURST_BLOCKS=N`. Once the
  clock decremented the burst to zero, run mode allowed ordinary cadence to
  continue, so a caller could not create a stable protocol-height barrier. The
  corrected helper writes `MODE=pause`; a live `burst 1` advanced Bitcoin from
  height 362 to exactly 363 and remained paused at policy generation 5.
- Risk: configuration rolls and signer-set transitions can be crossed while
  the harness claims the burnchain is frozen, invalidating causality and replay.
- Required action: retain exact-height behavioral assertions for every phase
  transition and record each requested and observed height in the run ledger.

## F-037: Stale `.miners` chunks can masquerade as current key mismatches

- Classification: diagnostic ambiguity
- State: classified; bounded StackerDB outcome metrics pending
- Evidence: miners logged `Bad DB slot signer` for chunks fetched after a new
  sortition changed the two authorized `.miners` slot owners. Timestamp and
  signature correlation proved the warnings referred to earlier-tenure chunks,
  not the current proposal initially under investigation. Searching only by
  contract, slot, or consensus-view hash conflated several writes.
- Risk: incident responders can change correct miner keys or weaken
  authorization based on an unrelated stale-fetch warning.
- Required action: correlate contract, slot, version, signature hash, write
  time, fetch time, local sortition and disposition. Add bounded counters for
  accepted, stale-view, bad-signer and missing-slot StackerDB outcomes so the
  dashboard exposes the distribution without log archaeology.
- Measured-soak evidence: the exact burn 503 -> 803 Loki window contained 139
  `Bad DB slot signer` errors across companions, including 34 on
  `signer-node-9`. All 18 nodes nevertheless ended at the identical burn 803 /
  Stacks 597 tip and every signer runloop remained ready and registered. The
  successful outcome reinforces that the raw error is not by itself a
  current-key failure; the missing bounded disposition metric remains the
  actionable observability gap.

## F-038: Attacknet lifecycle needs protocol-height phases, not startup sleeps

- Classification: orchestration design correction
- State: implemented and proven by the clean full-topology lifecycle
- Evidence: a two-second bootstrap cadence crossed reward-cycle and Nakamoto
  boundaries while companions rolled and signers initialized. Pod readiness
  ordering could narrow the race but could not prove which protocol state each
  actor held at activation.
- Risk: startup speed, image pull variance, PVC placement and node load change
  protocol outcomes, making an identical seed non-reproducible.
- Required action: the rendered manifest now carries bootstrap, observer,
  signer-registration and Nakamoto activation heights. Lifecycle advances with
  exact paused bursts, verifies node convergence at each barrier, and permits
  steady cadence only after every signer is a current-cycle participant.
- Live proof: the replacement lifecycle reached each exact height barrier,
  admitted all 31 actors, proved all ten current-cycle signer identities and
  weights, crossed Nakamoto activation only after the signer gate, and later
  completed the measured burn 503 -> 803 soak without a startup sleep being
  used as protocol evidence.

## F-039: Raw actor logs are node-local and can disappear before forensics

- Classification: attacknet observability and evidence-retention gap
- State: corrected and proven through full-run destructive teardown
- Evidence: Prometheus centrally scrapes actor metrics and the authenticated
  event bridge persists orchestrator events, but raw stdout/stderr is read from
  containerd only when `kubectl logs` or incident capture runs. Only the current
  and immediately previous container are queried. Rotation, Pod eviction, or
  loss of a worker can therefore remove the causal log window.
- Risk: a long or destructive campaign may preserve the invariant failure but
  lose the cross-actor messages required to establish root cause. Grafana can
  show metrics without providing the corresponding log sequence.
- Required action: collect container logs centrally with bounded retention and
  collector-attached network, actor, role, Pod UID, node, container, run, and
  image identity. Treat message bodies as actor-self-reported and potentially
  malicious; Kubernetes metadata and authenticated orchestration events remain
  the authoritative correlation sources.
- Live proof: node-local Alloy collectors attached Kubernetes identity and
  streamed the complete run into Loki. The mandatory teardown artifact retained
  10,329,085 entries / 10.14 GB uncompressed as a digest-verified 368.9 MB gzip
  before any observability or actor PVC was deleted. Bounded `kubectl logs`
  snapshots remain a secondary incident source rather than the sole history.

## F-040: Confirmed stacking requires a subsequent burn event before signer participation

- Classification: protocol-fixture sequencing fact exposed by a truthful gate
- State: corrected and proven in the clean full-topology lifecycle
- Evidence: all ten `stack-stx` transactions were confirmed at burn height 220.
  At 221 every signer reported `runloop_ready=1` but
  `registered_for_current_reward_cycle=0`. An exact diagnostic block to 222
  caused all ten runloops to refresh from reward cycle 10 to 11 and report
  current-cycle registration before activation at 223.
- Risk: a harness that equates transaction confirmation or runloop readiness
  with participation crosses activation one event too early and creates a
  network with zero effective signer weight.
- Required action: use height 222 as the signer-registration barrier, retain
  the current-cycle gauge as the decisive assertion, and record requested and
  observed heights rather than inserting a timing sleep.

## F-041: A transient event-journal disconnect failed an otherwise healthy launch

- Classification: harness evidence-transport reliability defect
- State: fixed with bounded retry; clean rerun pending
- Evidence: the full network reached `Ready 31/31`, all signers registered, and
  the first post-activation snapshot later passed. While recording the baseline
  actor inventory, one loopback POST inside the event-journal Pod ended with
  `RemoteDisconnected`; `set -e` classified the entire lifecycle as failed.
- Risk: a momentary observability transport error can masquerade as protocol
  failure and prematurely seal an otherwise valid run descriptor.
- Required action: retry the identical authenticated, idempotent event up to
  three times. Persistent failure still preserves the admitted network and
  fails the evidence gate; transient failure no longer invalidates the run.

## F-042: Burn-block observer delivery can lead companion RPC visibility by one block

- Classification: transport-independent signer/node ordering finding; impact
  under investigation
- State: reproducible, with successful recovery demonstrated in the same
  occurrence; no participation loss observed
- Evidence: at burn heights 223, 224, and 225 the signer received the correct
  new-burn-block event, then its RPC check reported the companion at exactly the
  preceding height and failed local-state update with `Node has not processed
  the next burn block yet`. The companion converged shortly afterward and the
  full 18-node snapshot remained canonical.
- Risk: if the signer does not re-evaluate after companion convergence, every
  burn boundary can suppress state publication or proposal handling even
  though both components are individually healthy. The repeated StackerDB 404
  for signer-state publication may be downstream evidence, but causality is not
  yet established.
- Required action: correlate observer callback timing, companion chainstate
  commit, retry behavior, signer-state publication, and proposal/vote outcomes
  across several tenures. File a current-main issue only after distinguishing a
  harmless retried ordering window from persistent participation loss.
- Follow-up evidence: at burn 230 signer 1 logged the one-block RPC mismatch at
  `2301.131`, then evaluated the new proposal at `2303.215` with both global and
  local state at burn 230, validated it, voted Accepted, and observed 76% weight
  reach threshold. This occurrence recovered in about two seconds and did not
  suppress the vote. Retain the condition as a measurable recovery path rather
  than filing it as a liveness defect on this evidence alone.
- Long-window evidence: the exact 300-burn-block acceptance window contained
  2,300 instances of this family (222--236 per signer), so the ordering window
  is common rather than exceptional under the ten-second regtest cadence. The
  same counter window recorded 3,013 accepted companion validations and zero
  rejected companion validations across all ten signers; every actor ended on
  the same canonical tip. It also recorded 246 policy-level rejections before
  validation, which remain a separate tenure-policy signal. This demonstrates
  repeated recovery without false validation rejection, while the high error
  volume still justifies a bounded recovery counter and less alarming logging.

## F-043: A signer companion silently omits proposal transport unless configured as a `stacker`

- Classification: current-main configuration ambiguity and attacknet bootstrap
  defect; transport-independent of libp2p
- State: topology fixed and proven over the clean 300-block acceptance window
- Evidence: miners repeatedly accepted proposals into their local
  `ST000000000000000000002AMW42H.miners` slots, while every signer companion's
  metadata endpoint returned `StackerDB contract not found` and no signer log
  contained the proposal hashes. In current main, configuration finalization
  calls `add_miner_stackerdb()` and `add_signers_stackerdbs()` only when
  `[node].miner` or `[node].stacker` is true. A companion configured with both
  false can follow canonical burn and Stacks tips and appear healthy, but it
  never constructs the database that carries miner proposals.
- Risk: the overloaded `stacker` name looks like a consensus role instead of a
  transport subscription switch. A signer operator can pair a healthy signer
  with a healthy follower node and receive burn events while receiving zero
  block proposals, producing total participation loss with no direct startup
  error.
- Required action: render signer companion nodes with `miner = false` and
  `stacker = true`; retain a topology test for this exact distinction; and add
  a pre-activation behavioral assertion that the companion `.miners` metadata
  endpoint exists. Consider a clearer explicit `subscribe_signer_stackerdbs`
  configuration or startup diagnostic in the production node.
- Verification: after rolling only the corrected companion configuration with
  Bitcoin paused, all ten `.miners` metadata endpoints changed from 404 to 200.
  An exact one-block diagnostic then produced a proposal accepted by signers,
  followed by signed Nakamoto blocks at heights 19, 20, and 21. Proposal
  transport, independent companion validation, response transport, threshold
  aggregation, and Nakamoto block propagation all executed end to end.

## F-044: Docker Desktop exhausted shared node storage without Kubernetes DiskPressure

- Classification: local-cluster capacity and false-admission finding
- State: preflight fixed and live; host capacity restored
- Evidence: Loki, Alloy, and a replacement Grafana were scheduled but failed
  their first writes with `ENOSPC`. Kubelet summary reported exactly
  `availableBytes=0` and about 98.9 GB used for both node and image filesystems
  on all three nodes, while every Node condition still reported
  `DiskPressure=False`. Actor PVC data was only about 3--21 MiB per workload and
  the largest actor log was about 7 MiB, excluding the active network itself as
  the dominant consumer. Docker Desktop separately reported 8.5 GB of
  reclaimable build cache and 10.5 GB of reclaimable unused images; historical
  named volumes remain protected from cleanup.
- Risk: Kubernetes admits a complete experiment and reports healthy nodes even
  though evidence services cannot persist data. A protocol failure can then be
  accompanied by missing logs, a broken event journal, or Grafana migration
  errors, defeating root-cause analysis while the control plane still appears
  healthy.
- Remediation: lifecycle and capacity preflight now query kubelet
  `/stats/summary` before applying observability or actors, record both root and
  image filesystem availability per node, and fail below a conservative floor
  unless a negative-control scenario explicitly opts in. Docker Desktop's
  restart/upgrade restored roughly 51.3 GB available on each kind node; the
  clean stage-1 run subsequently admitted Loki, Alloy, Grafana, and every actor
  without storage errors. Historical evidence and actor volumes were not used
  as an unscoped cleanup target.

## F-045: Concurrent harness writers had no cluster-wide run ownership

- Classification: harness attribution and resource-governance defect
- State: fixed in entry points; fresh concurrent negative control pending
- Evidence: lifecycle, cadence, campaign, and ad-hoc diagnostic commands could
  mutate the same local cluster independently. Subagents were able to begin an
  observability rollout while a preserved protocol-diagnostic network was
  active, which made the resulting `ENOSPC` investigation initially ambiguous
  and allowed unrelated experiments to compete for the same finite node
  filesystem.
- Risk: an attacknet can attribute a failure to Stacks only if its own control
  actions are totally ordered. Concurrent applies, fault injection, cadence
  changes, or teardown can manufacture failures absent from the recorded
  scenario and make a reproduction seed insufficient.
- Required action: allow exactly one persistent network per cluster; serialize
  every mutating operation with a token-protected Kubernetes lease carrying
  owner, purpose, network, and acquisition time; permit concurrent read-only
  forensics; never auto-steal a stale lease; and record any explicit
  negative-control bypass. Lifecycle apply/delete, burnchain policy changes,
  and complete fault campaigns now enforce this contract.

## F-046: Teardown attempted to append to an already-finalized run ledger

- Classification: harness evidence-integrity/lifecycle defect
- State: fixed; exercised by teardown of the preserved diagnostic run pending
- Evidence: bootstrap failure correctly finalized its descriptor as `failed`,
  but later lifecycle deletion unconditionally appended a `run-final-status`
  assertion and finalized again. The run ledger intentionally rejects both
  operations after finalization, so evidence-preserving teardown would abort
  before deleting the admitted network.
- Risk: the more faithfully a failed run is sealed, the less likely its cleanup
  is to succeed, leaving resources and leases behind and encouraging unsafe
  manual deletion.
- Required action: treat finalization as immutable. Teardown may add the final
  assertion and seal a `running` descriptor; for an already-finalized run it
  must retain that status and export the existing ledger without rewriting it.

## F-047: Docker Desktop bundles a kubectl client outside supported server skew

- Classification: local attacknet tooling/version ambiguity
- State: fixed locally; preflight/version recording still to implement
- Evidence: the active Docker Desktop kind API server reports Kubernetes
  v1.36, while both `/usr/local/bin/kubectl` and Docker.app's bundled binary are
  v1.34.1. Commands warn that the two-minor difference exceeds Kubernetes'
  supported client/server skew. `helm` is not installed at all, despite the
  operator and planned Headlamp deployment being Helm-packaged.
- Risk: ordinary commands currently work, but schema, wait, and newer-resource
  behavior are not a defensible acceptance surface when the controlling client
  is outside supported skew. Hand-written install steps can also drift from the
  chart when Helm is silently absent.
- Remediation: Homebrew kubectl v1.36.3 now matches the v1.36.1 server within
  patch-level skew, and Helm v4.2.4 is installed. The older `/usr/local/bin`
  kubectl remains on disk but is later in `PATH`.
- Required action: pin a supported kubectl and Helm release for this
  cluster, record their versions in every run descriptor, and make preflight
  reject unsupported skew instead of merely retaining kubectl's warning.

## F-048: Offline CRD tests and Helm lint accepted schemas rejected by Kubernetes 1.36

- Classification: attacknet control-plane portability defect
- State: fixed and server-side dry-run verified
- Evidence: the initial `FaultCampaign`/`AttacknetRun` schemas passed their
  structural tests and `helm lint`, but the live v1.36 API rejected combinations
  of named properties with `additionalProperties: false`, quadratic
  `uniqueItems` constraints, an over-budget `oldSelf` CEL rule, and CEL access
  to the deliberately dual-shaped network/I/O `delay` field.
- Risk: a locally convincing API implementation would fail at installation on
  the exact target cluster. More subtly, relying only on client parsing and
  Helm lint would make CRD compatibility claims that were never exercised by
  an API server.
- Remediation: use Kubernetes pruning plus explicitly bounded arrays, retain
  the compiler/controller as action-dependent admission authority, remove the
  CEL rules that cannot type the dual-shaped field, and require server-side
  dry-run of every CRD and rendered chart in the release gate. Both new CRDs
  and all rendered controller/RBAC resources now pass that gate on v1.36.1.

## F-049: Same-Pod active probes are isolated but not cryptographically attributable

- Classification: forensic trust-boundary limitation
- State: bounded and documented; stronger attestation is optional future work
- Evidence: the controlled `attacknet-probe` sidecar has no service-account
  token, accepts only operator-generated enrolled peer/port requests, and owns
  the only intended listener on Pod port 18080. The run controller pins the
  exact Ready Pod UID/IP and requires the probe container to remain Ready.
  However, all containers in a Pod share one network namespace. A deliberately
  modified actor could attempt to occupy that port while the probe is absent or
  restarting, and the HTTP response is not signed by a probe-only key.
- Risk: ordinary actor logs or payloads cannot satisfy a fault assertion, and a
  persistent impersonator prevents the real probe from becoming Ready, but a
  narrow readiness-observation race is not cryptographically excluded. Calling
  these observations tamper-proof against the co-located actor would overstate
  their provenance.
- Required action: classify missing/unready/mismatched probe evidence as
  Inconclusive and retain the exact probe container state in incident evidence.
  If scenarios require protection from same-Pod response impersonation, add a
  per-Pod signing key mounted only in the probe and verify signatures in the run
  controller, or move the probe to a separate Pod while explicitly accepting
  the loss of same-network-namespace, clock, and filesystem fidelity.

## Pending additions

## F-050: Imperative image overrides can make Helm 4 upgrades and rollbacks conflict

- Classification: local attacknet control-plane ownership ambiguity
- State: recovered; runbook prevention pending
- Evidence: upgrading the existing `hacknet` release with Helm 4 server-side
  apply failed because an earlier `kubectl set image` manager owned
  `.spec.template.spec.containers[name="operator"].image`. Helm's attempted
  rollback then failed on the same field conflict. The running old operator
  remained available, but the release was left `failed` until the deliberate
  `--force-conflicts` upgrade returned ownership to Helm.
- Risk: a normal local debugging command can make both upgrade and automatic
  rollback fail, leaving the harness control plane at an ambiguous revision.
  An experiment started in that state cannot truthfully identify which
  controller implementation admitted it.
- Required action: change development images through Helm values plus a
  rollout annotation, not `kubectl set image`; make preflight reject a failed
  Helm release and record Pod image IDs. Treat `--force-conflicts` as an
  explicit ownership-recovery operation, not a routine upgrade flag.

## F-051: Helm does not add or upgrade CRDs for an existing release

- Classification: attacknet install/upgrade lifecycle gap
- State: fixed in the local installer and proven live
- Evidence: the release predated the `FaultCampaign` and `AttacknetRun` CRDs.
  Helm upgraded the Deployment resources but, by design, did not apply new
  files from the chart's `crds/` directory. The run controller started and
  repeatedly received API 404 for both resources, keeping `/readyz` at 503.
  Explicit server-side application of the two CRDs caused the already-running
  controller to recover and allowed Helm to complete without a restart.
- Risk: a chart can report a workload rollout while its API prerequisites are
  absent, and a user may misclassify the resulting 404 loop as an operator bug.
- Remediation: `install-local.sh` applies all three CRDs server-side before
  `helm upgrade`, waits for each API to become Established, and requires an
  explicit conflict-recovery flag before reclaiming schema ownership. The
  corrected installer was used for the accepted clean stage-1 run. Retain
  server-side dry-run as the compatibility gate; do not assume Helm owns CRD
  lifecycle after initial installation.

## F-052: Grafana actor discovery depended on a late synthetic metric

- Classification: human-observability truthfulness defect
- State: fixed live and regression-tested
- Evidence: Prometheus was successfully scraping the miner, signer,
  companion, and follower with collector-attached `attacknet_network`,
  `attacknet_actor`, and `attacknet_role` labels, while both Grafana dashboards
  populated their variables from `attacknet_actor_info{network,actor,role}`.
  That orchestrator metric is emitted only after an actor-state journal event;
  no such series existed during bootstrap, leaving Network empty and every
  actor query filtered to `No data`. Fault counters without actor filters still
  displayed zero, making the page look connected but the network absent.
- Risk: the primary human incident surface hid a healthy active network during
  precisely the bootstrap interval where operators need it most. A reader
  could mistake dashboard wiring failure for total actor or telemetry failure.
- Remediation: discover Network/Role/Actor directly from the live `up` target
  labels and retain `attacknet_actor_info` only for admitted image/placement
  metadata. The corrected dashboard was provisioned live and its four actor
  targets returned `up=1`.

## F-053: Fast bootstrap crossed the signer-set cutoff before stacking confirmed

- Classification: deterministic harness liveness and evidence defect
- State: fixed in phase model and proven by a fresh clean run
- Evidence: a fresh stage-1 run burst-mined from burn 202 to 220 while Stacks
  nodes were still processing the compressed epoch schedule. The stacker then
  submitted and confirmed its PoX-4 transactions at cycle 11's start, after
  the cycle's prepare/snapshot boundary. At burn 222 the signer correctly
  reported `runloop_ready=1` but both current- and next-cycle registration as
  zero. Lifecycle paused Bitcoin and waited 900 seconds for current-cycle
  registration, a condition that could only change after later burn blocks,
  producing a deterministic deadlock. The sealed bootstrap-failure bundle is
  retained under the generated stage-1 run directory.
- Risk: the harness could manufacture a signer outage while claiming to prove
  a pre-Nakamoto participation barrier. Faster machines or different API
  timing merely changed whether the race appeared, so earlier passes were not
  portable evidence.
- Remediation: expose structured stacker submission state; pause at PoX-4
  enrollment (burn 208); advance one burn block at a time; and prove every
  configured signer address has non-zero canonical `locked` state before the
  cycle-11 prepare cutoff at burn 215. Crossing the cutoff without that proof
  is now impossible. Only after this gate may the lifecycle enable observers,
  require current-cycle signer readiness at 222, and enter Nakamoto at 223.
  The clean run retained at
  `contrib/attacknet/evidence/stage1-clean-current-main-20260815/` confirmed
  canonical lock at burn 212, before the cutoff, and first-start signer
  registration without a restart.

## F-054: A compound Bash `local` assignment aborted the enrollment barrier

- Classification: attacknet harness reliability defect
- State: fixed and regression-tested
- Evidence: the first corrected enrollment run stopped at burn 208 with
  `seconds: unbound variable`. `wait_stacker_submission_window` declared
  `seconds="$1"` and computed its deadline in the same `local` command; Bash
  expands the arithmetic expression before the new local value exists, and
  `set -u` turned that ordering detail into a fatal error. The complete sealed
  incident is retained at
  `contrib/attacknet/evidence/stage1-enrollment-shell-abort-20260815/`.
- Risk: a valid paused network could be abandoned by the harness before a
  protocol assertion ran, making infrastructure failure look like a signer or
  stacker failure.
- Remediation: split declaration, assignment, and deadline computation into
  separate commands and retain behavioral registration-lifecycle tests.

## F-055: Reapplying a rendered burn policy reused an acknowledged generation

- Classification: deterministic cadence-control defect
- State: fixed and regression-tested
- Evidence: resuming lifecycle against an admitted generation-2 burn policy
  reapplied the generated generation-1 ConfigMap. The controller incremented
  it to generation 2, while the clock correctly ignored that already-applied
  command ID; lifecycle then mistook the old generation-2 acknowledgement for
  its new request. No requested block was mined.
- Risk: a resume could silently skip a cadence instruction or satisfy an
  exact-height gate with a stale acknowledgement. That breaks both protocol
  sequencing and replay truthfulness.
- Remediation: `ensure_burnchain_policy` now creates the initial policy only
  when absent and otherwise preserves the admitted monotonic generation. The
  run ledger remains the authority for whether a recovery command was already
  requested.

## F-056: A cached `NotRegistered` signer entry suppresses reward-set retries

- Classification: transport-independent signer liveness defect in current main
- State: confirmed with sealed runtime evidence; upstream fix required
- Evidence: after canonical stacking was confirmed before the configured
  cutoff, the companion's `/v3/stacker_set/11` returned the signer's exact
  public key and weight. The signer simultaneously reported reward cycle 11,
  `runloop_ready=1`, and both registration gauges as zero. In
  `stacks-signer/src/runloop.rs`, an early negative lookup installs
  `ConfiguredSigner::NotRegistered`; `is_configured_for_cycle()` then returns
  true for that placeholder, so later burn events never call
  `refresh_signer_config()` for the same cycle. Restarting only the signer,
  without mining a block or changing its companion, immediately produced
  `registered_for_current_reward_cycle=1`. The complete pre-recovery evidence
  is retained at
  `contrib/attacknet/evidence/stage1-notregistered-cache-20260815/`.
- Risk: a signer that queries just before its canonical reward-set entry is
  available can remain unable to vote for the entire reward cycle unless an
  operator restarts it. Correlated startup or node-lag timing can therefore
  remove meaningful signing weight despite healthy RPC and chainstate later.
- Required action: distinguish a definitive absence from a reward set that is
  not available yet, and retry negative/unavailable configurations on later
  burn events with bounded backoff. Add a regression that first returns no
  entry, later exposes the signer in the same cycle, and proves registration
  without process restart. The deterministic attacknet baseline starts signers
  only after the canonical reward set is frozen; a separate early-start
  negative control must retain this as failed current-main behavior.

## F-057: Burn and Stacks heights shared an unusable dashboard scale

- Classification: human-observability presentation defect
- State: fixed live and regression-tested
- Evidence: the overview overlaid burn height (222) and Stacks tip height (15)
  in one chart. In a Nakamoto network, Stacks height advances at a substantially
  different cadence from the Bitcoin burnchain; either series can become
  visually flat or dominate the Y-axis as the run grows.
- Risk: an operator can miss cohort divergence or stalled Stacks progress even
  while the underlying series are present and accurate.
- Remediation: split the panel into independently scaled `Burn-chain cohort
  progress` and `Stacks-chain cohort progress` charts, while retaining the
  top-level spread statistics. The change passed all observability tests and
  was rolled into the active Grafana deployment.

## F-058: A rollout annotation did not prevent kind from running stale `:dev` code

- Classification: local image provenance and admission defect
- State: fixed and proven live
- Evidence: the rebuilt operator image contained per-actor suspension, and the
  StacksNetwork API admitted `signer-1.suspended=true`, but the resulting
  StatefulSet still had `replicas=1`. The Deployment's build annotation had
  forced a new Pod, while `imagePullPolicy: IfNotPresent` reused the worker's
  older cached `stacks-hacknet-operator:dev`. Inspecting `/app/controller.py`
  inside that Pod showed the old replica expression. This also omitted the
  burnchain runtime-policy mount, so the clock ran its default 20-second cadence
  and could not acknowledge the lifecycle's generation-2 policy. The failed
  pre-mining run was automatically sealed and exported before teardown.
- Risk: a run could record the new source digest and a fresh Pod UID while
  executing old controller code, invalidating every admission, orchestration,
  and replay claim downstream. A rollout annotation proves restart, not image
  identity.
- Remediation: `install-local.sh` now retags each local image with a tag derived
  from its full immutable Docker image ID, passes that content-specific tag to
  Helm, and retains the full ID as a Pod annotation. The admitted operator and
  run-controller `imageID` values now exactly match the local build IDs, and
  live inspection confirms the expected controller source. The installer also
  gained a read-only `--help`; previously, asking for help executed an install.

## F-059: Bootstrap readiness assumed every declared actor had a Pod

- Classification: phase-assertion model defect
- State: fixed and regression-tested
- Evidence: after per-actor suspension worked, Kubernetes correctly admitted
  seven actor StatefulSets, kept the signer at `replicas=0`, and created six
  actor Pods. The foundation gate compared Pod count directly with the seven
  workloads in the manifest, so it could never pass even though every active
  foundation actor was Ready.
- Risk: intentional suspension, staged upgrades, and future scale-to-zero fault
  scenarios would all look like unexplained bootstrap failure. Relaxing the
  count entirely would be worse because a genuinely missing StatefulSet or Pod
  could then pass unnoticed.
- Remediation: require the complete declared StatefulSet count first, derive
  the expected active Pod count from each admitted StatefulSet's nonzero
  replica intent, and independently require the named foundation actors Ready.
  Behavioral coverage proves a seven-actor topology with one suspended signer
  accepts exactly six active Pods and still rejects missing admitted resources.

## F-060: Network-scoped readiness inventory counted observability workloads as actors

- Classification: assertion-scope and resource-label ambiguity
- State: fixed and regression-tested
- Evidence: the replica-aware gate correctly queried StatefulSets, but selected
  only `testing.stacks.org/network`. Loki deliberately shares that network label,
  producing eight StatefulSets for a seven-actor topology and another impossible
  equality. Actor Pod inventory already required the additional
  `testing.stacks.org/actor` label.
- Risk: attaching any new network-scoped StatefulSet—logs, tracing, a proxy, or
  an adversarial helper—could break protocol bootstrap despite every actor being
  healthy. Conversely, treating all network-labelled workloads as actors would
  corrupt capacity and attribution metrics.
- Remediation: actor readiness inventory now requires both the network and actor
  labels for Pods and StatefulSets. The behavioral fixture includes an eighth
  observability StatefulSet and proves it cannot affect the seven-actor gate.

## F-061: Two lifecycle branches issued duplicate steady-state cadence commands

- Classification: mutually-exclusive phase-control defect
- State: fixed and regression-tested
- Evidence: the phased bootstrap reached burn 222, proved the signer registered,
  proved the companion subscribed to `.miners`, switched the clock to the
  requested 60-second steady cadence, and reached `Ready 7/7`. Because stage 1
  had no activation-gated miner, the later generic ungated-startup branch also
  ran and issued the same policy as a new generation. The clock was correctly
  sleeping for generation 9's 60-second interval and did not acknowledge
  generation 10 inside the command deadline, so lifecycle marked an otherwise
  healthy launch failed.
- Risk: successful protocol bootstrap could be reported as infrastructure
  failure, and an unnecessary second cadence command could perturb replay
  ordering or mine a block at an unintended boundary.
- Remediation: the generic post-Ready clock start is now restricted to
  single-phase topologies with no bootstrap resource and no activation-gated
  actors. A behavioral decision-table test proves two-phase, gated, and simple
  startup paths are mutually exclusive.

## C-001: Fresh staged current-main bootstrap reached Nakamoto consensus

- Classification: clean acceptance evidence
- Observation window: empty PVCs from burn 202 through Nakamoto burn 223/224
- Evidence: `contrib/attacknet/evidence/stage1-clean-current-main-20260815/`
  captures the admitted generation-2 network at `Ready 7/7`, exact local image
  IDs, Kubernetes state, trusted timeline, and run descriptor. Canonical signer
  funds locked at burn 212 before cutoff 215; the observer-enabled final
  generation reconciled with seven active Pods before mining continued; the
  signer initialized registered for reward cycle 11 on its first process start;
  and its companion subscribed to the legacy `.miners` StackerDB.
- Protocol result: at burn 223 the miner produced Nakamoto blocks, the signer
  received/validated/accepted proposals with zero rejections, and miner,
  companion, and follower converged on the same burn height, Stacks height, and
  canonical tip. A later backend-neutral progress gate observed burn 232/Stacks
  31 advance to burn 233/Stacks 32 inside 30 seconds with zero cohort drift and
  four authenticated conversations per node; the signer had accepted 9/9
  proposals at the preceding sample. No actor container restarted during the
  accepted run, including across a Docker Desktop restart.
- Boundary: this proves the corrected one-miner/one-signer/one-follower staged
  lifecycle and human observability surface. It is not the full 28-actor
  capacity baseline, a fault campaign, or the required 300+ burn-block soak.

## C-002: Medium and full current-main capacity stages passed API-pressure and convergence gates

- Classification: clean capacity and control-plane acceptance evidence
- Evidence: `contrib/attacknet/evidence/capacity-current-main-20260815T1215Z/`
  contains requested topology, admitted resources, per-node kubelet storage,
  operator metrics before/after each stage, every convergence attempt, final
  invariant result, runtime image identity, and trusted timeline.
- Medium result: the two-miner/four-signer/two-follower topology reached Ready
  in 174 seconds and a clean stable progress window on attempt 2. The operator
  made 3,029 API requests across 28 reconciliations with zero throttles, server
  errors, or transport failures; mean reconcile duration was 0.434 seconds and
  maximum was 1.096 seconds.
- Full result: the three-miner/ten-signer/five-follower topology rendered 31
  actor workloads, reached Ready in 218 seconds, and passed a clean stable
  progress window on attempt 5. The operator made 6,826 API requests across 31
  reconciliations with zero throttles, server errors, or transport failures;
  mean reconcile duration was 1.080 seconds and maximum was 1.489 seconds.
  All 31 actors remained Ready with zero restarts and were distributed 16/15
  across the two worker nodes. The accepted window advanced burn 227 to 228
  and Stacks 23 to 24 with zero cohort drift, one canonical tip per height, and
  the required live authenticated-peer coverage.
- Transient observation: the full topology's first three post-activation
  samples had incomplete peer coverage and followers up to five Stacks blocks
  behind. Attempt 4 converged by its ending snapshot, but correctly remained a
  failed stable-window result because its starting snapshot was unhealthy.
  Attempt 5 proved both endpoints clean. This is bounded convergence behavior,
  not silently discarded warm-up evidence.
- Resource result: before each stage, all three kubelet summaries reported
  roughly 51.4 GB free on root and image filesystems. No ENOSPC, eviction,
  restart, or unexplained control-plane pressure occurred.
- Boundary: this proves a fresh corrected full-topology baseline and API
  feasibility on the local two-worker kind data plane. It does not yet prove
  fault recovery, mixed-version compatibility, deliberate worker loss/PVC
  behavior, or the required 300+ burn-block soak.

## F-062: Asking the topology renderer for help silently rendered a network

- Classification: command-line safety and operator-expectation defect
- State: fixed and regression-tested
- Evidence: `node contrib/attacknet/topology.mjs --help` ignored the unknown
  flag, selected every default, and wrote a seven-workload topology into the
  default generated directory. This happened during read-only investigation
  of the trusted-probe option; it did not mutate Kubernetes, but it could
  overwrite local generated inputs subsequently passed to lifecycle apply.
- Risk: a user intending only to inspect syntax can alter a replay input or
  accidentally prepare the wrong topology. Silently accepting arbitrary
  options also makes misspelled safety/configuration flags appear effective.
- Remediation: `--help` now exits before topology construction or filesystem
  writes and documents counts, images, per-actor overrides, probes, namespace,
  network, and output. Behavioral coverage invokes it from an empty directory
  and proves no generated directory is created. Rejecting all other unknown
  options remains a follow-up hardening item.

## F-063: First-class fault resources bypassed the shared environment mutation lease

- Classification: control-plane serialization and attribution defect
- State: fixed and regression-tested offline; live controller-owned campaign proof pending
- Evidence: the host lifecycle and shell campaign runner serialize applies,
  cadence changes, faults, and teardown through the
  `attacknet-mutation-lease` ConfigMap. The asynchronous run controller instead
  serialized only `FaultCampaign` objects against one another with an in-memory
  oldest-campaign rule. A directly submitted `FaultCampaign` or an
  `AttacknetRun` child could therefore inject Chaos while a host process was
  changing cadence, applying a network generation, capturing a supposedly
  stable assertion window, or tearing the environment down.
- Risk: two individually valid operations could overlap and produce an
  unattributable failure, a false recovery, or a replay ledger whose recorded
  order did not match the mutations actually observed by the network. This is
  especially dangerous for an agent-driven attacknet because Kubernetes CR
  submission is asynchronous and human discipline cannot serialize the later
  controller action.
- Remediation: every executable campaign now verifies the persistent
  environment lease, atomically acquires the same namespaced mutation
  ConfigMap used by the host harness, and binds ownership to the campaign's
  immutable Kubernetes UID. A foreign holder leaves a pending campaign inert;
  loss of an owned lease after injection fails closed and removes the owned
  Chaos resource without deleting the replacement holder's lease; terminal
  and finalizer cleanup release only an exact UID/token match. The run
  controller's namespaced Role gained only ConfigMap delete, not broader
  cluster authority. Regression coverage proves exclusive acquisition,
  foreign-holder waiting, post-injection lease-loss cleanup, noninterference,
  and terminal release. A live campaign must still verify the installed RBAC,
  ConfigMap lifecycle, Chaos effect, and recovery end to end.

## F-064: A fault-induced network outage regressed its campaign to Pending

- Classification: run-controller state-machine liveness defect
- State: fixed, regression-tested, and proven by corrected live rerun
- Evidence: the first controller-owned full-topology campaign injected
  `PodChaos/pod-failure` into `signer-node-1`. Chaos Mesh reported a successful
  Apply at `12:49:03Z`, the exact admitted Pod became `Ready=False`, and the
  aggregate `StacksNetwork` consequently left `Ready`. At `12:49:15Z` the
  campaign contained an admitted target and live Chaos UID but had regressed
  from `Active` to `Pending/NetworkNotReady`. After Chaos Mesh successfully
  recovered the target at `12:49:33Z`, the controller re-entered admission,
  reused the recovered Chaos object as a new injection, and finally reported
  `Failed/InjectionTimeout` at `12:51:18Z`.
- Risk: the expected effect of a valid campaign destroys the controller state
  needed to observe and clean up that campaign. A run can remain injected,
  retry a completed fault, emit a false failure, delay the next experiment,
  and make its forensic timeline disagree with Chaos Mesh's authoritative
  Apply/Recover record.
- Remediation: aggregate network readiness now gates only initial admission.
  Once admitted, a campaign continues against the sealed network UID,
  generation, compiled digest, target Pod UID, and owned Chaos object even when
  its requested effect makes actors or the whole network non-Ready. A
  regression models the network becoming Degraded during an admitted
  `pod-failure` and proves the campaign advances rather than returning to
  Pending.

## F-065: AllInjected preceded the observable Pod effect and created a false verdict

- Classification: asynchronous evidence-sampling defect
- State: fixed, regression-tested, and proven by corrected live rerun
- Evidence: the same campaign observed Chaos Mesh `AllInjected=True` and
  sampled `PodUnavailable=Failed` at `12:49:08Z`. The forensic snapshot seconds
  later showed the exact admitted Pod UID still present but `Ready=False`,
  which is precisely the requested and trusted `pod-failure` effect. The early
  result was never re-evaluated, so the controller's terminal verdict
  contradicted the later Kubernetes state and Chaos Mesh record.
- Risk: Kubernetes readiness, restart count, DNS, and network observations are
  eventually consistent with Chaos controller conditions. Treating the first
  post-`AllInjected` sample as final can turn a real effect into `Failed` or
  `Inconclusive`; an agent would then minimize or triage a harness race instead
  of the network behavior it requested.
- Remediation: Pod campaigns remain in `Injecting/WaitingForEffectEvidence`
  after `AllInjected` until the required count of immutable-UID Pod effects is
  proven or the bounded assertion window ends. The controller retains the
  first trusted observation, polls again, preserves injection evidence if
  `AllInjected` later clears, and can proceed directly to recovery when the
  fault duration ends. Coverage proves an initially Ready Pod produces no
  verdict, a later `Ready=False` sample proves the effect, and recovery reaches
  `Passed`.

## F-066: A terminal campaign could release serialization before Chaos deletion settled

- Classification: cleanup and cross-campaign isolation defect
- State: fixed, regression-tested, and proven by corrected live rerun
- Evidence: the failed live campaign recorded
  `cleanup.absent=false, allRecovered=true`, but its next terminal reconcile
  released `attacknet-mutation-lease` without rechecking the owned Chaos
  resource. Kubernetes completed the asynchronous deletion shortly afterward,
  so this run did not overlap another mutation, but the controller contract
  permitted that race.
- Risk: a subsequent campaign or lifecycle mutation could start while the
  previous Chaos finalizer was still restoring iptables, process, filesystem,
  or clock state. The next baseline would be contaminated even though the
  shared lease claimed exclusive ownership.
- Remediation: terminal reconciliation now repeatedly removes and reads the
  exact owned Chaos resource, retains the mutation lease while deletion is
  unsettled, records `cleanup.absent=true` only after a 404, and releases only
  then. A delayed-deletion test proves the lease survives the first cleanup
  pass and that neither the resource nor lease remains after confirmed
  settlement.

The failed live controller run and the network's independent recovery proof
are retained under
`contrib/attacknet/evidence/faultcampaign-pod-failure-20260815T124726Z/`.
Despite the incorrect controller verdict, the full network recovered to one
canonical cohort and advanced burn `252 -> 253` and Stacks `53 -> 54` during a
70-second stable window with zero drift and at least 29 live authenticated
connections per node. This is evidence of Stacks resilience, but it is not an
accepted `FaultCampaign` proof; C-003 records the separate corrected rerun that
does pass the controller contract.

## C-003: Controller-owned companion outage proved effect, recovery, and serialization

- Classification: clean first-class fault-campaign acceptance evidence
- Evidence:
  `contrib/attacknet/evidence/faultcampaign-pod-failure-corrected-20260815T125807Z/`
  contains the requested resource, clean pre-fault cohort, time-ordered campaign,
  lease, Chaos, Pod, and network observations, terminal custom-resource status,
  run-controller metrics/logs, and post-recovery invariant result.
- Serialization result: before the corrected run, the identical resource was
  submitted while a host mutation lease remained held for 15 seconds. The
  controller stayed `Pending/WaitingForMutationLease`, created no Chaos object,
  and acquired the lease under the immutable campaign UID only after the host
  released it. During the corrected run the lease remained owned throughout
  injection and recovery and was absent only after cleanup was confirmed.
- Effect result: the first post-`AllInjected` observation remained
  `Injecting/WaitingForEffectEvidence` rather than becoming a verdict. Five
  seconds later the same admitted Pod UID was `Ready=False`, producing trusted
  `PodUnavailable=Proven`. The aggregate network simultaneously reported
  `Progressing 30/31`, while the campaign correctly stayed Active rather than
  regressing to Pending.
- Recovery result: Chaos Mesh reported `AllRecovered=True`; the same Pod UID
  returned Ready; the controller recorded `TargetReady=Proven`,
  `cleanup.absent=true`, `cleanup.allRecovered=true`, and terminal
  `Passed/EffectAndRecoveryProven`. All 31 actors returned Ready and the owned
  Chaos resource and mutation lease were both absent. The subsequent stable
  window advanced burn `257 -> 259` and the cohort's minimum Stacks height
  `58 -> 59`; ending drift was one permitted Stacks block with no same-height
  fork and at least 26 live authenticated connections per node.
- Boundary: this proves one PodChaos `pod-failure` against a full current-main
  topology and the corrected first-class controller state machine. Network,
  DNS, I/O, time, mixed-version, worker/PVC, replay/minimization, and long-soak
  acceptance remain separate requirements.

## F-067: Non-Pod recovery evidence used a generic assertion name

- Classification: run-controller evidence-contract defect
- State: fixed and regression-tested; corrected live non-Pod campaigns pending
- Evidence: the `FaultCampaign` CRD and shipped examples expose the bounded
  recovery assertions `NetworkRecovered`, `DNSRecovered`, `IORecovered`, and
  `ClockSkewCleared`. The controller's trusted before/during/after evaluator did
  compute the corresponding recovery verdict, but labelled every result
  `TargetReady`. Consequently, a campaign using the documented type-specific
  assertion could observe a real effect and recovery yet terminate
  `Inconclusive/EffectNotProven` because its required assertion name could
  never match. This was found by tracing the complete contract immediately
  before the first live non-Pod campaign, not by weakening a failed verdict.
- Correction: recovery results now retain the fault-family-specific assertion
  name. The reconciliation test uses the documented `NetworkRecovered`
  requirement and proves both the effect and recovery labels before accepting
  `Passed/EffectAndRecoveryProven`.
- Boundary: unit evidence proves the mapping. Each of the four non-Pod fault
  families still requires live proof of effect and recovery on the probe-enabled
  network.

## F-068: Probe hardening prevented DNS fault observation

- Classification: data-plane probe/Chaos Mesh compatibility defect
- State: fixed and regression-tested; corrected live DNS canary pending
- Evidence: the first controller-owned DNS canary selected both the `actor` and
  `attacknet-probe` containers in `signer-1`. Chaos Mesh injected and later
  recovered the actor, but every probe injection attempt failed with
  `cp: can't create '/etc/resolv.conf.chaos.bak': Read-only file system`.
  DNSChaos must create this backup beside the container's resolver file. The
  probe therefore could not observe the same selected-query failure it was
  intended to prove, even though its pre-fault selected and control queries
  were both healthy.
- Correction: the opt-in, credential-free probe keeps a writable container
  overlay. It remains non-root, drops all capabilities, forbids privilege
  escalation, uses runtime-default seccomp, and receives no ServiceAccount
  token. Operator and run-controller filesystems remain read-only. This is a
  deliberate disposable data-plane exception: preventing the instrument from
  experiencing a requested fault is not useful hardening.
- Boundary: this does not yet prove that corrected DNS injection or its active
  probe succeeds live.

## F-069: Partial Chaos injection waited for a generic timeout

- Classification: run-controller attribution and liveness defect
- State: fixed and regression-tested; corrected live partial-injection negative control pending
- Evidence: the same DNS campaign had one successfully injected/recovered
  container and one repeatedly failed container. Chaos Mesh truthfully reported
  `AllInjected=False`, `AllRecovered=True`, and retained the actionable daemon
  error, but the controller remained `Injecting/ChaosResourceCreated` until the
  90-second assertion deadline and only then returned `Failed/InjectionTimeout`.
  This held the one-fault mutation lease for roughly a minute after recovery and
  collapsed a known injection failure into an ambiguous timeout.
- Correction: `AllRecovered=True` before any `AllInjected=True` observation now
  terminates immediately as `Failed/InjectionFailed`, retaining the bounded
  Chaos experiment records and daemon message. Cleanup and lease release remain
  subject to the existing confirmed-absence gate.
- Evidence completeness: lifecycle capture now includes all namespaced
  `FaultCampaign`/`AttacknetRun` resources, all five Chaos families, both shared
  leases, and separate topology/run-controller logs so this attribution is not
  lost when a fault resource is removed.

## F-070: A Bitcoin restart left confirmed miner funds hidden behind stale wallet transactions

- Classification: attacknet burnchain-policy restart and wallet-state defect
- State: root cause proven live; reconciliation and reserve fix regression-tested
  offline; corrected live restart proof pending
- Trigger: the full 31-actor topology was healthy through Nakamoto activation.
  Rolling the actor StatefulSets also restarted the persisted Bitcoin Pod. Its
  deliberate `persistmempool=0` policy correctly discarded pre-restart block
  commits, while `walletbroadcast=0` correctly prevented the watch-only miner
  wallets from republishing them. Miners 2 and 3 then restarted indefinitely
  with `UTXOs not found` even as the burnchain continued advancing.
- Evidence: Bitcoin Core's authoritative UTXO set reported miner 2's confirmed
  change output `61a3339d...17fbf:3` as unspent with 49.99194104 BTC and miner
  3's `ee2a699f...4ab8d:3` as unspent with 49.99193998 BTC. The mempool contained
  only miner 1's current commit. Nevertheless, the dedicated watch-only wallets
  retained two absent, mutually conflicting, zero-confirmation transactions per
  affected miner with `abandoned=false` and therefore suppressed those
  confirmed outputs from `listunspent`. This is a wallet/mempool split brain,
  not missing funding, key mismatch, or chainstate lag.
- Risk: a normal Bitcoin process restart can permanently remove a subset of
  otherwise funded miners from an attacknet. The network appears partially
  healthy and Bitcoin keeps progressing, but the affected Stacks nodes cannot
  even finish startup. Any restart/chaos evidence after that point is tainted.
  This particular trigger is caused by the attacknet's explicit mempool policy;
  it is not asserted as a current-main Stacks consensus defect.
- Correction: the external burnchain clock now reconciles wallet history
  against the authoritative mempool before bootstrap and before every mined
  block. It abandons only deduplicated, unconfirmed send transactions that are
  absent from the mempool; active, confirmed, received, or already-abandoned
  transactions are untouched. Reconciliation fails closed and retries instead
  of mining across ambiguous wallet state. Fresh regtest bootstraps also create
  four mature coinbase reserve outputs per configured miner rather than making
  each secondary miner depend on a single spend/change chain. A fake Bitcoin
  RPC regression proves the exact selection and deduplication contract.
- Acceptance still required: re-render the corrected clock into the live
  `StacksNetwork`, observe the stale transactions become abandoned, prove all
  31 actors return Ready without replacing actor PVCs, then restart Bitcoin
  again and prove miners remain funded and the chain continues.

## F-071: A hot actor rollout outran signer-state propagation and lost the next PoX anchor

- Classification: attacknet lifecycle defect exposing a transport-independent
  signer liveness hazard
- State: root cause bounded by complete incident evidence; topology and startup
  regression work in progress; clean rerun pending
- Trigger: all actor StatefulSets were hot-rolled while the external Bitcoin
  clock continued at the 60-second stress cadence. This bypassed the phased,
  paused bootstrap path used for a fresh `StacksNetwork` deployment.
- Evidence: the complete incident bundle is retained at
  `contrib/attacknet/evidence/reward-cycle-anchor-stall-complete-20260815T142000Z/`.
  All 18 Stacks nodes agreed on burn height 259, Stacks height 39, canonical
  tip `19f2d01...12ac5fd`, and PoX consensus `553d9e...14b92`. No Stacks block
  was produced after the tenure at burn 243. At burn 260 every coordinator
  reported `No PoX anchor block known yet for cycle 13` / `Missing canonical
  anchor block`.
- Signer-state evidence: during the burn-255 proposal window, signers
  1/2/6/7/9/10 had timely updates from exactly that six-signer cohort, whose
  authoritative reward-set weight was 14 of 25. Signers 3, 4, 5, and 8 each
  saw only their own update. Neither the correct 18-of-25 Nakamoto block
  threshold nor the current global-state evaluator's discrepant 17-of-25
  rounded-down threshold
  was reached. Every signer emitted `NoSignerConsensus` as a real rejection,
  and the miners terminated the proposal as `SignersRejected`.
- Connectivity evidence: `signer-node-3` still had zero live inbound and
  outbound conversations at capture. Most other nodes had 29--31 live
  conversations, and most signers eventually learned nine identities. This
  proves a persistent isolated companion plus propagation too slow for the
  proposal window; it does not support the stronger claim that the whole
  network remained disconnected.
- Ruled out: `handle_pending_update()` is invoked on every signer event and the
  lagging local state did eventually catch up. The one-burn companion lag was
  processing/order pressure, not the separate "never retry pending state"
  defect. The 60-second burn cadence makes this a deliberate stress case and
  must not be projected directly onto mainnet frequency.
- Failure chain: continued burn cadence during rollout left the restored P2P
  signer-state plane below agreement weight; proposals received only
  `NoSignerConsensus`; those availability failures were counted as genuine
  rejection weight (see `.docs/p2p-fixes/01-do-not-count-unavailability-as-invalidity.md`);
  the prepare phase produced no anchor; the next reward cycle could not start.
- Required corrections: hot updates must acquire the mutation lease, pause and
  later restore the external burn policy, and prove live peer connectivity plus
  signer global-state support before cadence resumes. Node configuration needs
  multiple deterministic bootstrap peers instead of a single dependency on
  `miner-1`. The dashboard and lifecycle gate need direct signer-state support
  metrics rather than inferring this condition from eventual proposal
  rejections.

## F-072: Global signer-state agreement rounds 70% down while block validation rounds up

- Classification: current-main threshold-consistency and signer-state safety
  defect; transport-independent
- State: source-proven on `upstream/main`; targeted fix and mixed-version
  analysis pending
- Evidence: `GlobalStateEvaluator::reached_agreement()` in
  `libsigner/src/v0/signer_state.rs` compares vote weight against
  `(total_weight * 7) / 10`, using integer floor. In contrast,
  `NakamotoBlockHeader::compute_voting_weight_threshold()` in
  `stackslib/src/chainstate/nakamoto/mod.rs` explicitly adds one whenever the
  division has a remainder.
- Concrete result: the attacknet's canonical reward set has total weight 25.
  The signer-state evaluator accepts weight 17 (68%), while a Nakamoto block
  requires weight 18 (72%). This was not the cause of F-071 because the timely
  cohort had only weight 14, below both thresholds. A total of 19 provides
  another useful boundary test: 13 currently passes while 14 is canonical.
- Risk: protocol-version selection, global burn view, active miner state, and
  transaction replay-set selection can be derived from less weight than could
  authorize a block. Different total weights produce different rounding gaps,
  making comments and tests that describe a 70% threshold false at discrete
  boundaries. Although chainstate still rejects a block with insufficient
  signatures, signers can act or capitulate based on a weaker global view,
  creating liveness and mixed-version divergence risk.
- Required correction: use one canonical ceiling threshold helper for both
  block signatures and signer global state, add explicit 19-slot boundary
  tests (`13` fails, `14` passes), audit the complementary disagreement
  boundary, and analyze activation/mixed-version behavior before changing the
  deployed signer state machine.

## F-073: Readiness-gated DNS deadlocked reciprocal bootstrap peers

- Classification: attacknet topology/runtime-exposure defect
- State: root cause proven live; correction regression-tested offline; clean
  rerun pending
- Trigger: the first clean full-topology run after adding three deterministic
  bootstrap identities per Stacks node configured `miner-1` to bootstrap from
  followers. Those followers retained the deliberate init dependency on the
  miner RPC endpoint. The actor Services published only Ready endpoints.
- Evidence: the failed network remained at `Progressing 2/31`. `miner-1` logged
  repeated failures resolving
  `attacknet-baseline-global-state-follower-1:20444`, while `follower-1`'s init
  container repeatedly logged `bad address` for `miner-1`. Bitcoin and the
  external burn clock were the only Ready actors. The sealed incident bundle
  is `contrib/attacknet/evidence/bootstrap-readiness-cycle-20260815T1438Z/`.
- Root cause: Stacks resolves all configured bootstrap hostnames while parsing
  node configuration, before `/v2/info` can become Ready. Kubernetes withheld
  each reciprocal peer's DNS endpoint until readiness, so neither application
  process could cross the condition required to publish the other endpoint.
  This is a harness-induced deadlock, not a Stacks P2P failure.
- Correction: every Stacks node Service now uses the existing
  `runtimeExposure: reachable` contract. DNS publishes the scheduled Pod before
  readiness, allowing config parsing and connection attempts, while init
  dependency gates still require the requested TCP port to accept and Pod
  readiness still requires the real node RPC endpoint. A topology regression
  asserts this exposure contract for every node alongside bootstrap diversity.
- Design lesson: startup dependency checks and runtime endpoint publication are
  different controls. A bootstrap graph may be cyclic by design; readiness
  must remain observable without making DNS resolution contingent on the same
  graph reaching Ready.

## F-074: An expected retry sample falsely finalized the run as failed

- Classification: lifecycle evidence-integrity defect
- State: fixed and regression-tested; clean rerun pending
- Trigger: after F-073 was corrected, all 31 actors became Ready at burn 223.
  The new live-peer barrier sampled the network once before every node had an
  authenticated inbound or outbound conversation. The invariant command
  correctly returned nonzero to request another bounded sample.
- Evidence: lifecycle immediately printed `attacknet apply failed at
  lifecycle.sh:282` and sealed a bootstrap-failure bundle, then continued and
  proved live connectivity for all 18 nodes on a later sample. It subsequently
  proved canonical-threshold global signer state for all ten signers and found
  the first Nakamoto block, but the already-finalized run descriptor rejected
  runtime resolution with `cannot resolve inputs for a failed run`.
- Root cause: lifecycle runs with `set -E`, so its ERR trap is inherited by
  command substitutions. The intentionally nonzero peer-invariant subprocess
  invoked the top-level failure trap inside the substitution even though the
  surrounding wait loop treated that status as a normal retry signal. The
  apparent failure and later success therefore coexisted in one run.
- Correction: the expected invariant probe now removes the inherited ERR trap
  inside its command-substitution boundary and records the exit status
  explicitly. A regression injects one failed peer sample under the real ERR
  trap, then proves a later sample succeeds without invoking `apply_error`.
- Risk: without this distinction, any transient condition at a bounded startup
  gate can produce a cryptographically sealed false-negative evidence bundle.
  Continuing after finalization then makes later evidence internally
  inconsistent even when the system under test is healthy.

## F-075: Declared signer weights understated the canonical reward set

- Classification: attacknet fault-admission safety and evidence-integrity
  defect
- State: root cause proven live; static correction and fail-closed runtime
  parity gate regression-tested and proven on a fresh clean full-topology run;
  deliberate live mismatch control still pending
- Trigger: the topology assigned repeating signer weights `1,2,3`, copied from
  the stacker's `targetSlots` input. `FaultCampaign` and `AttacknetRun` used
  those values to calculate unavailable signer weight and enforce the 30%
  quorum-loss boundary.
- Evidence: the admitted manifest summed the ten signers to 19. On the healthy
  clean network at burn height 230, `/v3/stacker_set/11` returned the exact ten
  signing keys with weights `1,3,4,1,3,4,1,3,4,1`, totaling 25; all ten signer
  metrics independently reported total/known/maximum-view weight 25 and a
  canonical threshold of 18.
- Root cause: the stacker locks `1.5 * minimum_threshold * targetSlots` and
  consensus assigns `floor(stacked_amount / minimum_threshold)` slots. The
  admitted weights are therefore `floor(1.5 * targetSlots)`, not
  `targetSlots` itself.
- Safety impact: a campaign selector could be admitted using understated
  signer impact. The discrepancy also corrupted the numeric reconstruction of
  F-071 even though its below-quorum conclusion remained correct. No fault was
  injected after discovery.
- Initial correction: topology now derives `1,3,4` in one helper, records each
  signer's compressed signing public key, and carries the same identity and
  weight on its signer and companion records. Before steady cadence, lifecycle
  fetches the current `/v2/pox` cycle and canonical `/v3/stacker_set` and
  requires an exact key/weight join. Runtime fault admission separately requires
  exact signer-key identity, overlays the current canonical reward-cycle
  weights for safety accounting, and pins the resulting canonical manifest.
  A changed identity or a signer-set change between schedule sealing and child
  creation fails closed.
- Fresh acceptance evidence: the misdeclared run was captured and retired,
  including its actor PVCs. A clean 31-actor recreation named
  `attacknet-baseline-signer-parity` reached lifecycle readiness at burn 224.
  Its sealed run timeline records `signer-set-parity=pass` at reward cycle 11:
  declared count 10, observed count 10, declared weight 25, observed weight
  25, rounded-up threshold 18, no missing/unexpected/mismatched entries, and
  signer-set digest
  `sha256:f1ad977af5e2344a42f6a37362aef065932896844e0e4b16fd7ba4fa2a91b78c`.
  Signer 1 also recovered from its deliberately early initialization attempt
  without a container restart once its companion RPC became available.
- Acceptance evidence still required: show a deliberately modified weight is
  rejected before any Chaos resource is created. This must not be implemented
  by mutating the live baseline CR if that mutation would roll actor Pods.

## F-076: Explicit run-operator image packaging omitted a new transitive dependency

- Classification: attacknet controller packaging and deployment-reliability
  defect
- State: fixed, regression-tested, rebuilt, and deployment-smoked live
- Trigger: the run controller began importing the shared signer-set parity
  verifier. Its Dockerfile copies an explicit allowlist of source modules and
  did not include the new dependency.
- Evidence: the first rebuilt image log copied eight existing modules but no
  `signer-set-parity.mjs`. Starting that image would make Node's module loader
  fail before the controller could reconcile any resource, despite all host
  source tests passing.
- Correction: the verifier is now copied into the image. A packaging test
  recursively follows every relative `import`/`export` from the controller
  entry point and requires the complete transitive graph to appear in
  Dockerfile `COPY` sources. This protects future shared-module additions
  instead of matching only today's filename.
- Acceptance evidence: immutable image
  `stacks-hacknet-run-operator:local-70d9649f5f7a0427` was deployed in Helm
  revision 14; both the network and run-controller Deployments became
  Available, and API discovery retained all three attacknet CRDs without a
  module-loader failure. Runtime schedule admission was subsequently exercised
  by `baseline-parity-pod-canary-r2`, which sealed a schedule and completed an
  owned child using the packaged verifier.

## F-077: An active AttacknetRun regressed to Pending when its own fault made the network unready

- Classification: attacknet orchestration truthfulness and lifecycle defect
- State: reproduced live; fixed, regression-tested, and proven by a corrected
  live canary
- Trigger: the first run-controller-driven PodChaos killed
  `signer-node-1`. The owned child correctly reached `Active` with
  `PodRestarted=Proven`, while aggregate `StacksNetwork` readiness became
  temporarily non-Ready as intended.
- Evidence: during the active fault, parent run
  `baseline-parity-pod-canary` repeatedly reported
  `Pending/NetworkNotReady` even though its persisted schedule was sealed and
  its owned child remained active. The child and Chaos resource did continue
  reconciling, so this was not a data-plane outage.
- Root cause: `AttacknetRunReconciler` applied its pre-admission network-ready
  gate before checking for an already-admitted active child. A fault capable
  of changing actor readiness therefore made its own parent appear not to
  have started.
- Impact: dashboards, budgets, and an external agent could misclassify a
  running mutation as a preflight wait. A later refactor could also return
  before cleanup-sensitive logic and turn this status defect into a safety
  defect.
- Correction: an owned active child now takes precedence over aggregate
  readiness and forces `Running/CampaignActive`. A sealed run with no active
  child waits as `Running/WaitingForNetworkRecovery`; only an unsealed run may
  report `Pending/NetworkNotReady`. Regression coverage degrades the network
  while an owned child is active and requires the parent to remain Running.
- Acceptance evidence: corrected run `baseline-parity-pod-canary-r2` remained
  `Running/CampaignActive` through injection and effect observation. During
  the short interval after the child passed but before aggregate readiness
  recovered, it truthfully reported `Running/WaitingForNetworkRecovery`, then
  terminated `Passed/StoppedAfterSuccessfulCampaign` with one completed
  campaign.

## F-078: One-shot PodChaos waited for an impossible AllRecovered transition

- Classification: attacknet cleanup, serialization, and bounded-experiment
  defect
- State: reproduced live; restart-safe fix regression-tested and proven by a
  corrected live canary
- Trigger: a `PodChaos` `pod-kill` action was declared for 15 seconds. The
  original Pod UID disappeared and the replacement StatefulSet Pod became
  Ready, proving both requested effect and system recovery.
- Evidence: Chaos Mesh retained `AllInjected=True`, `AllRecovered=False`, and
  `desiredPhase=Run`; the run controller kept the campaign Active for more
  than five minutes and held the global mutation lease. The first preserved
  attempt eventually recorded `RecoveryTimeout`, despite
  `PodRestarted=Proven`, after the corrected controller rollout arrived just
  beyond its 15-second fault plus 300-second recovery deadline.
- Root cause: PodKill and ContainerKill are one-shot actions. Chaos Mesh can
  prove their application but cannot restore the deleted Pod or killed
  process in the same sense as a reversible network, DNS, I/O, time, or
  pod-failure mutation. The controller incorrectly treated `AllRecovered` as
  mandatory for every Chaos family.
- Impact: a successful one-shot experiment could occupy the sole mutation
  slot until timeout, falsely fail, and prevent every later campaign from
  running. Duration did not provide the expected bound.
- Correction: once Kubernetes-observed immutable Pod UID disappearance or
  container restart meets the admitted mode's minimum affected count, the
  controller deletes the one-shot Chaos bookkeeping resource and separately
  requires the resolved replacement target to become Ready. The same
  transition is supported from both `Injecting` and `Active`, so a controller
  restart or rollout cannot strand durable effect evidence.
- Acceptance evidence: corrected run `baseline-parity-pod-canary-r2` admitted
  exactly signer weight 1 of canonical total 25 (4%), observed the original
  Pod UID `e8235295-4891-43fa-b866-f38cc67e7066` disappear, recorded
  `PodRestarted=Proven`, removed the Chaos resource even though its historical
  record correctly retained `allRecovered=false`, and proved replacement Pod
  UID `06a7341c-fb2e-4e9e-ae87-2b06cc83b1f7` Ready. The run completed in 35.7
  seconds; every one of the 18 Stacks nodes then converged at burn 238, Stacks
  height 35, tip `9c203b82b430dc8348fb3b7498ebe1c41f81ac4268a71a60c6bf1c351ba56173`,
  with zero burn/Stacks drift and no unauthenticated live peer conversations.

## F-079: Legitimate reward-cycle weight changes made every later fault schedule inadmissible

- Classification: attacknet fault-admission availability and evidence-integrity
  defect
- State: reproduced live; canonical runtime overlay and pre-injection pinning
  regression-tested and proven by a corrected live NetworkChaos canary
- Trigger: the first NetworkChaos canary was submitted after the healthy full
  topology crossed from reward cycle 11 into cycle 12. No signer identity or
  configured stacked amount changed.
- Evidence: cycle 11 contained the ten declared signing keys at weights
  `4,1,4,1,3,3,3,4,1,1`, total 25. Cycle 12 contained the exact same keys at
  `4,1,4,1,2,2,2,4,1,1`, total 22. The controller rejected the run as
  `ScheduleAdmissionFailed`; no Chaos resource was created.
- Root cause: the first runtime parity gate treated topology weights as
  permanently authoritative. In PoX, signer weight is derived from locked
  amount relative to the cycle's minimum stacking threshold, so fixed amounts
  can legitimately map to different integer weights in a later reward cycle.
  Exact weight parity is appropriate for the lifecycle's known initial
  enrollment gate, but it is not a valid invariant for a long-running
  attacknet.
- Risk: every run submitted after a legitimate weight transition would fail,
  preventing long soaks and reward-cycle-boundary experiments. Relaxing the
  entire check would be worse: stale weights could undercharge quorum impact,
  or a changed signer identity could be mistaken for harmless drift.
- Correction: runtime resolution now separates identity from weight authority.
  It requires an exact join of topology signing keys to the current canonical
  reward set, overlays those observed weights onto both signer and companion
  actors, and compiles all per-campaign and aggregate safety budgets from that
  resolved manifest. The immutable schedule pins its digest. Immediately
  before a child is created, and again before a standalone FaultCampaign is
  injected, the controller re-resolves the set and refuses any digest change.
  Admission status records reward cycle, total weight, signer-set digest, and
  the Stacks RPC actor that supplied the canonical observation.
- Regression evidence: unit coverage proves weight-only drift is accepted and
  charged from the observed total, missing/unexpected keys are rejected, the
  original manifest is not mutated, and a second canonical observation with a
  changed digest creates neither a child campaign nor a Chaos resource.
- Live acceptance evidence: `baseline-parity-network-canary-r2` admitted reward
  cycle 12 at canonical total weight 22 and signer-set digest
  `sha256:04fee1495a69bbe2dd1a6ce4e2f6e6f012e1ad6f1205891ca75c27a8264d9e98`.
  It correctly charged zero signer weight and one of three miners for a
  miner-2-to-signer-node-1 delay. The trusted probe measured p95 latency of
  7.582 ms before, 1,613.232 ms during the 750 ms bidirectional delay, and
  2.598 ms after. Both effect and recovery were Proven, the NetworkChaos
  resource was absent after cleanup, and the parent run passed. The shared
  verifier then found every one of 18 Stacks nodes at burn 259 / Stacks 61 on
  tip `49d5da56950693bfbaf67d24f266ba23762355754f2c75799a23a7040d8ac85d`,
  with zero burn/Stacks drift, 28--34 authenticated live conversations per
  node, and zero unauthenticated conversations.

## F-080: Recovery status reused the fault-effect explanation

- Classification: attacknet human-observability and evidence-presentation
  defect
- State: reproduced live; fixed, regression-tested, and proven by the next
  live non-Pod canary
- Trigger: the successful NetworkChaos canary classified both
  `NetworkDegraded` and `NetworkRecovered` from distinct during/after probe
  phases, then copied the evaluator's effect reason into both status rows.
- Evidence: recovery was correctly Proven from the restored 2.598 ms p95, but
  its message read `named reachability/latency probe observed delay=true`.
- Impact: the structured outcome and raw phase artifacts were correct, but a
  dashboard or human reading only the recovery row could reasonably conclude
  that latency remained injected. This is exactly the kind of ambiguous
  presentation that slows incident attribution even when underlying evidence
  is sound.
- Correction: effect results retain the effect-specific reason. Recovery
  results now use a recovery-specific evaluator reason when available, or a
  bounded explicit `trusted after-fault probe classified recovery=<outcome>`
  message. Regression coverage requires a Proven network recovery message not
  to contain the earlier `delay=true` effect claim.
- Live acceptance evidence: `baseline-parity-dns-canary` independently proved
  the selected companion FQDN resolvable before, failing during DNSChaos, and
  resolving to the original address afterward, while
  `kubernetes.default.svc.cluster.local` stayed healthy in all three phases.
  Its `DNSRecovered=Proven` row now reads
  `trusted after-fault probe classified recovery=proven`. The canary also
  crossed into reward cycle 13 and correctly admitted the same signer
  identities at their new total weight 30, providing a second live proof of
  F-079's dynamic overlay. Cleanup removed the DNSChaos resource, and all 18
  nodes subsequently converged at burn 264 / Stacks 65 with zero drift and one
  common tip.

## F-081: Chaos Mesh's IOChaos helper is x86-only in the arm64 daemon image

- Classification: local-platform capability and fault-cleanup reliability gap
- State: reproduced and attributed; evidence preserved; zero injection proven;
  safe manual apparatus abort completed; architecture admission and an exact
  zero-injection cleanup escape are implemented and regression-tested offline;
  corrected live admission proof and a distinctly-labelled arm64 I/O-pressure
  experiment remain pending
- Trigger: `baseline-parity-io-canary` requested a 500 ms FSYNC delay for 20
  seconds on `follower-1`, scoped to the probe-only path
  `/data/.attacknet-probe-follower-1/*`. Safety admission correctly charged
  zero signer and miner impact at reward cycle 13, canonical signer weight 30.
- Evidence: the trusted before probe completed five FSYNC operations with p95
  13.483 ms. Chaos Mesh selected both the actor and probe containers, but every
  application failed with `toda update RPC failed`; neither container ever
  exceeded `injectedCount: 0`, and `AllInjected` remained false. All three kind
  nodes and the target userspace are arm64. The `toda` binary embedded in the
  Chaos Mesh 2.8.3 arm64 daemon image has ELF machine `0x003e` (x86-64), while
  the target provides only the arm64 loader. Daemon logs state
  `rosetta error: failed to open elf at /lib64/ld-linux-x86-64.so.2`.
- Native-helper audit: rebuilding the tagged `toda` v0.2.4 source as arm64 is
  not a packaging fix. Its ptrace implementation explicitly hard-codes x86-64
  registers and syscall conventions (`rax`, `rdi`, and related registers),
  and its replacement code emits `.arch x64` machine code through dynasm.
  The upstream Dockerfile's x86-only download therefore reflects a real
  implementation limitation, not merely a missing multi-architecture build.
  A trial native build was stopped once this was established from source.
- Cleanup finding: after the run controller's bounded injection timeout,
  Chaos Mesh left the deleting IOChaos object behind its
  `chaos-mesh/records` finalizer in `Not Injected/Wait`. The attacknet
  controller correctly retained the global mutation lease while that object
  remained, preventing overlapping faults, but this would serialize the
  campaign queue indefinitely. After the complete live evidence bundle proved
  zero injection, the exact already-deleting object's finalizer was removed as
  an apparatus abort. The IOChaos object disappeared and the run controller
  released the lease. No recovery was claimed.
- Evidence bundle:
  `contrib/attacknet/evidence/iochaos-arm64-toda-20260815T1617Z/` contains the
  admitted orchestration, Chaos resources, before probe, cluster runtime, run
  ledger, and trusted timeline captured before cleanup.
- Correction: the trusted co-located probe now exposes a bounded system
  capability observation. Before taking an I/O baseline or creating IOChaos,
  the run controller compares each exact admitted target Pod's platform and
  architecture to the chart's explicit helper-support profile (x64-only for
  the installed Chaos Mesh 2.8.3) and terminates
  `Failed/FaultCapabilityUnavailable` otherwise. The unsupported evidence is
  retained in status and no Chaos resource is created. Injection failures now
  retain the exact Chaos Mesh records and diagnostic message. If an already
  deleting IOChaos remains behind `chaos-mesh/records` for at least 30 seconds,
  the controller may remove that one finalizer only when the records exactly
  cover every admitted Pod/container, all show zero injected and recovered
  operations, every Apply event failed, and no Apply event succeeded. Cleanup
  records `method=ZeroInjectionFinalizerAbort` and
  `zeroInjectionProven=true`; any observed or ambiguous injection preserves the
  object and the global mutation lease. Regression tests cover the positive
  and negative boundaries. The namespaced run-controller Role now grants only
  the additional Chaos-resource `patch` verb needed for this bounded cleanup.
- Remaining platform boundary: true per-syscall IOChaos on this Apple Silicon
  cluster requires an x86-64 target actor or a genuinely ported arm64 `toda`;
  simply recompiling the existing source is invalid. An I/O-pressure fallback
  may be added as a different fault semantic, but must not be presented as
  latency/fault injection. The corrected controller must still be rolled out
  and a live arm64 campaign must prove fail-closed admission before the
  original run is considered resolved end to end.
- Corrected live admission evidence: run
  `baseline-parity-io-capability-r2` resolved exact follower Pod UID
  `c0410acc-0418-4248-ad91-cbad7bdd9fc5`. Its Ready probe reported
  `linux/arm64`; the child terminated
  `Failed/FaultCapabilityUnavailable` with that bounded evidence. It never
  acquired `status.chaos` or `status.actualInjection`, no IOChaos object
  existed, terminal cleanup confirmed absence, and the mutation lease was
  released. The post-canary verifier found all 18 Stacks nodes on one Stacks
  height/tip (height 105, zero Stacks drift), burn drift one, at least 21
  authenticated live conversations per node, and zero unauthenticated
  conversations. The sealed evidence slice is
  `contrib/attacknet/evidence/iochaos-arm64-capability-20260815T1652Z/`.

## F-082: Selecting two containers in one Pod made TimeChaos partially inject

- Classification: attacknet fault-shape and evidence-integrity defect
- State: reproduced, attributed, and preserved; compiler/API guard proven;
  corrected single-container injection/recovery proven live; truthful
  application-clock observation implemented and proven to reject an
  ineffective injection; the remaining arm64 platform defect is F-083
- Trigger: `baseline-parity-time-canary` requested a 30-second negative
  `CLOCK_REALTIME` offset for 20 seconds in both `follower-1` containers so the
  Stacks actor would experience the fault and the co-located trusted probe
  could measure it.
- Evidence: Chaos Mesh applied and recovered the actor record exactly once.
  Every probe Apply failed with `duplicate entity`; its injected and recovered
  counts stayed zero, and `AllInjected` never became true. The controller
  terminated `Failed/InjectionFailed`, preserved both records and the daemon
  message, emitted no effect/recovery verdict, removed the recovered TimeChaos
  resource, and released the mutation lease.
- Corrected root cause: the shared time-namespace inode was real but was not
  the injection mechanism. Chaos Mesh 2.8.3 obtains the selected container's
  PID and ptrace-patches `clock_gettime` and `gettimeofday` in PID 1 and its
  process group. Its task UID is the TimeChaos UID plus Pod UID, so selecting
  two containers in one Pod attempts to create the same task entity twice and
  the second record fails as a duplicate. The official documentation also
  states that only container PID 1 and its children are affected; a sidecar
  and even a later `kubectl exec` process are not valid clock witnesses.
- Admission correction: a TimeChaos campaign may select at most one container
  per target Pod. Both the local compiler and the FaultCampaign CRD enforce
  this. A fresh invalid object with actor plus probe was rejected by the API
  server; the pre-existing invalid template was retained under Kubernetes CRD
  validation ratcheting and emits an explicit warning rather than being
  silently rewritten.
- Second live result: `baseline-parity-time-canary-r2` selected only the actor.
  Chaos Mesh recorded exactly one successful actor injection, observed
  `AllInjected`, then exactly one successful recovery and `AllRecovered`.
  Cleanup was normal and the mutation lease was released. The sidecar clock
  correctly remained aligned with the control, so the evaluator refused to
  claim the requested -30-second effect and the run paused
  `Inconclusive/EffectNotProven`.
- Evidence correction: every node metrics scrape now samples
  `stacks_node_process_wall_clock_seconds` inside the Stacks process. The
  bounded collector will compare that application-process clock with its own
  monotonic clock and an independent control actor. Evidence explicitly marks
  the metric content `actor-self-reported` and remains bound to the admitted
  actor image digest; it is not described as a kernel probe and cannot serve
  as authoritative evidence for an arbitrary malicious image.
- Third live result: `baseline-parity-time-canary-r3` used the corrected actor
  image and process-clock evidence path. Chaos Mesh again recorded one
  successful actor injection and recovery, but the target's differential
  `CLOCK_REALTIME` shift was only +0.0303 seconds rather than the requested
  -30 seconds. The control stayed within 0.001 seconds. The evaluator therefore
  returned `ClockSkewObserved=Failed`, `ClockSkewCleared=Proven`, and the child
  and parent remained Inconclusive/Paused. This is positive evidence that the
  attacknet no longer treats `AllInjected` as proof that TimeChaos had an
  effect.
- Post-recovery evidence: all 18 Stacks nodes remained within one burn and one
  Stacks block, with one tip per observed height, at least 22 authenticated
  live conversations each, and no unauthenticated connections. The preserved
  slice is
  `contrib/attacknet/evidence/timechaos-shared-time-namespace-20260815T1656Z/`.

## F-083: Chaos Mesh 2.8.3 TimeChaos is not effective or fail-safe on this arm64 kind platform

- Classification: local-platform capability, proof-of-effect, and fault-cleanup
  reliability gap
- State: reproduced in a Stacks actor and an independent disposable process;
  network remained healthy; fail-closed architecture admission implemented,
  regression-tested, deployed, and proven live; a portable automated
  effect-and-recovery capability canary remains future hardening
- Stacks-process reproduction: `baseline-parity-time-canary-r3` targeted only
  the `actor` container in follower-1. The daemon reported `sec:-30`, mask 1,
  attached to all 14 threads of the correct process PID, and Chaos Mesh set
  `AllInjected`. The application sampled Rust `SystemTime::now()` from inside
  that same process on every `/metrics` request. During the fault its
  target-minus-monotonic, control-normalized shift was +0.030325 seconds, not
  -30 seconds. Recovery was clean, but there was no effect to recover from.
- Independent platform reproduction: a disposable Node process on the same
  worker emitted `Date.now()` and `process.hrtime()` once per second. A
  12-second single-container TimeChaos selected the exact Pod and invoked the
  worker2 daemon. The daemon attached to the process and its threads but never
  reached `finding injected image`, never returned the gRPC call, and never
  detached. `Selected`, `AllInjected`, and `AllRecovered` all remained false.
  Deleting the TimeChaos then blocked indefinitely behind
  `chaos-mesh/records`; the disposable process was ptrace-stopped.
- Recovery: the disposable Pod was force-deleted after the bounded timeout.
  Restarting only the worker2 `chaos-daemon` Pod caused the in-flight RPC to
  fail closed with EOF, allowed the controller to remove the TimeChaos
  finalizer, and released the attacknet mutation lease. The DaemonSet returned
  Ready and no Stacks actor or PVC was touched.
- Root-cause boundary: Stacks uses Rust `SystemTime::now()`, which maps to the
  requested realtime clock. Chaos Mesh's arm64 fake-clock implementation
  ptrace-rewrites the target vDSO and carries arm64-specific relocation and
  syscall code, so this is not the same explicit x86-only helper limitation as
  F-081. The two live results nevertheless show that successful attachment or
  `AllInjected` is insufficient on this platform, and one ordinary arm64
  process shape can wedge the daemon during injection.
- Required correction: add a cluster capability canary that proves a known
  process observes the requested realtime offset and subsequent recovery
  before admitting any TimeChaos campaign. Timeout, no measured effect,
  incomplete detach, or stuck cleanup must mark TimeChaos unsupported for the
  cluster and prevent actor-targeted TimeChaos. Preserve daemon/controller
  logs and exact image/kernel/architecture evidence. Do not replace the proof
  with `AllInjected`, and do not describe an application-level clock shim as
  Chaos Mesh TimeChaos.
- Immediate correction and live acceptance: the run controller now admits
  TimeChaos only for an explicit platform architecture profile, separate from
  the IOChaos helper profile. It defaults to x64; extending it is documented as
  a claim that an effect-and-recovery canary passed. Run
  `baseline-parity-time-capability-r4` resolved follower-1 Pod UID
  `09871823-0c51-4ca0-b857-3b6cda1a9142` and image ID
  `sha256:1b43c28de833f8e8929a0839d2b67dccb1872aa148955ddd76927d9a9151bce5`,
  then obtained `linux/arm64` from the exact Ready probe. The child terminated
  `Failed/FaultCapabilityUnavailable` before baseline collection or Chaos
  creation. No TimeChaos object existed, normal terminal cleanup confirmed
  absence, and the mutation lease was released. The shared verifier then found
  all 18 Stacks nodes exactly converged at burn 357 / Stacks 157 on one tip,
  at least 22 authenticated live connections per node, and zero unauthenticated
  conversations. This closes the unsafe local path without claiming that x64
  is proven by this arm64 environment.

## F-084: Local dashboard supervisors ignored termination and accumulated duplicate forwards

- Classification: local operator-experience and harness-reliability defect
- State: reproduced after Docker Desktop restart; corrected, regression-tested,
  and repaired live
- Trigger: Docker Desktop and Kubernetes restarted while localhost access was
  enabled. Grafana remained reachable, while the newer Grafana supervisor
  logged a port-3000 bind failure every two seconds. Chaos Dashboard was
  temporarily unreachable while its Kubernetes stream recovered.
- Root cause: both shell supervisors installed one trap for `EXIT`, `INT`, and
  `TERM` whose only action removed the PID file. Receiving `TERM` therefore did
  not exit the shell or terminate its foreground `kubectl port-forward` child.
  A subsequent start saw no trustworthy PID record and created another
  supervisor. At reproduction there were two Grafana supervisors: the older
  one owned the healthy port while the newer one retried indefinitely. The
  apparent UI health concealed broken lifecycle ownership.
- Correction: both supervisors now run `kubectl` as an explicitly tracked
  child, translate `INT`/`TERM` into process exit, and kill/wait for the child
  during the `EXIT` cleanup. Grafana now uses the same singleton launchd
  supervision as Chaos Dashboard on macOS, with absolute script paths and a
  detached fallback elsewhere. Tests cover loopback forwarding, ambiguity,
  launchd identity, and signal/child cleanup structure.
- Live repair evidence: both old launchd jobs and only the exact stale access
  processes were removed. One new launchd job and one `kubectl` child now exist
  per dashboard. A subsequent stop/start cycle for each supervisor completed
  normally and again left exactly one shell/child pair. Both
  `http://127.0.0.1:3000/` and `http://127.0.0.1:2333/` returned HTTP 200.

## F-085: Storage preflight treated option-shaped arguments as filesystem paths

- Classification: harness usability and diagnostic-quality defect
- State: reproduced, corrected, and regression-tested offline
- Trigger: invoking `observability/storage-preflight.sh --help` while checking
  the live capacity gate. The script treated `--help` as its optional output
  filename, passed it to `dirname` and `mkdir`, and emitted unrelated filesystem
  errors before reaching its real check.
- Impact: this did not mutate Kubernetes or weaken the storage gate, but it made
  an ordinary operator discovery action look like a storage/filesystem fault.
  That is especially misleading in a harness whose earlier ENOSPC diagnosis was
  load-bearing evidence.
- Correction: the script now has an explicit `[OUTPUT.json]` command contract,
  returns usage for `-h`/`--help`, rejects unknown options and multiple
  positional arguments before calling Kubernetes, and has a regression test
  proving no `dirname`/`mkdir` noise is emitted.

## F-086: Chaos Mesh 2.8.3 StressChaos panics and drops custom stress-ng arguments

- Classification: upstream fault-injector correctness and local-platform
  capability gap
- State: reproduced live; attacknet failed closed and recovered without actor
  mutation; arm64 disk-pressure support remains unproven and must not be
  advertised through StressChaos
- Trigger: `baseline-parity-io-pressure-r1` compiled a bounded one-container
  disk workload for follower-1 as `StressChaos` with
  `--hdd 2 --hdd-bytes 256M --hdd-write-size 1024K --temp-path /data
  --metrics-brief`. The exact target record was created, but `Selected` and
  `AllInjected` remained false.
- Root cause: Chaos Mesh 2.8.3's official `stresschaos.Impl.Apply` reads
  `Spec.StressngStressors` only to decide not to normalize the typed CPU/memory
  stressors, never copies the custom string into `ExecStressRequest`, and then
  dereferences `Spec.Stressors.MemoryStressor` unconditionally. With the
  documented custom-stressor-only shape, `Spec.Stressors` is nil and the
  controller panics at `controllers/chaosimpl/stresschaos/impl.go:84` on every
  reconciliation. The current upstream source adds a nil check at that line,
  but still does not pass the custom argument string to the daemon request, so
  merely adding an empty `stressors` object would avoid the panic while
  silently injecting no disk workload.
- Truthful failure evidence: the attacknet child terminated
  `Failed/InjectionFailed`; the retained record says `Not Injected`,
  `injectedCount=0`, `recoveredCount=0`, and `AllInjected=false`. No effect or
  recovery assertion was emitted. Owned-resource cleanup observed the
  StressChaos absent with `method=Normal`; the mutation lease was released.
- Network evidence: follower-1 retained the same Pod UID, both containers
  remained Ready with zero restarts, and the Chaos daemons remained Ready. The
  shared verifier then found all 18 Stacks nodes exactly converged at burn 385
  / Stacks 185 on one tip. Minimum authenticated connectivity was 21; one
  transient unauthenticated conversation on follower-1 remained within the
  explicitly permitted ceiling.
- Required correction: keep native IOChaos available only behind its proven
  architecture capability. Do not use StressChaos custom stressors as an I/O
  fallback on this release. A local arm64 fallback must be a separately named,
  bounded, controller-owned disk-pressure mechanism with its own admitted
  workload identity, resource caps, active proof of effect, strict cleanup,
  and explicit evidence that it is not Chaos Mesh IOChaos/StressChaos.

## F-087: A stale Ready condition can falsely complete an actor-image rollout

- Classification: harness lifecycle and evidence-integrity defect
- State: reproduced during the first live missed-upgrade rollout; existing
  lifecycle gate confirmed correct; reusable admission join added and tested
- Trigger: follower-5's image was patched while the StacksNetwork still
  reported `Ready` for the previous generation. An immediate StatefulSet
  rollout/wait returned success against the old Pod; the operator observed the
  new generation and terminated that Pod moments later.
- Impact: a caller that waits only for `status.phase=Ready`, actor counts, or a
  StatefulSet's currently complete revision can capture the wrong Pod UID and
  wrong image as rollout evidence. This is a false pass, not merely a slow
  rollout.
- Correction: every mutation wait and image-admission join must require
  `status.observedGeneration == metadata.generation` before accepting Ready.
  `lifecycle.sh` already enforces this for full-network and bootstrap waits.
  The new `image-admission-evidence.mjs` independently rejects stale
  generations and binds the admitted declaration to the replacement Pod UID,
  Ready actor container, and exact runtime image identity. Its negative test
  proves stale status cannot pass.

## F-088: Preloading a local kind image does not make its registry digest pullable

- Classification: local-cluster image-distribution ambiguity
- State: reproduced, attributed, and handled explicitly in the admission
  contract
- Trigger: follower-5 was assigned the otherwise correct unqualified digest
  reference `stacks-core-attacknet@sha256:8b794...` after the image had been
  imported into each kind node under its content-derived tag.
- Result: kubelet treated the digest reference as
  `docker.io/library/stacks-core-attacknet@sha256:...` and entered
  `ImagePullBackOff`; no such registry object exists. A node-local tag with
  `IfNotPresent` then admitted immediately.
- Boundary: an OCI digest reference is the right declaration for a real
  registry-backed cluster, but local containerd does not infer a second name
  from matching content. In registry-free kind, the tag is only a transport
  handle. Acceptance must bind the exact Pod UID and CRI runtime config digest
  to a sealed build record; a matching tag alone remains insufficient.

## F-089: BuildKit image-index digests and Kubernetes runtime image IDs identify different OCI objects

- Classification: mixed-version evidence-contract defect
- State: reproduced, corrected, regression-tested, and proven live
- Trigger: BuildKit reported image/index digest `sha256:8b794...`, while the
  Ready follower-5 Pod reported `imageID=sha256:42fb1...`. Treating those as
  directly comparable made a correct rollout appear unauthenticated.
- Root cause: maximum provenance produces an OCI index. Its arm64 descriptor is
  platform manifest `sha256:6f83e...`; that manifest names runtime config
  `sha256:42fb1...`. Containerd correctly reports the config digest through
  CRI. The outer index additionally carries an attestation manifest and is not
  the executable config identity.
- Correction: the build executor now exports the loaded image to a temporary
  OCI archive, verifies every blob digest, selects exactly one requested
  platform manifest, verifies its config, and records the complete
  index/manifest/config chain. The admission join requires the Pod's terminal
  CRI digest to equal `expectedRuntimeImageID`, plus exact actor, network,
  observed generation, and Pod UID. Tests prove the two hashes are distinct
  and that a wrong runtime digest fails closed.
- Rebuild nuance: a cached rebuild produced a different provenance/index
  digest (`sha256:73019...`) while retaining the same arm64 manifest
  `sha256:6f83e...` and runtime config `sha256:42fb1...`. Attestation-envelope
  nondeterminism must therefore remain visible in each build record, while
  executable-byte comparison uses the verified config identity.

## F-090: The default progress window was shorter than the configured burn cadence

- Classification: backend-neutral assertion calibration defect
- State: deliberately reproduced, corrected, and regression-tested
- Trigger: the shared verifier defaulted to a 45-second observation while the
  live manifest declares a 60-second steady burn interval. A ten-second
  negative control and a naturally aligned short run both observed zero burn
  progress despite a healthy clock and correctly failed; a fixed short default
  would make ordinary success depend on where the sample lands within a minute.
- Correction: `progress-window.mjs` now derives the default from
  `manifest.protocol.steadyBurnIntervalSeconds`, adding a bounded 25% jitter
  margin with a 15-second floor. The current topology therefore uses 75
  seconds. Explicit overrides remain bounded and validated. A 75-second live
  window advanced both burn and Stacks heights by two while the full cohort and
  peer invariants passed.
- Evidence: the exact 4.0.2 build/admission join, both current and released
  executable versions, deliberate short-window failure, successful
  cadence-aware progress result, and checksums are retained in
  `contrib/attacknet/evidence/mixed-version-4.0.2-follower5-20260815T1840Z/`.

## F-091: Recovery assertion timeouts were implemented as a single post-fault sample

- Classification: orchestration truthfulness and recovery-classification defect
- State: reproduced live; corrected and regression-tested; successful arm64
  I/O-pressure effect, recovery, cleanup, and subsequent network progress
  proven live
- Trigger: the first controller-owned I/O-pressure run raised follower-1's
  FSYNC p95 from 1.009 ms to 2.310 ms. The pressure Pod then completed and was
  removed, but the first post-fault sample was still 1.721 ms. The campaign
  immediately terminated `Inconclusive/EffectNotProven` even though its
  `IOPressureRecovered` assertion declared a 300-second timeout.
- Root cause: the `Recovering` state used the recovery timeout only while
  waiting for the target Pod to become Ready. Once Ready, it collected exactly
  one after-fault probe and made that result terminal. It never polled a failed
  recovery observation inside the advertised window. The status was also
  imprecise: `IOPressureObserved` was Proven, while only recovery had failed,
  yet the reason said `EffectNotProven`.
- Correction: effect and recovery satisfaction are evaluated independently.
  A proven effect plus an unproven recovery now remains
  `Recovering/WaitingForRecoveryEvidence`, preserves each trusted observation,
  and polls until recovery is proven or its timeout expires. Terminal failure
  is named `RecoveryNotProven`; an actually unproven effect remains
  `EffectNotProven`. A regression test forces the first after sample to remain
  elevated and the second to recover.
- Live acceptance: `baseline-parity-io-pressure-pod-r3` resolved exact target
  Pod UID `09871823-0c51-4ca0-b857-3b6cda1a9142`, PVC
  `data-attacknet-baseline-signer-parity-follower-1-0`, and node
  `desktop-worker2`. Its chart-owned arm64 pressure Pod UID was
  `d61a957a-06b1-4638-8504-15b82829e452`, with runtime image ID
  `sha256:d23fa3d4b688ba61d0dd556a063f59bbbc4bebaf0084add04d418561292cc6b3`.
  FSYNC p95 met both effect thresholds at 8.177x / +17.433 ms and subsequently
  fell below both at 0.694x / -0.743 ms. Exact owned-resource absence was
  confirmed, follower-1 retained the same UID with zero restarts, no named
  pressure files remained, and PVC free space returned to 40.8 GB.
- Network acceptance: the cadence-aware post-fault window exited zero and
  advanced burn 435 -> 436 and Stacks 234 -> 235. All 18 Stacks nodes agreed
  exactly on burn height, Stacks height, and tip; every node had at least 24
  authenticated live conversations and no actor exceeded the one permitted
  unauthenticated conversation. Evidence is retained under
  `contrib/attacknet/evidence/io-pressure-pod-arm64-20260815T185207Z/`.

## F-092: A planned mid-run topology mutation makes the file-backed run ledger unexportable

- Classification: reproducibility-ledger lifecycle gap
- State: reproduced during evidence capture; correctly failed closed;
  immutable initial/admitted input snapshots implemented and regression-tested;
  explicit admitted mutation events remain to complete replay of phase changes
- Trigger: the active network's generated `stacksnetwork.json` was changed to
  place released 4.0.2 on follower-5 after the lifecycle run descriptor had
  sealed its initial digest. Later I/O-pressure evidence capture asked the run
  ledger to export the original inputs.
- Result: export reported `exported artifact digest mismatch` for that source
  path. Kubernetes admitted state, exact run/campaign CRs, actor metrics/logs,
  and the trusted timeline were still captured, and the error marker prevents
  the partial ledger from being mistaken for a reproducible bundle. This is a
  truthful failure, not corruption evidence.
- Correction: run initialization now copies topology, requested manifest, and
  every rendered configuration into content-addressed `initial-inputs` before
  sealing their descriptor paths. Runtime resolution likewise snapshots the
  admitted manifest into `runtime-inputs` before updating the descriptor. Tests
  mutate and replace all original paths after those phases and prove export
  still verifies only the immutable copies.
- Remaining gap: each admitted topology/image change must become an ordered
  ledger action carrying old/new generations, source/spec digests, admitted
  Pod UIDs, and runtime image IDs. The snapshots make the original run
  exportable; they do not by themselves replay the later mixed-version phase.

## F-093: Local chart installation does not distribute newly built images to kind nodes

- Classification: local deployment workflow and image-admission usability gap
- State: repeatedly reproduced; automatic kind-on-Docker loader implemented,
  regression-tested, integrated before Helm mutation, and proven on all three
  live nodes
- Trigger: `build-local.sh` created updated run-controller and I/O-pressure
  images, and `install-local.sh` assigned content-derived tags, but those tags
  existed only in Docker Desktop's image store. The three kind nodes use their
  own containerd stores.
- Impact: an otherwise valid Helm upgrade can enter `ImagePullBackOff` or reuse
  an older node-local tag unless the operator manually imports the exact image
  into every node. The current run was repaired with explicit OCI imports and
  admitted runtime IDs, but that manual sequence is easy to omit and is not a
  suitable multi-version attacknet contract.
- Correction: `load-kind-images.sh` identifies nodes only from server-assigned
  `kind://docker/.../<node>` provider IDs, verifies matching Docker containers,
  imports one archive into every node's `k8s.io` containerd namespace, verifies
  every normalized reference, and emits a machine-readable node/image/host-ID
  receipt. `install-local.sh` invokes it in auto mode before CRD/Helm mutation;
  require and explicitly disabled modes are available. Tests cover complete
  import, non-kind skip/fail behavior, and read-only help/invalid inputs.
- Live acceptance: the three exact currently admitted chart images were loaded
  and verified across `desktop-control-plane`, `desktop-worker`, and
  `desktop-worker2`, producing nine verified joins and no Kubernetes workload
  mutation. The receipt is retained with the I/O-pressure evidence. Real
  clusters continue to require immutable registry digests; this local
  Docker/containerd mechanism is not used by the general operator.

## F-094: kind local-path volumes correctly strand Pods when their node is unavailable

- Classification: multi-node storage behavior and recovery boundary
- State: deliberate negative control and same-volume recovery proven live;
  actual worker-process outage and portable-CSI cross-node reattachment remain
  separate scenarios
- Setup: follower-2's PVC
  `data-attacknet-baseline-signer-parity-follower-2-0` was bound to PV
  `pvc-422bcfc8-2619-42cf-b28a-f53217380643`. The PV's required node affinity
  named `desktop-worker`; the actor Pod UID was
  `8b4b3a4c-9222-4721-b0e0-163ec7bf57de`.
- Negative control: under the shared mutation lease, only
  `desktop-worker` was cordoned and only follower-2's Pod was deleted. The
  StatefulSet created replacement UID
  `3210e50f-b07f-420d-861c-2c77f6a3bc14`, which remained Pending with
  `PodScheduled=False/Unschedulable`. Scheduler evidence included the volume
  node-affinity conflict; Kubernetes did not pretend to recover by attaching
  node-local chainstate to another worker.
- Recovery: uncordoning the original worker scheduled the replacement there.
  The PVC UID and PV UID were unchanged, both actor and trusted probe became
  Ready with zero restarts, and the full cohort converged before the scenario
  proceeded. The cadence-aware gate then advanced burn 441 -> 442 and Stacks
  239 -> 240 with zero height drift and one canonical tip. The mutation lease
  released and the worker remained Ready and schedulable.
- Boundary: this proves truthful local-path stranding and recovery when the
  original node returns. It does not prove that a local-path volume can move to
  another node—it cannot—or that a portable CSI driver reattaches correctly.
  A real worker outage and a portable-CSI cross-node scenario should be kept as
  distinct experiments with distinct expected outcomes.
- Evidence: requested actions, before/stranded/after Pod state, scheduler
  events, exact PVC/PV identities, chain snapshots, progress result, and
  checksums are retained at
  `contrib/attacknet/evidence/pvc-node-affinity-recovery-20260815T190500Z/`.

## F-095: Majority-weight worker loss pauses Stacks quorum and recovers without unsafe progress

- Classification: clean adversarial result plus evidence-schema correction
- State: real kind worker process stopped and restarted; recovery proven live;
  exact future outage timing made explicit
- Setup: `desktop-worker` hosted six active signers carrying 16 of the current
  reward set's 30 slots (53.33%). The experiment acquired the mutation lease
  and explicitly set `allowQuorumLoss=true`; it never renormalized signer
  weights or lowered the 70% threshold.
- Fault: the exact kind node container was stopped. Kubernetes changed the
  node to `Ready=Unknown/NodeStatusUnknown` at 19:20:59Z and back to
  `Ready=True` at 19:21:52Z. Burnchain remained available on the other worker.
- Consensus result: five-second Prometheus evidence shows all three miners at
  Stacks height 250 before and throughout the node-unready interval. Their
  first height-251 samples occurred at 19:22:20Z, after the worker returned.
  The network therefore paused instead of producing with insufficient signer
  weight, then resumed automatically. This is a clean safety/liveness result,
  not a node defect.
- Recovery: all 31 workloads returned Ready; every network PVC retained its
  UID; the cadence-aware gate advanced burn 456 -> 458 and Stacks 253 -> 254;
  the cohort had at most one block of transient drift, no equal-height fork,
  and live authenticated P2P connectivity recovered.
- Harness correction: the original result called the configured 50-second
  post-NotReady hold `downtimeSeconds`, even though Docker had already been
  stopped while Kubernetes detected the loss. That label understated the
  total fault window. The runner now records stop-requested, Docker-stopped,
  NotReady-observed, start-requested, and Ready-observed timestamps and reports
  the intentional hold separately. The retained run is annotated rather than
  inventing absent Docker timestamps.
- Evidence:
  `contrib/attacknet/evidence/worker-outage-recovery-20260815T192000Z/`.

## F-096: The Bitcoin clock health server could close before reading the kubelet request

- Classification: harness readiness false-negative and HTTP lifecycle defect
- State: corrected, regression-tested, and live-proven over the measured soak
- Evidence: the clock mined continuously with zero container restarts, but
  Kubernetes accumulated 36 intermittent readiness failures over roughly four
  hours. The kubelet error was
  `readLoopPeekFailLocked: %!w(<nil>)`; the Pod remained Ready because the
  threshold intentionally tolerates transient failures. Direct requests from
  the trusted sidecar succeeded.
- Root cause: the minimal Perl health server wrote a response and closed the
  accepted socket without reading the HTTP request. That can race a client's
  request write and produce a TCP reset/ambiguous close even though the clock
  process is healthy. This is an apparatus failure, not Bitcoin or Stacks
  liveness evidence.
- Correction: consume one complete request header with an 8 KiB bound and a
  one-second read deadline before returning the fixed response. Incomplete or
  slow clients are closed without occupying the single-threaded listener
  indefinitely. A behavioral test performs 50 complete HTTP exchanges and
  requires every response body and status.
- Live proof: the corrected clock Pod ran with zero restarts and remained Ready
  in all 92 independently captured Pod-health samples across the exact burn
  503 -> 803 interval, including the four deterministic fault campaigns. The
  final lifecycle teardown completed without a clock-health exception.

## F-097: Expected future reward-set lookup state is emitted as an error storm

- Classification: current-node observability correctness and incident-noise gap
- State: repeatedly observed on current main; no liveness impact established;
  implementation site and phase relationship confirmed
- Trigger: Prometheus/Grafana and operator checks poll `/v2/pox` before the
  next reward cycle's prepare phase exists in the canonical sortition chain.
  At burn 471, for example, current cycle 23 was healthy and the API reported
  four blocks until cycle 24's prepare phase, while each lookup attempted to
  resolve a prepare-phase ancestor at future height 476.
- Result: `get_prepare_phase_start_sortition_id_for_reward_cycle` logs
  `Could not find prepare phase start ancestor while fetching reward set` at
  error level and returns `NotFound`. Repeated `/v2/pox` clients turn the
  expected not-yet-available state into multiple error lines roughly every two
  seconds. Chain height and signer activity continue. A bounded post-boundary
  sample at burn 476 contained zero matching errors, confirming that the storm
  is phase-bounded rather than persistent database corruption.
- Recommended correction: if the computed prepare-phase start exceeds the
  canonical sortition tip, return an explicit not-ready/absent result without
  error logging. Preserve error severity for an ancestor that should already
  exist, and add before/at/after prepare- and reward-boundary tests. Bound or
  coalesce any remaining endpoint diagnostic.
- Portability: this behavior predates attacknet and is transport-independent;
  the accelerated regtest makes its volume conspicuous but does not create the
  logical future-ancestor condition.
- Measured-soak evidence: the exact burn 503 -> 803 window contained 300
  `PoXAnchorBlockRequired` response errors plus 300 corresponding
  `RequestFailure(400)` client errors--60 lines per signer--while the chain
  advanced all 300 requested burn blocks and every signer remained registered.
  The volume is therefore material forensic noise even though no liveness
  failure accompanied it.

## F-098: A restored peer can amplify stale Nakamoto-inventory send warnings for minutes

- Classification: current-node P2P recovery efficiency and log-amplification
  finding
- State: one worker-restart occurrence classified; network recovered; internal
  ownership/race mechanism needs a focused reproduction before remediation
- Evidence: after `desktop-worker` returned, miner-2 emitted at least 3,039
  warnings from 19:22:12Z through the first 19:39 sample for
  `failed to send GetNakamotoInv ... PeerNotConnected` to stale neighbor
  identity `8e5553...` at follower-2's unchanged Pod IP `10.244.1.23`. During
  the same interval `/v2/neighbors` showed a different, live authenticated
  identity `e13e93...` at that address and the full cohort kept progressing.
  The old identity repeatedly logs an unauthenticated-timeout drop under a new
  event ID, then reappears; at 19:41:21Z event 567 dropped and fresh warnings
  were still arriving. A later bounded sample contained 171 matching warnings
  in 60 seconds. The final soak capture paginated 6,369 matching Loki entries;
  its most recent retained warning was at 20:10:58Z, roughly 49 minutes after
  the worker returned. The condition had therefore still not self-cleared when
  the run crossed its 300-block boundary, even though protocol progress
  continued. The local cluster has no Metrics
  Server, so this run does not quantify its CPU cost. At that rate, the
  harness's intentionally bounded 20,000-line per-actor incident capture can
  also lose earlier causal context in under two hours; Loki retention remains
  the longer forensic source when available.
- Bounded conclusion: worker/process recovery can leave an inventory peer
  eligible for repeated send attempts long after a healthy replacement
  conversation exists. This run proves recovery plus substantial warning
  amplification; it does not yet prove whether the underlying cause is peer
  key rotation, duplicate conversation bookkeeping, or a race between
  `iter_peer_event_ids` and `neighbor_send`.
- Follow-up: create a focused stable-IP peer-restart test that records both
  endpoint identities, event IDs, connection registration/removal, inventory
  map membership, warning count, CPU, and time-to-garbage-collection. A failed
  send to an already-disconnected inventory peer should be bounded and should
  promptly evict or suppress that state rather than warning thousands of
  times. The current run should be observed through its 300-block boundary to
  determine whether the condition ever clears. Verify the same behavior on a
  normal VM/TCP network before attributing any rate to kind.

## F-099: Teardown evidence does not yet export the retained Loki log corpus

- Classification: forensic-evidence completeness gap
- State: confirmed by harness inspection; bounded Kubernetes log snapshots and
  the trusted event timeline are exported, but the centralized Loki streams are
  not
- Impact: Loki is intentionally the longer forensic source when actor output
  exceeds the 20,000-line `kubectl logs` cap or kubelet rotates a container log.
  The stale-peer condition in F-098 can fill that bounded snapshot in under two
  hours. Deleting a network's observability PVC before exporting the relevant
  Loki range can therefore discard the earliest causal context even though the
  dashboard displayed it during the run.
- Required correction: add a paginated, time-bounded Loki exporter that records
  the exact LogQL selector, start/end nanoseconds, stream labels, per-page
  cursors, truncation/limit state, Loki build/config identity, and digests. The
  incident and normal teardown paths must run it before deleting observability
  storage, fail visibly on an incomplete export, and preserve the PVC for
  forensic recovery rather than treating an empty/truncated response as
  success. Keep the existing `kubectl logs` snapshots as an independent source;
  neither collector is assumed complete by itself.

## F-100: The retained full topology crossed 300 burn blocks and kept progressing

- Classification: preliminary long-run acceptance evidence
- State: passed and digest-sealed; deliberately not the final corrected soak
- Evidence: the clean-volume network began at burn 202 and reached burn 502.
  At that boundary all 18 Stacks nodes reported burn 502, Stacks height 297,
  zero drift on either height, one common tip, and no same-height fork. A new
  bounded window then advanced burn 503 to 504 and Stacks 298 to 299 while the
  full cohort remained in agreement. All 31 declared network workloads and all
  38 enrolled network/observability Pods were Ready; all 32 PVCs were Bound;
  every node retained at least 41.6 GB of root/image filesystem headroom.
- Adversarial coverage retained in the same run: recovered Pod, network, DNS,
  controller-owned disk-pressure, local-path node-stranding, and real worker
  outage experiments; the worker carried 53.33% signer weight and produced the
  expected safe quorum pause before recovery. Follower-5 ran the released 4.0.2
  image while the remaining actors ran the current branch image.
- Qualification: this run predates immutable rendered-input snapshots and the
  Bitcoin clock HTTP correction. The planned follower-5 image mutation causes
  the old ledger to reject export with an artifact digest mismatch, exactly as
  it should; the admitted clock was not hot-rolled. F-098 also remained active
  at the boundary. This evidence therefore validates the retained network and
  fault recoveries but does not satisfy the active goal's final fresh corrected
  soak.
- Bundle:
  `contrib/attacknet/evidence/full-topology-preliminary-300-20260815T201007Z/`.
  Its `SHA256SUMS` verifies every retained file, including the explicit ledger
  failure, actor metrics/logs/APIs, admitted Kubernetes state, targeted
  paginated Loki evidence, storage report, and machine classification.

## F-101: A retained event bridge can reject a newer lifecycle's terminal event contract

- Classification: observability-component rollout compatibility gap
- State: reproduced at preliminary-run closure; current source accepts and
  tests the expanded phase/kind contract; fresh joint-image live proof pending
- Trigger: the lifecycle and record helpers in the worktree were newer than the
  event-bridge image admitted when the retained run began. Closing the run tried
  to record teardown actor state and `run.finished` using the current trusted
  event contract.
- Result: the active bridge returned HTTP 400 on all three bounded attempts.
  No terminal event was fabricated. The 196 previously accepted events were
  exported read-only and an explicit error record was added to the evidence
  bundle. Chain state and workload readiness were unaffected.
- Correction and gate: deploy the bridge, lifecycle, and recorder contract from
  one chart/image revision, publish a bounded contract-version readiness value,
  and reject lifecycle startup before a run if required kinds/phases are not
  supported. The final clean run must prove `run.started`, fault/invariant
  events, teardown actor states, and `run.finished` end-to-end from the same
  admitted revision. Retaining old components is valuable for mixed-version
  protocol tests, but the trusted measurement plane itself must not drift
  accidentally.
- Evidence: `final-event-write-error.json` and `timeline-final/` in the F-100
  bundle.

## F-102: A mutable local actor tag can pair an old binary with a newer readiness contract

- Classification: build/admission identity and lifecycle compatibility gap
- State: reproduced on a fresh seven-workload lifecycle; fail-closed behavior
  worked, corrective rebuild and fresh replay pending
- Trigger: after the controllers were rebuilt from the current worktree, a
  fresh topology still requested the convenience tag
  `stacks-core-attacknet:main`. The kind nodes resolved that tag to an older
  actor image whose executable reported source `a7e3e76019d9+`. The current
  StatefulSet readiness contract requires
  `stacks_signer_runloop_ready` and
  `stacks_signer_registered_for_current_reward_cycle`.
- Result: the signer really initialized and logged that signer 0 was registered
  for reward cycle 11, but its metrics endpoint exported neither readiness
  gauge. Kubernetes correctly kept the actor NotReady and the two-phase
  lifecycle refused to claim completion. Storage, Bitcoin exact-height
  bootstrap, account locking, companion observer rollout, and the remaining
  actors were healthy. The wait was stopped after the binary/metric mismatch
  was proven rather than weakening readiness or waiting out the full deadline.
- Impact: a mutable local tag is only a transport convenience. Rebuilding a
  chart/controller without rebuilding every actor can silently admit a binary
  whose telemetry and readiness contract predates the harness. This can waste a
  full bootstrap interval and, if probes are permissive, could produce false
  acceptance evidence. It is the actor-side analogue of F-101.
- Required correction: rebuild and load the actor image from the exact current
  source, retain its OCI/runtime identity, and bind that identity to each
  admitted Pod UID. The default lifecycle should gain a pre-run build-contract
  receipt or equivalent expected runtime-config check so a mutable tag alone
  cannot satisfy acceptance. Mixed-version actors remain allowed only when the
  requested older contract and compatible probes are explicit.
- Evidence:
  `contrib/attacknet/evidence/ddmin-live-stale-actor-contract-20260815T2042Z/`.
  It contains the pre-teardown snapshot, trusted timeline, and aborted run
  export; actor logs and the live metrics response establish registration
  versus missing readiness metrics.

## F-103: Fresh-network image identity was hashed in two different actor orders

- Classification: replay/minimization harness correctness defect
- State: reproduced live; canonical ordering and behavioral regression test
  implemented; closed by the successful R5 fresh replay and counterfactual
- Trigger: the first live ddmin baseline recreated the source topology with a
  new `StacksNetwork` UID and then compared the admitted image set with the
  sealed source schedule. Every actor retained the same requested reference,
  runtime `imageID`, and immutable digest.
- Result: replay paused before creating an `AttacknetRun` with `fresh network
  changed the admitted images`. The source schedule canonicalized images by
  actor scope before hashing, while the Kubernetes adapter hashed the same
  records in `StacksNetwork.spec.actors` declaration order. The two arrays
  contained identical records but produced different digests. The fresh
  network was deliberately preserved for triage and no fault was injected.
- Impact: any non-lexically ordered topology could be misclassified as image
  drift, making deterministic replay and ddmin unusable despite an unchanged
  admitted binary set. The fail-closed behavior prevented an invalid causal
  claim, but the false-positive consumed a full clean bootstrap.
- Correction and gate: `resolvedNetworkImages()` now returns records sorted by
  actor scope, matching the persisted schedule's canonical contract. A
  behavioral test reverses actor declaration order and proves both the ordered
  result and full record set remain identical. The live source/replay/ddmin
  sequence must be repeated across fresh network UIDs before this finding is
  closed.
- Evidence:
  `contrib/attacknet/evidence/ddmin-live-20260815T2053Z/ddmin/` contains the
  preserved-network marker, source receipt, executor error, storage preflight,
  and execution ledger. The compared source and fresh image records establish
  that order was the only difference.

## F-104: Teardown could return before the `StacksNetwork` owner was deleted

- Classification: lifecycle delete/recreate race
- State: reproduced by the first live reduced ddmin attempt; corrected and
  covered by a behavioral polling test; closed by the R5 consecutive fresh
  network recreations
- Trigger: the baseline replay completed and exported its evidence, after which
  ddmin requested a new clean network for the first removal-only candidate.
  `lifecycle.sh delete` issued an asynchronous CR deletion and waited for
  labeled children and PVCs, but it did not include the owner
  `StacksNetwork` itself in the absence condition.
- Result: a rapid subsequent `kubectl apply` could successfully update the
  still-terminating owner. Kubernetes then completed the already-requested
  deletion. The apply process returned zero, but the adapter's immediate
  admitted-state read found no `StacksNetwork`; it emitted no fault, classified
  the attempt Inconclusive, and preserved the evidence directory for triage.
- Impact: serialized execution alone does not make delete/recreate safe when
  the API object's deletion is asynchronous. Replay, minimization, or any
  same-named clean-run loop could lose an entire freshly applied environment
  at this boundary and spend another bootstrap interval diagnosing a false
  experiment failure.
- Correction and gate: `wait_deleted()` now requires both the owner CR and all
  non-artifact labeled resources to be absent before returning. The regression
  test makes a fake owner survive the first poll and proves teardown performs a
  second poll rather than accepting child absence alone. A successful live
  source replay followed by candidate recreation must prove the corrected
  boundary.
- Evidence:
  `contrib/attacknet/evidence/ddmin-live-r2-20260815T210356Z/ddmin/` seals the
  successfully reproduced baseline and the subsequent zero-attempt
  `StacksNetwork NotFound` pause separately.

## F-105: Ddmin inferred two different source-evidence roots from directory depth

- Classification: replay/minimization evidence-path contract defect
- State: reproduced after the F-104 correction; explicit root contract and
  regression implemented; closed by the R5 shared source receipt
- Trigger: the executor stores baseline evidence at
  `<root>/baseline-replay/` and candidate evidence at
  `<root>/attempts/<id>/`. The Kubernetes adapter inferred the shared source
  receipt by applying `dirname()` twice to the attempt directory.
- Result: baseline captured the source at `<parent-of-root>/source/`, while the
  candidate searched `<root>/source/`. After the baseline had correctly
  exported evidence and deleted its fresh network, the candidate treated the
  missing receipt as a request to recapture source state. That read returned
  `StacksNetwork NotFound`; no candidate network or fault was created, and the
  executor paused Inconclusive. The baseline itself again reproduced the exact
  expected failure on fresh UID `42b5adc9-8d92-4804-90ab-96e2296ca909`.
- Impact: path-shape inference coupled the adapter to an incidental directory
  layout and made the first counterfactual impossible even though replay,
  cleanup, image identity, and owner deletion all worked.
- Correction and gate: `executeDdmin()` now passes the single resolved evidence
  root explicitly to every `recreateNetwork()` call. The adapter captures and
  reads only `<root>/source/receipt.json`. Before reuse it verifies the receipt
  digest, local URI, source run UID, schedule digest, source network UID, and
  logical network name; a partial record is never overwritten by recapture. A
  behavioral executor test proves the baseline and all counterfactual
  recreations receive the identical root. The full live replay plus reduced
  attempt then passed in R5.
- Evidence:
  `contrib/attacknet/evidence/ddmin-live-r3-20260815T212010Z/ddmin/` contains a
  reproduced baseline, its fresh UID and classification, followed by the
  pre-admission candidate error with no injected resource.

## F-106: Candidate recreation redundantly tore down an already-absent network

- Classification: replay/minimization lifecycle idempotency defect
- State: reproduced after the F-105 correction; fixed with fail-closed network
  presence detection; closed by the R5 candidate recreation
- Trigger: after a reproduced baseline, `deleteAttemptNetwork()` had already
  deleted the replay `AttacknetRun`, exported the network evidence, removed the
  `StacksNetwork`, waited for its owner and children to disappear, and released
  both leases. The next candidate's `recreateNetwork()` nevertheless invoked a
  second full lifecycle deletion before applying the next clean network.
- Result: the empty teardown located the finalized baseline run ledger and
  attempted terminal observability export after its event bridge had already
  been removed. The required export failed, so the lifecycle returned nonzero
  before candidate apply. The executor paused Inconclusive and injected no
  candidate fault. Baseline replay again reproduced the expected assertion on
  fresh UID `774e5815-4ab7-4a3f-a3d5-96ed9d8c9dad`.
- Impact: a deliberately strict teardown was being asked to finalize the same
  run twice. Its refusal was correct, but the redundant call prevented all
  post-baseline counterfactuals.
- Correction and gate: recreation now queries the owner CR first and runs
  teardown only when it exists. A genuine NotFound is the only accepted absent
  result; API unavailability or any other error remains fatal. Unit coverage
  proves present, absent, and API-error branches. The final live sequence must
  still demonstrate candidate creation, classification, evidence export, and
  cleanup.
- Evidence:
  `contrib/attacknet/evidence/ddmin-live-r4-20260815T213348Z/ddmin/` seals the
  reproduced baseline and the failed redundant teardown separately.

## F-107: Fresh replay and one removal-only counterfactual reproduced the same failure

- Classification: positive replay/minimization acceptance evidence
- State: passed, cleaned up, and integrity-verified
- Experiment: source run 5 executed an irrelevant one-shot follower Pod kill
  followed by a TCP packet-duplication NetworkChaos whose trusted
  `NetworkDegraded` effect assertion deliberately returned `Failed`. The
  failure is useful as a deterministic negative control: Chaos Mesh reported
  injection, but TCP absorbed the duplication and the named probes did not
  report the required protocol-error delta.
- Baseline replay: a clean network with UID
  `909dcff4-ec7a-416a-9575-8ba337d5d6c5` admitted the exact sealed source
  schedule and reproduced `NetworkDegraded=Failed`.
- Counterfactual: ddmin removed only `irrelevant-pod-kill`, admitted candidate
  digest
  `sha256:4799bdf8c0bf6f237819bca8e93dfd9f3eb6416087e6ca08f7d4c66db341f966`
  on a second clean network UID `a6fc4529-8c0b-41de-a9df-1a0ac7b3efc8`, and
  reproduced the same trusted assertion. Both runs used the same manifest,
  admitted image set, source template identities, seed, and source schedule.
- Interpretation: this proves one useful semantic reduction—the Pod kill was
  not necessary for the observed failure under this replay. The one-attempt
  budget then expired, so the executor correctly reports `BudgetExhausted`,
  `empiricallyReduced=false`, and `causalMinimalityClaimed=false`; it does not
  claim the remaining campaign is minimal or causal in any broader sense.
- Cleanup and evidence: both fresh networks exported evidence before deletion;
  no `StacksNetwork`, environment lease, or mutation lease remained. The
  execution receipt's canonical SHA-256 integrity verified locally. Bundle:
  `contrib/attacknet/evidence/ddmin-live-r5-20260815T214626Z/ddmin/`.

## F-108: A restarted burnchain clock replayed a completed one-shot burst

- Classification: burnchain-cadence idempotency and lifecycle safety defect
- State: fixed, regression-tested, and proven by a clean live Compose phase
  transition
- Trigger: the Compose bootstrap reached the observer barrier at Bitcoin
  height 220 using `BURST_BLOCKS=9`. Applying the final Compose phase recreated
  `bitcoin-miner` while preserving the last policy generation. The new clock
  process initialized `burst_remaining` from the durable count and mined the
  same nine blocks again, reaching 229 without an orchestrator request.
- Impact: any clock Pod/container restart after a completed burst could cross
  signer enrollment, observer, activation, or hard-fork barriers. The evidence
  ledger would still describe the requested target while Bitcoin had advanced
  farther, invalidating the experiment and potentially manufacturing a signer
  outage. This is a harness defect, not Bitcoin Core behavior.
- Correction and gate: new burst policies include
  `BURST_TARGET_HEIGHT=current_height+requested_count`. On every generation
  application or process restart, the clock derives remaining work as
  `max(0, target-current)`; an already-reached target therefore mines nothing.
  Legacy count-only policies remain readable for upgrade compatibility. Unit
  coverage proves a restart below the target resumes only the remainder and a
  restart at the target performs zero work. The Compose cadence API now uses
  the same process-level policy acknowledgment as Kubernetes. A clean phase
  transition then reached target height 220 under generation 7, recreated both
  Bitcoin and `bitcoin-miner`, waited 12 seconds, and observed Bitcoin still at
  exactly 220. The restarted clock reported `state=paused`,
  `bitcoin_height=220`, and `policy_generation=7`, proving that it recognized
  the completed target instead of replaying the eight-block request.

## F-109: Compose declared a healthy Bitcoin clock unready because its probe tool was absent

- Classification: backend-parity and readiness-evidence defect
- State: fixed, regression-tested, and proven by a clean live re-render
- Evidence: the clock was paused at the requested burn height 223, its status
  file was fresh, and its dedicated listener was accepting on port 18500, but
  the shared verifier reported `Unready actors: bitcoin-miner`. Docker recorded
  63 consecutive healthcheck exits with code 127 and `curl: not found`.
  `bitcoin/bitcoin:25.2` intentionally contains neither curl nor wget; the
  rendered Compose healthcheck therefore measured image packaging rather than
  clock health. Kubernetes uses a TCP socket probe and did not share the bug.
- Impact: every otherwise-valid Compose assertion was forced to fail, so a
  paired backend control could falsely appear to show behavioral divergence.
  Ignoring the actor would have hidden a genuinely failed cadence process as
  well, so verifier weakening is not an acceptable workaround.
- Correction and gate: the Compose renderer now executes a direct TCP connect
  with Perl's `IO::Socket::INET`. Perl is already a runtime dependency of the
  clock's health listener, so the probe adds no package or shell assumption.
  Regression coverage inspects the rendered healthcheck and forbids curl. The
  active small topology was then re-rendered from the corrected source and
  rolled onto the same persisted chain at burn 223. After two `starting`
  observations the clock became `healthy`, while Bitcoin remained exactly at
  223 throughout; no readiness exception or chain advance was hidden.

## F-110: The Kubernetes backend reported a successful pause without stopping the actor

- Classification: deliberate-negative-control truthfulness defect
- State: fixed, regression-tested, and proven with a controller-owned live
  negative control
- Evidence: `runtime-backend.sh pause follower-1` returned success after issuing
  `kill -STOP 1` through `kubectl exec`, but the follower remained Ready and
  served every probe for more than 30 seconds. The admitted actor really does
  run `stacks-node` as PID 1; this was not a wrapper-process mistake. PID 1 is
  the namespace init process, and Linux does not deliver an in-namespace
  SIGSTOP to it even though `kill` reports success. A second direct probe
  observed PID 1 still in sleeping state before and after STOP/CONT.
- Impact: a paired negative control could claim that Kubernetes tolerated a
  frozen actor when no fault had occurred. This is the same false-pass class
  the attacknet is intended to eliminate.
- Correction and gate: Kubernetes `pause` and `resume` now fail closed with an
  instruction to use a controller-owned `FaultCampaign`; they never issue the
  ineffective signal or report success. Compose retains cgroup-level
  pause/unpause. The Kubernetes half of the parity test uses bounded PodChaos
  `pod-failure`, requires the shared verifier to name `follower-1` as unready,
  and requires controller-proven cleanup plus a healthy verifier result. The
  live campaign proved `PodUnavailable`; the verifier exited 1 with exactly
  `Unready actors: follower-1`; the same Pod UID recovered; and all nodes then
  agreed at burn 229 / Stacks height 26 with four authenticated conversations
  each.

## F-111: A terminal campaign briefly exposed stale cleanup status

- Classification: controller-status atomicity and forensic-evidence defect
- State: fixed, regression-tested, rolled out, and proven live
- Evidence: the controller did not enter `Recovering` until it had requested
  Chaos deletion, and it did not enter `Passed` until a later GET proved the
  `PodChaos` absent. Nevertheless, the terminal status update copied the older
  `cleanup.absent=false` field. The next terminal reconcile corrected it five
  seconds later. A reader in that window—exactly what the parity run captured—
  saw `phase=Passed`, `EffectAndRecoveryProven`, and `cleanup.absent=false`.
- Impact: the safety action itself was correct and the Chaos resource was
  already absent, but an evidence snapshot could not distinguish that from a
  controller which declared success before cleanup. This undermines incident
  attribution and automated acceptance gates.
- Correction and gate: the authoritative absence observation in `Recovering`
  is now copied into the same status patch that records recovery evidence or a
  terminal result. Tests require `Passed` and `cleanup.absent=true` in one
  observed object. After rolling immutable run-controller image
  `sha256:e0473bd2b44c3eeaf75733b13e76bc10c9ead47869a15cd59c176f1a49d92e1b`,
  a second live 20-second follower `pod-failure` was polled once per second.
  Its first terminal observation was simultaneously `phase=Passed`,
  `cleanup.absent=true`, `EffectAndRecoveryProven`, with the same admitted Pod
  UID in both effect and recovery evidence.

## F-112: The capacity profile omitted the trusted active-probe containers

- Classification: attacknet profile and acceptance-evidence gap
- State: default corrected; clean live full-topology admission proven; fault
  effect and recovery proof pending
- Evidence: the corrected three-stage capacity run admitted and converged the
  complete 31-workload topology, but the retained actor Pods contained only
  the `actor` container. `capacity-preflight.sh` invoked `topology.mjs`
  without its opt-in `--probes=true`, even though NetworkChaos, DNSChaos,
  IOChaos, I/O-pressure, and TimeChaos require the independently controlled
  active probe for effect and recovery evidence.
- Impact: PodChaos remained independently provable from Kubernetes Pod state,
  but a data-plane campaign on the retained stage could only terminate
  Inconclusive. Hot-adding probes would also roll every actor after the clean
  capacity baseline, weakening the provenance of a final long soak.
- Correction and gate: capacity rendering now enables trusted probes by
  default and accepts explicit `ATTACKNET_PROBES` and
  `ATTACKNET_PROBE_IMAGE` inputs. The final 300+ block environment must admit
  the exact probe image from initial Pod creation and prove controlled
  before/during/after observations; the probe requirement is never weakened
  to make a campaign pass.
- Clean proof: `attacknet-final-soak` reached `Ready 31/31` with every actor
  Pod reporting `2/2` containers from its initial creation. The admitted probe
  image is `stacks-hacknet-probe:dev`; no actor was rolled or hot-patched to
  add it. This proves admission and readiness, but not yet the required
  before/during/after fault effect.
- Capacity evidence retained separately:
  `contrib/attacknet/evidence/capacity-current-20260815T2250Z/`.

## F-113: Legacy P2P startup convergence was highly lopsided before becoming dense

- Classification: startup-convergence latency and measurement gap; no
  permanent node failure established
- State: reproduced in three fresh full or scaled stages; all recovered
  without intervention; structured timing and laggard evidence captured
- Evidence: in the 2-miner/4-signer stage, `signer-node-2` served RPC and was
  chain-synchronized while `/v2/neighbors` reported zero live inbound and
  outbound conversations; its three configured bootstrap Services were all
  TCP-reachable. In the fresh full stage, `signer-node-1` showed the same zero
  state while every other sampled node already had 11--26 authenticated
  conversations. Each isolated companion later acquired an authenticated
  inbound conversation and rapidly converged to the dense cohort. Final full
  verification showed at least 28 authenticated conversations per node and
  no unauthenticated conversations.
- Clean reproduction: in `attacknet-final-soak`, `signer-node-9` remained at
  zero live inbound and outbound conversations for 595 seconds while serving
  RPC, staying chain-synchronized at burn height 222 / Stacks height 15, and
  retaining three reachable bootstrap endpoints. The peer database had
  already learned and recently contacted a broad frontier, yet `/v2/neighbors`
  still exposed no active conversation. It recovered at 595 seconds without
  a restart or configuration change; the post-activation 18-node gate then
  passed in two seconds.
- Boundary: configured `bootstrap` and `sample` rows do not prove a live
  connection; the API currently hard-codes their `authenticated` field to
  true. Only `inbound` and `outbound` were used by the gate. No Kubernetes
  DNS, Service endpoint, TCP reachability, process restart, or persistent
  isolation failure was found.
- Follow-up: `wait_live_peer_connectivity` now reports the zero-connection
  actor set every 30 seconds and records convergence duration plus per-actor
  live counts in the sealed run ledger. Repeat fresh runs before deciding
  whether this is expected randomized legacy-neighbor walking, an epoch-handoff
  delay, or a current-node reliability issue. A readiness timeout alone must
  not erase the distribution.
- Preserved evidence:
  `contrib/attacknet/evidence/final-soak-20260815T232258Z/startup-p2p-lag/`.

## F-114: A symlinked CLI fixture could make the peer-gate test pass on empty output

- Classification: attacknet regression-test false-positive
- State: fixed and covered
- Evidence: the startup-gate test symlinked `manifest-inventory.mjs` and
  `invariants.mjs` into its fake harness directory. Node canonicalized
  `import.meta.url` to the real module while retaining the symlink spelling in
  `process.argv[1]`, so the modules' CLI-entrypoint checks were false. They
  emitted nothing and exited zero. The former lifecycle gate trusted the exit
  status and returned success without parsing the invariant result.
- Impact: production lifecycle invocations used the real paths and did execute
  the helpers, but this test could not prove the claimed live-conversation
  gate. It was another instance of a check that could not fail.
- Correction: the lifecycle now requires a structured result containing rows
  and finite authenticated/unauthenticated extrema before recording success.
  The fixture copies the CLI modules and canonicalizes the macOS temporary
  directory path, so the actual CLI entry points execute. The test still
  forces one failed sample and proves a subsequent successful live-peer sample
  without triggering the lifecycle failure trap.

## F-115: I/O-pressure effect sampling raced the pressure process

- Classification: fault-effect evidence-window defect
- State: corrected, regression-tested, and proven by a clean live rerun
- Evidence: the first deterministic four-fault run passed Pod restart, network
  delay, and DNS-error campaigns, then truthfully paused because its final
  I/O-pressure campaign was `Inconclusive`. The controller-owned pressure Pod
  ran to completion on the exact admitted `follower-3` PVC and was removed
  cleanly. Its baseline FSYNC p95 was 0.861 ms, but the single sample taken as
  soon as Kubernetes first reported the pressure Pod `Running` was only 0.893
  ms. The first post-completion sample was 8.581 ms, demonstrating that the
  requested effect became observable after the prematurely captured `during`
  sample. This is an evidence-timing failure, not proof that the pressure
  process failed or that recovery succeeded.
- Impact: a real but delayed storage effect can be classified as absent, and a
  still-elevated filesystem can then make recovery inconclusive. In an
  agent-directed run this would discard a potentially causal fault from later
  replay or minimization.
- Correction and gate: while the bounded pressure Pod remains `Running`, every
  controller reconcile now obtains another trusted active-probe sample and
  retains only the highest p95 observation for the immutable actor and
  baseline. Higher p95 monotonically strengthens both configured effect
  clauses (latency multiplier and absolute added latency), while retaining one
  sample keeps CR status bounded. Recovery remains a separate bounded polling
  window and neither threshold is weakened. Regression coverage begins with a
  deliberately too-early active sample, proves a later sample replaces it,
  then requires both an initially elevated recovery sample and a subsequent
  recovered sample before the campaign passes.
- Live proof: immutable run-controller image
  `stacks-hacknet-run-operator:local-6905c2efe11800cd` reran the four-fault
  sequence without recreating any actor. Pod restart, 750 ms network delay,
  targeted DNS error, and I/O pressure all ended `EffectAndRecoveryProven`
  with confirmed cleanup absence; the parent run ended `SequenceCompleted`
  with four of four campaigns complete and zero inconclusive results. For the
  pressure campaign, baseline FSYNC p95 was 1.110 ms, the retained active p95
  was 7.890 ms (7.108x and +6.780 ms), and the recovery p95 was 2.199 ms
  (1.981x and +1.089 ms), satisfying the unchanged two-part effect and
  recovery contracts. The shared post-fault verifier then found zero burn or
  Stacks-height drift and one canonical tip across all 18 nodes at burn 250 /
  Stacks height 52.
- Preserved evidence: `FaultCampaign
  final-soak-v1-4-pressure-one-follower-pvc` and paused `AttacknetRun
  final-soak-v1` in the retained `attacknet-final-soak` environment, with the
  rendered schedule at
  `contrib/attacknet/evidence/final-soak-20260815T232258Z/fault-sequence.json`;
  passing v2 request, run, campaigns, and post-fault cohort evidence are under
  `contrib/attacknet/evidence/final-soak-20260815T232258Z/deterministic-faults-v2/`.

## F-116: Signalling PID 1 did not interrupt the burnchain clock's old cadence sleep

- Classification: cadence-control acknowledgment and responsiveness defect
- State: fixed, regression-tested, and proven with a live rolled clock
- Evidence: after the deterministic faults, policy generation 11 requested a
  change from 60-second to 10-second Bitcoin intervals. The ConfigMap and
  projected file both contained generation 11, but the controller process
  status remained at generation 10 until the old 60-second sleep naturally
  ended. `burnchain-policy.sh` therefore timed out after 30 seconds and
  correctly refused to emit `policy.changed`. At 00:06:53Z the old sleep ended,
  the clock logged generation 11, and subsequent blocks arrived every 10
  seconds. The signal had not provided the documented prompt wake-up.
- Root cause: Bash defers a trapped signal while synchronously waiting for an
  external foreground `sleep`. Sending `USR2` to the Bash PID 1 ran the no-op
  handler only after that child returned, so the policy acknowledgment latency
  was bounded by the *previous* cadence rather than the apply timeout.
- Impact: slowing, accelerating, pausing, or switching a burst at runtime can
  report a false control failure even though the generation applies later.
  More importantly, a requested pause can still allow the already-scheduled
  old interval to elapse before it is observed, making exact fault timing less
  controllable and confusing the causal ledger.
- Correction and gate: cadence sleeps now run as a tracked child under Bash's
  `wait` builtin. The `USR2` handler kills only that tracked sleep, causing an
  immediate loop boundary and policy reread; shutdown uses the same bounded
  cleanup. A regression test starts a nominal 60-second sleep, signals the
  parent, and requires it to return within two seconds. The timeout is not
  lengthened to hide the wake-up defect.
- Live proof: only the stateless `bitcoin-miner` clock Pod was rolled; the
  bitcoind Pod retained UID `2b0f20a8-91c4-42c9-8596-6a60c562edaa` and its
  uninterrupted chain. Generation 12 first established a 60-second interval.
  Generation 13 then changed it to 10 seconds and completed projection,
  signal, process reread, and acknowledgment in 5.7 seconds, inside the
  unchanged 30-second deadline and far short of the old interval.

## F-117: The trusted event schema had no phase for a long-running soak

- Classification: observability vocabulary and evidence-attribution gap
- State: fixed, regression-tested, and proven on the live bridge
- Evidence: the applied generation-12 cadence transition succeeded, but an
  event explicitly labelled `phase=soak` was rejected with HTTP 400 on all
  three authenticated writer attempts. The bridge's bounded phase set included
  setup, bootstrap, baseline, faults, verification, capture, incident, and
  teardown, but not the central long-running acceptance phase.
- Impact: a soak operator must either mislabel hours of observations as
  `baseline`/`verification` or lose their trusted timeline records. Both make
  human incident reconstruction and agent filtering less precise.
- Correction and gate: `soak` is now a first-class bounded phase, with an HTTP
  contract test proving an authenticated `policy.changed` event is accepted
  and persisted under that phase. The cadence script remained truthful: it
  warned about the journal failure but did not claim the observation failed or
  roll back the already-acknowledged policy.
- Live proof: the event ConfigMap and its checksum-bound Deployment were rolled
  without replacing the journal PVC. Generation 14 then applied the 10-second
  cadence and emitted `policy.changed` with `phase=soak` without a warning or
  retry failure; the clock status simultaneously reported generation 14 at
  burn height 297.

## F-118: Teardown discarded Loki's longer forensic log history

- Classification: forensic-evidence preservation defect
- State: corrected, regression-tested, and proven through destructive teardown
- Evidence: actor incident capture retained at most 20,000 lines per current or
  previous container, while Loki retained the longer Kubernetes log stream on
  its own PVC. Normal teardown exported the trusted event journal and run
  descriptor and then deleted that PVC without querying Loki. F-098 had already
  demonstrated that a single amplified warning could consume the bounded actor
  snapshot in under two hours, so the deleted source contained material causal
  history that the evidence bundle did not.
- Correction: a network-scoped exporter now records the exact LogQL selector,
  start/end nanoseconds, Loki build identity, admitted ConfigMap/StatefulSet/
  Service/Pod source objects, every page boundary, entry counts, compressed
  JSONL, and file digests. Pagination re-queries an inclusive nanosecond
  boundary and de-duplicates exact labelled entries; if a full page cannot
  advance (including an overfull identical timestamp) or the bounded page count
  is exhausted, it reports an incomplete export instead of skipping data.
  Normal teardown treats this export as mandatory and stops before deleting
  observability storage on failure. Lifecycle and incident capture retain the
  same evidence but do not destroy a running source when capture fails.
- Live proof: a read-only export from `attacknet-final-soak` queried Loki 3.5.3
  from the run's recorded creation time through burn height 347. It completed
  77 pages and retained 380,802 actor log entries without a pagination gap.
  The final teardown then exported 2,067 pages / 10,329,085 entries before its
  first destructive call, verified the gzip and metadata digests, finalized the
  run `passed`, deleted the owner and all actor/observability PVCs, and waited
  until the exact labeled resource set was empty. This closes both preservation
  and ordering rather than inferring them from a read-only capture.

## F-119: Full-run Loki export exhausted the host process heap

- Classification: forensic exporter scalability and bounded-resource defect
- State: corrected, regression-tested, and proven over the full teardown range
- Evidence: the first post-soak capture accumulated every flattened Loki entry
  in a JavaScript `Map`, then constructed a second sorted array and one giant
  JSON string. Node reached its approximately 4 GiB heap limit in
  `JsonStringify` and aborted. A first streaming correction proved the corpus
  itself was much larger than the earlier smoke: after 1,000 pages it had
  written 4,999,001 entries / 4.6 GiB and truthfully stopped at the configured
  page cap rather than claiming completeness. The incomplete bytes were
  removed after preserving the failure metadata.
- Impact: the mandatory teardown export would preserve Loki's PVC by aborting
  deletion, but could never complete for the long, high-cardinality runs it was
  introduced to protect. Repeated retries also consumed several GiB of host
  disk before compression.
- Correction: pagination now retains exact-entry hashes only for the inclusive
  boundary timestamp, streams each bounded page directly through gzip with
  backpressure, and never retains the complete corpus or an uncompressed file.
  An incomplete run keeps a clearly named `.partial` gzip plus metadata; the
  observability-disabled path now emits the same compressed-artifact/digest
  contract. Pagination and exact-deduplication semantics are unchanged.
- Live proof: the exact measured window from
  `2026-08-15T23:23:48.706Z` through `2026-08-16T00:49:39Z` completed 141
  pages and 701,338 entries. It streamed 773,175,267 uncompressed bytes into a
  39,341,951-byte gzip, recorded Loki 3.5.3 build identity and source objects,
  and passed every retained digest. Evidence is under
  `contrib/attacknet/evidence/final-soak-20260815T232258Z/post-soak-capture/loki/`.
- Replacement-soak proof: the corrected burn 503 -> 803 window exported
  591,594 entries / 663,134,029 uncompressed bytes in 119 pages to a
  35,634,893-byte gzip with zero malformed entries and verified digests. A
  streaming summary found no panic, OOM, ENOSPC, segmentation-fault, assertion,
  or stack-overflow family. The subsequent mandatory teardown streamed the
  complete run's 10,140,307,541 uncompressed bytes into a 368,876,029-byte gzip
  across 2,067 pages with bounded memory, marked the export complete, and
  passed all three retained digests before storage deletion.

## F-120: The nominal 300-block soak contract captured its first cohort 111 blocks late

- Classification: acceptance-evidence TOCTOU defect
- State: fixed, regression-tested, and replaced by a passing measured run
- Evidence: the ad-hoc monitor embedded `start_height=202` before it began its
  loop, and later wrote that value into `contract.json`. Its first timestamped
  Pod and cohort sample, at the same recorded monitor start time, observed burn
  height 313. The final sample was height 503. The directly monitored interval
  is therefore 190 new burn blocks, not the claimed 301, even though the fresh
  environment itself continuously traversed the omitted heights and the
  deterministic campaigns retained their own evidence at burn 250.
- Impact: subtracting a stale value from the final height can make an arbitrarily
  short observation window pass a long-soak gate. This is the same broad class
  of check-that-could-not-fail error that the attacknet is intended to prevent;
  indirect evidence that the chain happened to run is not a substitute for the
  requested continuously sampled acceptance window.
- Required correction: while the external Bitcoin clock is acknowledged
  paused, capture and validate the starting Bitcoin height and full canonical
  cohort in one bounded start phase, derive the target only from that admitted
  observation, then start cadence. The terminal result must cite the first and
  final sample heights and reject any mismatch with the contract. Run a new
  300-or-more-block window rather than reinterpreting this evidence as passing.
- Correction and live proof: `soak-runner.sh` now pauses first, requires exact
  Bitcoin/burn/Stacks agreement, derives the target from that observed height,
  samples the admitted baseline Pod UID set throughout the run, permits only an
  active campaign's exact target to be temporarily unavailable, pauses again,
  and rejects a terminal cohort that is not exact. The replacement run began
  at burn 503 / Stacks 302 and ended at burn 803 / Stacks 597, directly
  observing exactly 300 new burn blocks in 43 canonical cohort samples and 92
  Pod-health samples. Its deterministic four-campaign `AttacknetRun` ended
  `Passed`; every final actor agreed on the same tip. Evidence is under
  `contrib/attacknet/evidence/final-soak-20260815T232258Z/verified-soak-300/`.

## F-121: Cumulative signer counters can be misattributed to the measured soak window

- Classification: acceptance-evidence attribution trap
- State: fixed for future measured soaks; replacement evidence classified
- Evidence: the terminal signer-4 scrape contained one rejected companion
  validation. Read alone, it appeared to show that the 300-block soak exercised
  a genuine invalid-block path. The paused burn-503 baseline scrape already
  contained the same value; at burn 803 it was still one. All ten per-signer
  deltas were zero for rejected validations.
- Risk: cumulative Prometheus counters establish lifetime occurrence, not event
  time. A restart can also decrease a counter and make subtraction silently
  meaningless. Either mistake can turn an old event into a current acceptance
  failure or hide a truncated observation window.
- Correction: measured soaks now scrape every signer at both exact paused
  boundaries and emit `signer-metric-deltas.json`. The summarizer treats an
  uninstantiated labelled counter as zero, rejects capture-error markers,
  requires identical signer inventories, and fails closed on any decreasing
  counter. For the replacement window it records 3,259 proposals received,
  3,013 validation accepts, zero validation rejects, 2,932 accepted responses,
  and 246 policy rejections.

## F-122: Observer-enablement accepted stale Ready Pods while their replacement revision was rolling

- Classification: lifecycle/protocol-boundary ordering defect
- State: root-caused, corrected, regression-tested, and proven on a fresh live
  full-topology lifecycle
- Evidence: the mixed-version run applied the final companion observer configs
  while Bitcoin was paused at burn 220. The run ledger recorded the next burst
  at `08:34:05Z`, but several replacement companion Pods were not created until
  `08:34:30Z` through `08:34:34Z`. The lifecycle's foundation check accepted
  the old Ready Pods while the new StatefulSet template revision was still
  rolling. Those replacement processes therefore started after Bitcoin had
  already reached the burn-222 registration barrier. The truthful live-peer
  gate then waited 718 seconds before all 16 pre-activation nodes had a real
  authenticated conversation. The retained node logs begin by processing the
  reward-cycle boundary without a live peer path and include `Missing canonical
  anchor block`; this was not a slow Kubernetes scheduling event disguised as
  healthy protocol readiness.
- Root cause: the gate checked CR generation, aggregate replica counts, and Pod
  Ready state, but did not join each protocol-foundation actor to its
  StatefulSet `metadata.generation`, `status.observedGeneration`, updated
  replica, and matching current/update revisions. Pod readiness is not tied to
  the newly admitted template while the old Pod remains alive.
- Correction: `wait_bootstrap_foundation_ready` now requires the exact admitted
  StatefulSet revision for every foundation actor. After the final resource is
  applied, the lifecycle additionally proves authenticated connectivity for
  every pre-activation Stacks node while Bitcoin is still frozen at burn 220;
  the burn-222 check remains as a second barrier. Tests prove that an old Ready
  Pod with a stale revision is rejected and that the burn-220 transport proof
  precedes the registration burst. The next fresh lifecycle run must retain a
  passing `observer-height-live-peer-connectivity` assertion to close the live
  portion of this finding.
- Live acceptance: fresh run `attacknet-fresh-gate` held Bitcoin exactly at
  burn 220 after the final resource was admitted. During the rollout all ten
  companion StatefulSets were at generation 2 while their old Pods still
  reported Ready, with zero updated replicas and mismatched current/update
  revisions. The corrected gate did not advance. It waited for all exact
  revisions and then for every pre-activation Stacks node to have a live
  authenticated conversation. Only after that assertion passed did the clock
  advance to burn 222, where all ten signers registered and all ten companions
  exposed the `.miners` StackerDB. Activation at 223 then completed normally.
  The shared verifier subsequently found all 18 Stacks nodes at burn 224 /
  Stacks 20 on one tip with zero height drift, 27--33 authenticated live
  conversations per node, and zero unauthenticated conversations. The focused
  capture is retained at
  `contrib/attacknet/evidence/fresh-preactivation-gate-20260816/`.

## F-123: A current-main companion returned NotFound while validating across a fast burn transition

- Classification: transport-independent signer/node liveness-margin finding
- State: observed and bounded; node root cause and mainnet frequency remain open
- Evidence: during the deliberate three-second burn burst, signer 5 submitted
  proposal `1239fa548665be70944a0038c53458e62f63d249d8c3b6584149fef628358600`
  (height 26, burn 229) to its unmodified current-main companion. That companion
  had stored and advanced to the proposal's parent
  `101a2012d006ccbbd2227226f250959a94168082f489c1883c06e19820d017ff`
  at `08:50:42.323Z`. It processed burn sortition 229 at
  `08:50:45.262Z` through `.269Z`, received the proposal at `.340Z`, and the
  signer received `BlockValidateReject { reason: "Chainstate Error: Not found",
  reason_code: NotFoundError }` at `.386Z`. The same node stored the approved
  block at `.975Z` and advanced to it at `.987Z`; the complete cohort later
  converged.
- Impact: one healthy signer carrying 3/25 (12%) weight temporarily cast a
  validation rejection even though the proposal became canonical. In this run
  the remaining honest weight preserved liveness, but correlated occurrences
  would erode quorum margin. This is separate from the deliberately modified
  signer and was surfaced explicitly by the mixed-matrix classifier.
- Scope caution: a three-second regtest burn cadence deliberately compresses a
  coordination window that is normally much wider. This evidence proves a real
  current-main state-transition race under stress, not its production rate or
  security severity. A focused reproduction should identify the exact missing
  chainstate/sortition lookup and determine whether transient absence should be
  retried/unavailable rather than emitted as a validity verdict before filing
  a prescriptive fix.

## F-124: Immutable current, released, and deliberately modified actors interoperated under bounded adversity

- Classification: positive mixed-version/adversarial acceptance evidence
- State: passed and cryptographically attributed
- Evidence: the live 31-workload run joined every tested Pod UID and runtime
  image ID to its build record. `follower-5` ran exact release 4.0.2 source
  `1b57c3fb6709ab927f9179ab6814f874c84f5303`; `signer-1` ran the exact current
  source plus only the retained `reject-all` testing patch. Its weight was 1 of
  25, leaving 24 against an 18-weight threshold. Across the measured window,
  burn height advanced 227 to 248 and Stacks height 24 to 44. The modified
  signer rejected all 26 proposals it received and accepted none, while the
  nine healthy signers emitted 188 accepted responses. All 18 Stacks nodes,
  including the released follower, ended at the same burn height, Stacks
  height, and tip.
- Attribution: the backend-neutral classifier result is
  `contrib/attacknet/evidence/mixed-current-release-modified-20260816/matrix-proof/result.json`
  with digest
  `sha256:a9bc55bc71ce25e0917c081bd19a1b1535fc71e660b30268e507f4d759fdddeb`.
  The assertion is present in both the sealed-input run ledger and the
  authenticated event journal. F-123 records the one independent healthy-node
  validation rejection instead of hiding it inside this positive result.

## F-125: A simultaneous ten-companion rollout had a six-minute live-peer recovery tail

- Classification: measured lifecycle/recovery performance observation
- State: reproduced on a fresh full topology; safety gate worked; precise
  legacy-P2P retry cause remains open
- Trigger: enabling the ten final companion observer configurations at burn
  220 replaced all ten companion Pods while Bitcoin was deliberately paused.
  Kubernetes converged every StatefulSet to its exact update revision quickly,
  but five new companions initially reported zero active inbound and outbound
  conversations. Their configured bootstrap endpoints were DNS-correct and
  directly TCP-reachable, and `private_neighbors = true` plus the effective
  Pod IP were present in the runtime config.
- Evidence: the lagging set fell from five actors at 3 seconds, to three at
  130 seconds, and to one at 193 seconds. The final node acquired authenticated
  peers after 366 seconds. During the early interval all three common
  bootstrap nodes had twelve inbound conversations; that observation is
  consistent with connection contention or retry backoff but does not prove a
  hard twelve-peer ceiling. By release time the final companion had 15
  authenticated connections and the post-activation cohort had 27--33 each.
- Impact: the former lifecycle would have hidden this recovery tail by
  advancing the protocol while some companions had no transport path. The new
  gate preserves correctness, but a six-minute pause makes simultaneous
  rollout recovery operationally expensive and could exhaust a shorter
  deployment timeout. It also shows why Pod Ready and configured bootstrap
  records cannot substitute for active `inbound`/`outbound` evidence.
- Follow-up: retain the measured convergence duration as a baseline; classify
  connection attempts/rejections/backoff directly before changing topology or
  connection limits. A distributed deterministic bootstrap list may be worth
  testing as a counterfactual, but should not be asserted as the fix without
  that evidence. The run ledger's
  `observer-height-live-peer-connectivity` assertion records the exact rows and
  366-second convergence window in the F-122 evidence bundle.

## F-126: The shared cohort assertion detects a Ready actor with a partitioned Bitcoin view

- Classification: deliberate assertion negative control and clean recovery
- State: Kubernetes half proven live; the equivalent Compose control remains
  required before backend parity is complete
- Setup: controller-admitted campaign `fresh-gate-burn-drift-negative`
  selected exact Ready Pod `attacknet-fresh-gate-follower-5-0`, UID
  `e4733ed5-d348-4f0b-b716-a20972abb682`, and partitioned it bidirectionally
  only from the enrolled `bitcoin` actor for 90 seconds. Admission charged
  zero signer/miner weight. Chaos Mesh recorded one successful injection for
  each side of the pair; the trusted active probe changed from five successful
  Bitcoin-P2P attempts before injection to zero of five during it.
- Negative result: with Bitcoin deliberately accelerated to five-second
  cadence, every Pod remained Ready and all Stacks nodes retained authenticated
  P2P conversations. The unchanged backend-neutral verifier nevertheless
  returned `ok=false`: the healthy cohort had reached burn 237 / Stacks 32--33
  while `follower-5` remained at burn 232 / Stacks 28, producing reason-coded
  `burnDrift=5` and `stacksDrift=5`. It reported no equal-height fork. This
  proves readiness and internal P2P cannot mask a stale burnchain view.
- Recovery: the run controller independently classified
  `NetworkDegraded=Proven` and `NetworkRecovered=Proven`, observed normal
  `AllRecovered`, deleted the exact NetworkChaos resource, and released the
  mutation lease. After cadence paused, the same verifier passed with all 18
  nodes at burn 253, Stacks drift one, one tip at each observed height, 28--33
  authenticated conversations per node, and zero unauthenticated
  conversations. The focused bundle is retained at
  `contrib/attacknet/evidence/burn-drift-negative-control-20260816/`.
- Follow-up: run the identical logical control through the Compose adapter and
  retain the same fail/recover reason contract. Do not substitute container
  pause for the burn-view partition: that would only re-prove actor readiness,
  which already has paired evidence.

## F-127: Isolating all miners from non-miner Stacks peers made miner-local RPC temporarily unobservable

- Classification: node liveness/observability stress finding plus harness
  diagnostic defect
- State: reproduced and recovered; precise node-versus-fault-mechanism cause
  remains open; silent verifier failure corrected and regression-tested
- Trigger: a bounded NetworkChaos partition selected all three miners and all
  ten companions plus five followers as the opposite side. Bitcoin remained
  reachable and all miner Pods stayed `2/2 Ready`. The controller proved the
  partition independently for each exact miner UID. A first attempt was
  intentionally non-probative because cadence was paused; the global mutation
  lease correctly prevented cadence from changing underneath the active
  fault. Retry `fresh-gate-stacks-stall-negative-r2` started five-second
  cadence before injection.
- Observation: during the retry, a TCP connection to each miner's local
  `127.0.0.1:20443` succeeded, but `/v2/info` produced no response within the
  three-second direct bound and then exceeded the shared verifier's ten-second
  bound. The Pods remained Ready. Miner logs show a dense interval of failed
  StackerDB sends, dead-peer drops, and connection re-admission while the
  partition was active. Unaffected followers and companions continued to
  report a common view (sampled at burn 275 / Stacks 53), but the absence of a
  timestamped cohort at injection prevents claiming an exact no-progress
  interval from that sample alone.
- Impact: the shared progress verifier correctly did not report a pass, but
  its command substitution previously exited under `set -e` without naming
  the failed actor or endpoint. `verify.sh` now emits bounded diagnostics such
  as `miner-1 /v2/info probe failed within 10s`; a fake-backend regression test
  proves the attribution and ensures the invariant evaluator is never called
  with missing evidence. A Kubernetes-Ready miner whose RPC loop is
  unobservable remains a useful liveness signal independent of whether Stacks
  block production also stalls.
- Recovery: Chaos Mesh reported normal recovery for both sides of every
  selected relationship, the controller classified all three
  `NetworkRecovered` assertions Proven, removed the exact resource, and
  released the lease. After cadence paused, all miner RPC endpoints responded
  and all 18 nodes converged exactly at burn 279 / Stacks 57 on one tip with
  zero drift. The bounded evidence is retained at
  `contrib/attacknet/evidence/miner-partition-observability-20260816/`.
- Follow-up: repeat with progressively smaller target sets and capture native
  RPC latency plus P2P queue/socket gauges to distinguish ordinary bounded
  connection teardown, node event-loop starvation, and a Chaos Mesh rule
  interaction. Do not file this as a current-main defect until that boundary
  is classified, and do not count it as the still-missing clean
  canonical-tip-stall negative control.

## F-128: The shared progress assertion detects canonical Stacks stalling while Bitcoin advances

- Classification: deliberate assertion negative control and clean recovery
- State: Kubernetes half proven live; equivalent Compose control remains
  required for backend parity
- Setup: controller-admitted campaign
  `fresh-gate-signer-partition-stall-negative` selected all ten exact signer
  Pod UIDs and partitioned them bidirectionally from their ten enrolled
  companion nodes for 90 seconds. Five active network probes per signer changed
  from all successful before injection to zero successful during it. The
  controller independently classified `NetworkDegraded=Proven` for every
  target. Bitcoin cadence was acknowledged at five seconds before injection,
  so the global mutation lease did not permit an unrecorded policy change
  during the fault.
- Negative result: all node RPC probes remained responsive. Over the unchanged
  backend-neutral verifier's 20-second window Bitcoin advanced from 287 to 291
  while every Stacks node remained at height 60 on tip
  `9ce4f0a22fd9410e081d64e8c0e27974a650df2b602b8d5e8ca136ff0e5d02ac`.
  The verifier returned `ok=false` with the explicit reason `Stacks delta 0 <
  1`; it did not confuse burn progress, Pod readiness, or continued legacy-P2P
  connectivity with canonical Stacks progress.
- Recovery: Chaos Mesh reported normal `AllRecovered`, the exact
  `NetworkChaos` resource was absent, and the controller classified
  `NetworkRecovered=Proven` for all ten UIDs. After the cadence was paused, the
  same verifier passed with all 18 nodes exactly at burn 304 / Stacks 61 on one
  tip, zero height drift, 28--33 authenticated conversations per node, and no
  unauthenticated conversations. The focused capture is retained at
  `contrib/attacknet/evidence/signer-partition-stall-negative-control-20260816/`.
- Follow-up: execute the same logical signer-to-companion partition through the
  Compose adapter and require the identical fail/recover reason contract. F-129
  records the additional companion burn-view behavior exposed by this control.

## F-129: Default blocking event delivery lets an unavailable signer stall its companion node

- Classification: transport-independent liveness coupling and configuration
  safety finding
- State: deterministically reproduced on current main; recovery proven;
  production configuration guidance and desired default require review
- Evidence: before the signer partition, `signer-node-1` processed burn 283.
  Beginning at `09:46:55.952Z`, its event-dispatcher worker timed out delivering
  the burn event to `signer-1` and retried indefinitely with backoff capped at
  three seconds. It downloaded or processed no later burn block during the
  partition even though ordinary followers reached burn 292 and miners reached
  291 in the verifier sample. Immediately after network recovery at
  `09:48:29Z`, it resumed from 283 and processed the accumulated burn blocks in
  order. The other nine companion nodes showed the same 8--10-block lag, and
  the full cohort later converged exactly at burn 304.
- Mechanism: this is explicit current-main behavior, not a Kubernetes or
  libp2p artifact. `NodeConfig::event_dispatcher_blocking` defaults to `true`;
  `effective_event_dispatcher_queue_size()` therefore returns zero. The event
  worker's `initiate_send()` waits for successful completion, while HTTP
  delivery retries without a terminal bound. The configuration documentation
  itself warns that a slow observer can stall the node. In this topology the
  observer is the companion's signer process, so signer unavailability also
  freezes the otherwise healthy Stacks node's burn view.
- Risk: operators commonly colocate a signer with its companion and may expect
  signer failure to remove only that signer's vote. With the default, a dead,
  partitioned, or indefinitely slow signer also prevents its node from tracking
  Bitcoin and serving a fresh chain view. Correlated signer endpoint failures
  therefore create correlated companion lag and a larger recovery backlog.
- Required follow-up: evaluate `event_dispatcher_blocking=false` with the
  persisted bounded queue as the recommended signer-companion configuration,
  including queue-full, restart, ordering, and stale-signer behavior. Preserve
  blocking mode as an explicit scenario knob so the attacknet can reproduce
  the production default. Add metrics for pending event payloads, oldest age,
  retry count, and effective blocking state; without them a Ready node silently
  freezes. Do not silently change the production default until delivery
  ordering and backlog safety have been reviewed.

## F-130: A substituted stacker image could run the wrong process while reporting Ready

- Classification: attacknet apparatus contract and fail-fast finding
- State: reproduced during a preserved bootstrap failure; corrected and
  regression-tested before retry
- Trigger: a small telemetry-control render mistakenly set both
  `--node-image` and `--stacker-image` to the Stacks node image. The stacker
  actor inherited that image's default entrypoint, started `stacks-node`, and
  passed its former readiness probe because `/proc/1/status` existed. It never
  wrote `/tmp/attacknet-stacker-status.json` or submitted PoX-4 enrollment, so
  the lifecycle's independent cutoff gate stopped the run at burn 215 and
  preserved its bootstrap-failure bundle.
- Impact: the consensus fixture gate prevented a false healthy network, but
  the weak actor contract consumed the complete enrollment window before
  identifying a deterministic configuration error. The same shape could hide
  a malformed custom stacker image behind Kubernetes Ready.
- Correction: the rendered stacker actor now executes the explicit bounded
  contract `npx tsx /stacker/stacking.ts` instead of inheriting an image
  entrypoint, and readiness requires a non-empty stacker-owned status file.
  A wrong image therefore fails immediately. CLI help now distinguishes the
  dedicated stacker-client image and names its default. A behavioral topology
  test pins both the command and status readiness contract.
- Scope: this was an attacknet invocation/configuration error, not a Stacks
  node or signer defect. The retained failure is still valuable evidence that
  the independent PoX enrollment gate cannot be bypassed by Pod readiness.

## F-131: Enrolled telemetry loss is detected and attributed independently of actor readiness

- Classification: deliberate observability negative control and clean recovery
- State: Kubernetes live proof complete; Compose counterpart remains part of
  the backend-parity gate
- Setup: a fresh current-main network enrolled exactly four protocol actors.
  The new backend-neutral telemetry invariant first proved one fresh
  `up=1` series with the correct server-attached role for every manifest actor.
  Controller-admitted campaign `telemetry-prometheus-partition` then selected
  exact Ready `follower-1` Pod UID
  `02d7d141-f2a3-49b2-ab8b-d4e625fdfc8f` and used the bounded
  `harnessTarget: prometheus` contract. The compiler converted that name to
  the exact network-scoped Prometheus labels; no raw address or arbitrary
  selector was admitted.
- Negative result: Chaos Mesh recorded successful rules on both the follower
  and Prometheus Pod. The trusted active probe changed from 5/5 successful
  attempts before injection to 0/5 during it. At the same time, the telemetry
  invariant still observed all four attributable series but returned
  `ok=false` and exit 1 because only `follower-1` was fresh with `up=0`,
  reason-coded `scrape-down`. Actor/Kubernetes readiness was not used to excuse
  the missing telemetry path.
- Recovery: the run controller classified `NetworkDegraded=Proven` and
  `NetworkRecovered=Proven`, observed normal `AllRecovered`, deleted the exact
  NetworkChaos resource, and released the mutation lease. The same unchanged
  telemetry assertion then passed with 4/4 actors, correct roles, `up=1`, and
  sample age below 0.05 seconds. The focused admitted-state, orchestration,
  timeline, and Loki bundle is retained at
  `contrib/attacknet/evidence/telemetry-negative-control-20260816/`.
- Operational result: a flat or empty Grafana panel can now be distinguished
  from a healthy-but-idle chain and from an actor-specific scrape failure by a
  machine-readable invariant. The Prometheus harness target remains a narrow
  controller-owned exception rather than a general NetworkChaos escape hatch.

## F-132: DNSChaos isolates an enrolled service lookup without poisoning the control resolver path

- Classification: positive live DNS fault and recovery evidence
- State: passed on the local arm64 three-node kind cluster
- Setup: controller-admitted campaign `dns-enrolled-peer-error` targeted the
  exact Ready `follower-1` Pod and both its actor and trusted-probe containers.
  The only fault pattern was the enrolled miner service FQDN; admission charged
  zero signer and miner unavailability. Chaos Mesh recorded successful
  injection in both named containers.
- Effect: before injection, the trusted probe resolved the miner service to
  `10.244.1.47` and independently resolved
  `kubernetes.default.svc.cluster.local` to `10.96.0.1`. During injection the
  selected query failed with no answers while the Kubernetes control query
  continued to succeed with the same answer. The controller therefore
  classified `DNSDegraded=Proven` instead of treating `AllInjected` alone as
  proof.
- Recovery: after the 45-second fault, the selected service resolved again to
  its original answer, the control remained healthy, Chaos Mesh reported
  normal recovery, and the exact DNSChaos resource was absent. The controller
  classified `DNSRecovered=Proven` and the campaign Passed. The focused bundle
  is retained at `contrib/attacknet/evidence/dns-chaos-canary-20260816/`.
- Scope: this proves the DNS fault/evidence machinery and its trust boundary;
  it is not itself evidence of a Stacks defect. Longer scenarios should combine
  DNS disruption with connection churn because established P2P connections do
  not require repeated DNS resolution.

Each capacity stage, negative control, fault campaign, mixed-version run, and
long soak must append findings here before its evidence is summarized. A clean
run is also evidence and should record the invariant and observation window.
