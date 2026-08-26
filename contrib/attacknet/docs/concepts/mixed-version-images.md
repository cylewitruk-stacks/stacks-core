# Mixed-version Attacknet images

`StacksNetwork` can assign a distinct image to every actor. Building an image
does not prove which bytes a Pod ran: acceptance evidence must join the source
revision and build result to the admitted actor, Pod UID, and runtime image ID.

## Build exact revisions

Use one clean worktree per revision or deliberate modification. Build the
Stacks image with the same Attacknet Dockerfile from that worktree:

```bash
git worktree add /tmp/stacks-release RELEASE_GIT_REF

(cd contrib/helm/hacknet/operator && go build -o /tmp/attacknet ./cmd/attacknet)
/tmp/attacknet image build --repo-root /tmp/stacks-release --stacks
```

Record the exact 40-character revision, dirty patch or untracked-content
digest, Dockerfile digest, build invocation, platform, resulting local image
ID, and any emulation. Rename or content-tag each result before building the
next revision; mutable convenience tags are transport names, not identities.

Load the selected images into every kind node and retain the load receipt:

```bash
/tmp/attacknet image load --mode require IMAGE...
```

For a registry-backed cluster, use immutable digest references. Local kind can
use content-derived local tags with `IfNotPresent`, but evidence must still
verify the CRI runtime image ID.

## Declare the matrix

Human-authored `StacksNetwork` YAML assigns the requested image per actor.
Machine-oriented matrix inputs live under [`../../examples/matrices/`](../../examples/matrices/).
The API server and topology controller then report the admitted identities in
`StacksNetwork.status`.

Do not infer a successful matrix from tags. For each actor, require:

1. the expected source/build record;
2. the declared image on the observed `StacksNetwork` generation;
3. a Ready actor Pod with the admitted Pod UID;
4. the runtime image ID from `containerStatuses`; and
5. cohort and protocol assertions appropriate to that version combination.

The outer OCI index digest, selected platform manifest, and runtime config
digest may differ. Evidence must record which identity it compares rather than
assuming equality.

## Deliberately modified actors

Modified actors are separate, provenance-bound images. Production images must
not contain runtime adversary switches. Compile test-only directives only in a
dedicated worktree and image, then assign that image to a bounded actor. See
[`adversarial-actors.md`](adversarial-actors.md).

Historical v1alpha1 build-planner evidence remains bound to its reviewed Git
revision and evidence archive. Its Node command surface is not shipped or
supported as a current workflow.
