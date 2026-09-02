package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/document"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzcorpus"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzplan"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/fuzzsession"
)

func (app *App) runFuzz(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet fuzz plan|run|resume|status|lock|lease ...")
	}
	switch args[0] {
	case "plan":
		return app.runFuzzPlan(ctx, args[1:])
	case "status":
		return app.runFuzzStatus(args[1:])
	case "run":
		return app.runFuzzRun(ctx, args[1:])
	case "resume":
		return app.runFuzzResume(ctx, args[1:])
	case "lock":
		return app.runFuzzLock(args[1:])
	case "lease":
		return app.runFuzzLease(ctx, args[1:])
	default:
		return usageError("usage: attacknet fuzz plan|run|resume|status|lock|lease ...")
	}
}

func (app *App) runFuzzLock(args []string) error {
	if len(args) == 0 || (args[0] != "status" && args[0] != "break") {
		return usageError("usage: attacknet fuzz lock status|break --corpus DIR ...")
	}
	flags := newFlagSet("fuzz lock "+args[0], app.Stderr)
	root := flags.String("corpus", "", "existing corpus root")
	owner := flags.String("expected-owner", "", "exact stale lock owner")
	processID := flags.Int("expected-process-id", 0, "exact stale process ID")
	acquiredAt := flags.String("expected-acquired-at", "", "exact RFC3339Nano acquisition time")
	reason := flags.String("reason", "", "bounded operator reason")
	if err := flags.Parse(args[1:]); err != nil {
		return commandUsageError{err.Error()}
	}
	if *root == "" || flags.NArg() != 0 {
		return usageError("--corpus DIR is required")
	}
	store, err := fuzzcorpus.OpenExisting(*root, app.Now)
	if err != nil {
		return err
	}
	if args[0] == "status" {
		if *owner != "" || *processID != 0 || *acquiredAt != "" || *reason != "" {
			return usageError("status accepts only --corpus DIR")
		}
		record, err := store.LockRecord()
		if err != nil {
			return err
		}
		return writeJSON(app.Stdout, record)
	}
	when, err := time.Parse(time.RFC3339Nano, *acquiredAt)
	if err != nil || *owner == "" || *processID < 1 || *reason == "" || len(*reason) > 512 {
		return usageError("break requires exact --expected-owner, --expected-process-id, --expected-acquired-at, and --reason")
	}
	record := fuzzcorpus.LockRecord{
		SchemaVersion: "stacks-attacknet-corpus-lock/v1", Owner: *owner,
		ProcessID: *processID, AcquiredAt: when,
	}
	if err := store.BreakLock(record, *reason); err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{
		"schemaVersion": "stacks-attacknet-lock-break-result/v1",
		"broken":        record, "reason": *reason,
	})
}

func (app *App) runFuzzLease(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "status" && args[0] != "break") {
		return usageError("usage: attacknet fuzz lease status|break --corpus DIR ...")
	}
	flags := newFlagSet("fuzz lease "+args[0], app.Stderr)
	root := flags.String("corpus", "", "existing corpus root used for audit receipts")
	namespace := flags.String("namespace", app.DefaultNamespace, "namespace containing the session Lease")
	uid := flags.String("expected-uid", "", "exact stale Lease UID")
	resourceVersion := flags.String("expected-resource-version", "", "exact stale Lease resourceVersion")
	holder := flags.String("expected-holder", "", "exact stale Lease holder")
	reason := flags.String("reason", "", "bounded operator reason")
	if err := flags.Parse(args[1:]); err != nil {
		return commandUsageError{err.Error()}
	}
	if *root == "" || len(kubevalidation.IsDNS1123Label(*namespace)) != 0 || flags.NArg() != 0 {
		return usageError("--corpus DIR and a valid --namespace are required")
	}
	if app.FuzzRuntimeFactory == nil {
		return errors.New("fuzz runtime is unavailable")
	}
	runtimeBoundary, err := app.FuzzRuntimeFactory(*root, *namespace)
	if err != nil {
		return err
	}
	admin, ok := runtimeBoundary.(FuzzLeaseAdmin)
	if !ok {
		return errors.New("fuzz runtime does not support Lease administration")
	}
	if args[0] == "status" {
		if *uid != "" || *resourceVersion != "" || *holder != "" || *reason != "" {
			return usageError("status accepts only --corpus DIR")
		}
		identity, currentHolder, err := admin.SessionLease(ctx)
		if err != nil {
			return err
		}
		return writeJSON(app.Stdout, map[string]any{
			"schemaVersion": "stacks-attacknet-session-lease-status/v1",
			"lease":         identity, "holder": currentHolder,
		})
	}
	if *uid == "" || *resourceVersion == "" || *holder == "" || *reason == "" || len(*reason) > 512 {
		return usageError("break requires exact --expected-uid, --expected-resource-version, --expected-holder, and --reason")
	}
	identity := fuzzcorpus.ResourceIdentity{
		APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Namespace: *namespace, Name: "attacknet-fuzz-session",
		UID: *uid, ResourceVersion: *resourceVersion,
	}
	if err := admin.BreakSession(ctx, identity, *holder, *reason); err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{
		"schemaVersion": "stacks-attacknet-session-lease-break-result/v1",
		"lease":         identity, "holder": *holder, "reason": *reason,
	})
}

func (app *App) runFuzzRun(ctx context.Context, args []string) error {
	flags := newFlagSet("fuzz run", app.Stderr)
	descriptorPath := flags.String("descriptor", "", "immutable session descriptor JSON path")
	corpusRoot := flags.String("corpus", "", "initialized or new corpus root")
	dryRun := flags.Bool("dry-run", false, "render deterministic resources without mutation")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *descriptorPath == "" || *corpusRoot == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet fuzz run --descriptor SESSION.json --corpus DIR")
	}
	descriptor, err := readFuzzDescriptor(*descriptorPath)
	if err != nil {
		return err
	}
	if *dryRun {
		return app.writeFuzzDryRun(descriptor, "session", "", 0, "")
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	if err := validateFuzzDescriptorSources(ctx, backend, descriptor); err != nil {
		return err
	}
	return app.executeFuzzSession(ctx, descriptor, *corpusRoot)
}

func (app *App) runFuzzResume(ctx context.Context, args []string) error {
	flags := newFlagSet("fuzz resume", app.Stderr)
	session := flags.String("session", "", "session SHA-256 digest")
	corpusRoot := flags.String("corpus", "", "existing corpus root")
	dryRun := flags.Bool("dry-run", false, "render deterministic resources without mutation")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *session == "" || *corpusRoot == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet fuzz resume --session DIGEST --corpus DIR")
	}
	store, err := fuzzcorpus.OpenExisting(*corpusRoot, app.Now)
	if err != nil {
		return err
	}
	journal, err := store.OpenJournal(*session)
	if err != nil {
		return err
	}
	descriptorReferences := []fuzzcorpus.ObjectReference{}
	for _, record := range journal.Records() {
		if record.Kind != "SessionPlanned" {
			continue
		}
		for _, reference := range record.Artifacts {
			if reference.Name == "session-descriptor" {
				descriptorReferences = append(descriptorReferences, reference)
			}
		}
	}
	descriptorReference, err := uniqueNamedReference(
		descriptorReferences, "session-descriptor", "session journal",
	)
	if err != nil {
		return err
	}
	data, err := store.ReadObject(descriptorReference)
	if err != nil {
		return err
	}
	var descriptor fuzzplan.Descriptor
	if err := document.DecodeOne(data, &descriptor); err != nil {
		return err
	}
	if descriptor.Digest != *session {
		return errors.New("session descriptor differs from requested digest")
	}
	if *dryRun {
		return app.writeFuzzDryRun(descriptor, "resume", "", 0, "")
	}
	return app.executeFuzzSessionWithStore(ctx, descriptor, store, *corpusRoot)
}

func uniqueNamedReference(
	references []fuzzcorpus.ObjectReference, name, owner string,
) (fuzzcorpus.ObjectReference, error) {
	matches := make([]fuzzcorpus.ObjectReference, 0, 1)
	for _, reference := range references {
		if reference.Name == name {
			matches = append(matches, reference)
		}
	}
	if len(matches) != 1 {
		return fuzzcorpus.ObjectReference{}, fmt.Errorf(
			"%s must contain exactly one %s artifact; found %d", owner, name, len(matches),
		)
	}
	return matches[0], nil
}

func (app *App) executeFuzzSession(ctx context.Context, descriptor fuzzplan.Descriptor, corpusRoot string) error {
	store, err := fuzzcorpus.Open(corpusRoot, descriptor.Corpus.MaximumBytes, app.Now)
	if err != nil {
		return err
	}
	return app.executeFuzzSessionWithStore(ctx, descriptor, store, corpusRoot)
}

func (app *App) executeFuzzSessionWithStore(ctx context.Context, descriptor fuzzplan.Descriptor, store *fuzzcorpus.Store, corpusRoot string) error {
	if app.FuzzRuntimeFactory == nil {
		return errors.New("fuzz runtime is unavailable")
	}
	runtime, err := app.FuzzRuntimeFactory(corpusRoot, descriptor.Network.Template.Namespace)
	if err != nil {
		return err
	}
	engine := fuzzsession.Engine{Runtime: runtime, Store: store, Now: app.Now}
	if err := engine.Run(ctx, descriptor); err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{
		"schemaVersion": "stacks-attacknet-fuzz-run-result/v1",
		"sessionDigest": descriptor.Digest, "phase": "Complete",
	})
}

func (app *App) runFuzzPlan(ctx context.Context, args []string) error {
	flags := newFlagSet("fuzz plan", app.Stderr)
	file := flags.String("file", "", "strict fuzz-plan YAML path")
	output := flags.String("output", "", "immutable session descriptor JSON path, or -")
	namespace := flags.String("namespace", app.DefaultNamespace, "template namespace")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *file == "" || *output == "" || flags.NArg() != 0 {
		return usageError("usage: attacknet fuzz plan --file PLAN.yaml --output SESSION.json [--namespace NS]")
	}
	planBytes, err := app.readInput(*file)
	if err != nil {
		return err
	}
	var plan fuzzplan.Plan
	if err := document.DecodeOne(planBytes, &plan); err != nil {
		return fmt.Errorf("decode fuzz plan: %w", err)
	}
	if err := fuzzplan.ValidatePlan(plan); err != nil {
		return fmt.Errorf("validate fuzz plan: %w", err)
	}
	base := filepath.Dir(*file)
	networkBytes, err := readPlanFile(base, plan.Network.TemplateFile)
	if err != nil {
		return fmt.Errorf("read network template: %w", err)
	}
	networkObject, networkKind, err := DecodeSubmission(networkBytes, *namespace)
	if err != nil {
		return fmt.Errorf("decode network template: %w", err)
	}
	if networkKind.Name != "StacksNetwork" {
		return errors.New("network.templateFile must contain a StacksNetwork")
	}
	var network attacknetv1beta1.StacksNetwork
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(networkObject.Object, &network); err != nil {
		return err
	}
	networkDigest, err := fuzzplan.NetworkTemplateDigest(network)
	if err != nil {
		return err
	}
	planDigest, err := fuzzplan.PlanDigest(plan)
	if err != nil {
		return err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	policies, err := resolveFuzzPolicies(ctx, backend, &network)
	if err != nil {
		return err
	}
	resolved := make([]fuzzplan.ResolvedTemplate, 0, len(plan.Templates))
	for _, template := range plan.Templates {
		kind, err := LookupKind(template.Kind)
		if err != nil {
			return err
		}
		object, err := backend.Get(ctx, ResourceRef{
			Kind: kind, Namespace: *namespace, Name: template.Name,
		})
		if err != nil {
			return fmt.Errorf("resolve template %s: %w", template.ID, err)
		}
		item, err := resolvedFuzzTemplate(template, object.Object)
		if err != nil {
			return err
		}
		resolved = append(resolved, item)
	}
	advisories := make([]fuzzplan.AdvisoryArtifact, 0, len(plan.Advisories))
	for _, source := range plan.Advisories {
		data, err := readPlanFile(base, source.File)
		if err != nil {
			return fmt.Errorf("read advisory for trial %d: %w", source.TrialOrdinal, err)
		}
		var advisory fuzzplan.AdvisoryArtifact
		if err := document.DecodeOne(data, &advisory); err != nil {
			return fmt.Errorf("decode advisory for trial %d: %w", source.TrialOrdinal, err)
		}
		if advisory.TrialOrdinal != source.TrialOrdinal {
			return fmt.Errorf("advisory trial %d differs from plan trial %d", advisory.TrialOrdinal, source.TrialOrdinal)
		}
		providedDigest := advisory.Digest
		sealed, err := fuzzplan.SealAdvisory(advisory)
		if err != nil {
			return err
		}
		if providedDigest != "" && providedDigest != sealed.Digest {
			return fmt.Errorf("advisory for trial %d digest mismatch", source.TrialOrdinal)
		}
		advisories = append(advisories, sealed)
	}
	descriptor, err := fuzzplan.Compile(fuzzplan.ResolvedInput{
		Plan: plan, PlanDigest: planDigest,
		Network: fuzzplan.ResolvedNetwork{
			TemplateDigest: networkDigest, Template: network, Policies: policies,
		},
		Templates: resolved, Advisories: advisories,
	})
	if err != nil {
		return fmt.Errorf("compile fuzz session: %w", err)
	}
	if *output == "-" {
		return writeJSON(app.Stdout, descriptor)
	}
	if err := writePrivateJSON(*output, descriptor); err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{
		"schemaVersion": fuzzplan.DescriptorSchema,
		"sessionDigest": descriptor.Digest, "descriptor": *output,
		"trials": len(descriptor.Trials), "mutatedCluster": false,
	})
}

func resolveFuzzPolicies(
	ctx context.Context, backend Backend, network *attacknetv1beta1.StacksNetwork,
) ([]fuzzplan.ResolvedPolicy, error) {
	bindings := make(map[string]string, len(network.Spec.Burnchain.Nodes))
	for _, node := range network.Spec.Burnchain.Nodes {
		name := network.Spec.Burnchain.PolicyRef.Name
		if node.PolicyRef != nil {
			name = node.PolicyRef.Name
		}
		if name == "" || node.Name == "" {
			return nil, errors.New("network contains an incomplete burnchain policy reference")
		}
		if prior, duplicate := bindings[name]; duplicate && prior != node.Name {
			return nil, fmt.Errorf("burnchain policy %s is shared by Bitcoin nodes %s and %s", name, prior, node.Name)
		}
		bindings[name] = node.Name
	}
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	kind, err := LookupKind("BurnchainPolicy")
	if err != nil {
		return nil, err
	}
	resolved := make([]fuzzplan.ResolvedPolicy, 0, len(names))
	for _, name := range names {
		object, err := backend.Get(ctx, ResourceRef{Kind: kind, Namespace: network.Namespace, Name: name})
		if err != nil {
			return nil, fmt.Errorf("resolve burnchain policy %s: %w", name, err)
		}
		var policy attacknetv1beta1.BurnchainPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &policy); err != nil {
			return nil, fmt.Errorf("decode burnchain policy %s: %w", name, err)
		}
		digest, err := canonical.ArtifactDigest(policy.Spec)
		if err != nil {
			return nil, err
		}
		if policy.UID == "" || policy.Generation < 1 ||
			policy.Spec.NetworkRef != network.Name || policy.Spec.BitcoinNodeRef != bindings[name] ||
			policy.Spec.Flash != nil {
			return nil, fmt.Errorf("burnchain policy %s does not bind the selected source network and Bitcoin node", name)
		}
		resolved = append(resolved, fuzzplan.ResolvedPolicy{
			Name: name, Namespace: network.Namespace, UID: string(policy.UID),
			Generation: policy.Generation, SpecDigest: digest, Spec: policy.Spec,
		})
	}
	return resolved, nil
}

// validateFuzzDescriptorSources rechecks Kubernetes-backed planning inputs
// before an initial session is allowed to mutate the cluster. Resume and
// corpus replay intentionally use the immutable objects retained in the
// descriptor so they remain independent of the original templates.
func validateFuzzDescriptorSources(
	ctx context.Context, backend Backend, descriptor fuzzplan.Descriptor,
) error {
	for _, expected := range descriptor.Templates {
		kind, err := LookupKind(expected.Kind)
		if err != nil {
			return fmt.Errorf("recheck template %s: %w", expected.ID, err)
		}
		object, err := backend.Get(ctx, ResourceRef{
			Kind: kind, Namespace: expected.Namespace, Name: expected.Name,
		})
		if err != nil {
			return fmt.Errorf("recheck template %s: %w", expected.ID, err)
		}
		observed, err := resolvedFuzzTemplate(fuzzplan.TemplatePlan{
			ID: expected.ID, Kind: expected.Kind, Name: expected.Name,
			Weight: expected.Weight, MaxUses: expected.MaxUses,
			ConflictGroups: expected.ConflictGroups, Requires: expected.Requires,
		}, object.Object)
		if err != nil {
			return fmt.Errorf("recheck template %s: %w", expected.ID, err)
		}
		if observed.Namespace != expected.Namespace || observed.Name != expected.Name ||
			observed.UID != expected.UID || observed.Generation != expected.Generation ||
			observed.SpecDigest != expected.SpecDigest {
			return fmt.Errorf("template %s changed after session planning", expected.ID)
		}
	}

	policyKind, err := LookupKind("BurnchainPolicy")
	if err != nil {
		return err
	}
	for _, expected := range descriptor.Network.Policies {
		object, err := backend.Get(ctx, ResourceRef{
			Kind: policyKind, Namespace: expected.Namespace, Name: expected.Name,
		})
		if err != nil {
			return fmt.Errorf("recheck burnchain policy %s: %w", expected.Name, err)
		}
		var observed attacknetv1beta1.BurnchainPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &observed); err != nil {
			return fmt.Errorf("decode burnchain policy %s: %w", expected.Name, err)
		}
		digest, err := canonical.ArtifactDigest(observed.Spec)
		if err != nil {
			return err
		}
		if observed.Namespace != expected.Namespace || observed.Name != expected.Name ||
			string(observed.UID) != expected.UID || observed.Generation != expected.Generation ||
			digest != expected.SpecDigest || observed.Spec.NetworkRef != expected.Spec.NetworkRef ||
			observed.Spec.BitcoinNodeRef != expected.Spec.BitcoinNodeRef {
			return fmt.Errorf("burnchain policy %s changed after session planning", expected.Name)
		}
	}
	return nil
}

func (app *App) runFuzzStatus(args []string) error {
	flags := newFlagSet("fuzz status", app.Stderr)
	session := flags.String("session", "", "session SHA-256 digest")
	corpus := flags.String("corpus", "", "corpus root")
	output := flags.String("output", "json", "json")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *session == "" || *corpus == "" || *output != "json" || flags.NArg() != 0 {
		return usageError("usage: attacknet fuzz status --session DIGEST --corpus DIR --output json")
	}
	store, err := fuzzcorpus.OpenExisting(*corpus, app.Now)
	if err != nil {
		return err
	}
	journal, err := store.OpenJournal(*session)
	if err != nil {
		return err
	}
	records := journal.Records()
	phase := "Planned"
	if len(records) != 0 {
		phase = records[len(records)-1].Phase
	}
	verification, err := store.Verify()
	if err != nil {
		return err
	}
	entries, err := store.Entries()
	if err != nil {
		return err
	}
	sessionEntries := make([]fuzzcorpus.Entry, 0)
	classificationCounts := map[string]int{
		"Clean": 0, "NetworkFailureCandidate": 0, "ConfirmedNetworkFailure": 0,
		"NotReproduced": 0, "Inconclusive": 0, "HarnessFailed": 0,
	}
	for _, entry := range entries {
		if entry.SessionDigest == *session {
			sessionEntries = append(sessionEntries, entry)
			classificationCounts[entry.Classification]++
		}
	}
	warnings := make([]string, 0)
	if phase != "Complete" {
		warnings = append(warnings, "session is not complete; preserve the environment and inspect the journal")
	}
	for _, entry := range sessionEntries {
		if entry.Classification == "HarnessFailed" || entry.Classification == "Inconclusive" {
			warnings = append(warnings, fmt.Sprintf(
				"trial %d is %s; it is not a network-failure conclusion",
				entry.TrialOrdinal, entry.Classification,
			))
		}
	}
	result := map[string]any{
		"schemaVersion": "stacks-attacknet-fuzz-status/v1",
		"sessionDigest": *session, "phase": phase, "journalRecords": len(records),
		"classificationCounts": classificationCounts,
		"corpusVerification":   verification, "entries": sessionEntries, "warnings": warnings,
		"environmentPreservationRequired": len(warnings) != 0,
	}
	if len(records) != 0 {
		result["currentTransition"] = records[len(records)-1]
	}
	if pointer, err := store.Report(*session); err == nil {
		data, readErr := store.ReadObject(pointer.Report)
		if readErr != nil {
			return readErr
		}
		var report any
		if json.Unmarshal(data, &report) != nil {
			return errors.New("verified session report is not valid JSON")
		}
		result["reportReference"] = pointer.Report
		result["report"] = report
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, record := range records {
		if record.Kind != "CapacityAdmitted" || len(record.Artifacts) != 1 {
			continue
		}
		data, readErr := store.ReadObject(record.Artifacts[0])
		if readErr != nil {
			return readErr
		}
		var receipt fuzzsession.CapacityReceipt
		if json.Unmarshal(data, &receipt) != nil || receipt.SchemaVersion != fuzzsession.CapacitySchema {
			return errors.New("verified capacity receipt is not valid JSON")
		}
		result["capacityReference"] = record.Artifacts[0]
		result["capacity"] = receipt
		result["capacityHeadroom"] = capacityHeadroom(receipt)
		break
	}
	return writeJSON(app.Stdout, result)
}

func capacityHeadroom(receipt fuzzsession.CapacityReceipt) map[string]any {
	nodes := make([]map[string]any, 0, len(receipt.Snapshot.Nodes))
	for _, node := range receipt.Snapshot.Nodes {
		nodes = append(nodes, map[string]any{
			"name":       node.Name,
			"rootBytes":  node.RootAvailableBytes - receipt.Policy.MinimumNodeBytes - receipt.Policy.StorageEscrowBytes,
			"imageBytes": node.ImageAvailableBytes - receipt.Policy.MinimumImageBytes,
		})
	}
	return map[string]any{
		"nodes":       nodes,
		"corpusBytes": receipt.Snapshot.CorpusAvailableBytes - receipt.Policy.MinimumCorpusBytes - receipt.Policy.EvidenceEscrowBytes,
	}
}

func (app *App) runCorpus(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet corpus list|show|verify|replay ...")
	}
	flags := newFlagSet("corpus "+args[0], app.Stderr)
	root := flags.String("corpus", "", "corpus root")
	output := flags.String("output", "json", "json")
	entryDigest := flags.String("entry", "", "exact entry digest when a fingerprint has multiple entries")
	attemptID := flags.String("attempt-id", "", "unique bounded replay attempt identity")
	dryRun := flags.Bool("dry-run", false, "render deterministic resources without mutation")
	if err := flags.Parse(args[1:]); err != nil {
		return commandUsageError{err.Error()}
	}
	if *root == "" || *output != "json" {
		return usageError("--corpus DIR is required")
	}
	store, err := fuzzcorpus.OpenExisting(*root, app.Now)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		if flags.NArg() != 0 {
			return usageError("usage: attacknet corpus list --corpus DIR --output json")
		}
		entries, err := store.Entries()
		if err != nil {
			return err
		}
		return writeJSON(app.Stdout, entries)
	case "show", "replay":
		if flags.NArg() != 1 {
			return usageError("corpus show and replay require one semantic fingerprint")
		}
		entries, err := store.EntriesForFingerprint(flags.Arg(0))
		if err != nil {
			return err
		}
		if args[0] == "replay" {
			return app.executeCorpusEntry(ctx, store, entries, *entryDigest, *attemptID, false, *dryRun)
		}
		return writeJSON(app.Stdout, entries)
	case "verify":
		if flags.NArg() != 0 {
			return usageError("usage: attacknet corpus verify --corpus DIR")
		}
		result, err := store.Verify()
		if err != nil {
			return err
		}
		return writeJSON(app.Stdout, result)
	default:
		return usageError("usage: attacknet corpus list|show|verify|replay ...")
	}
}

func (app *App) runReduce(ctx context.Context, args []string) error {
	flags := newFlagSet("reduce", app.Stderr)
	root := flags.String("corpus", "", "corpus root")
	entryDigest := flags.String("entry", "", "exact entry digest when a fingerprint has multiple entries")
	attemptID := flags.String("attempt-id", "", "unique bounded reduction attempt identity")
	dryRun := flags.Bool("dry-run", false, "render deterministic resources without mutation")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if *root == "" || flags.NArg() != 1 {
		return usageError("usage: attacknet reduce --corpus DIR [--entry DIGEST] [--attempt-id ID] FINGERPRINT")
	}
	store, err := fuzzcorpus.OpenExisting(*root, app.Now)
	if err != nil {
		return err
	}
	entries, err := store.EntriesForFingerprint(flags.Arg(0))
	if err != nil {
		return err
	}
	return app.executeCorpusEntry(ctx, store, entries, *entryDigest, *attemptID, true, *dryRun)
}

func (app *App) executeCorpusEntry(
	ctx context.Context,
	store *fuzzcorpus.Store,
	entries []fuzzcorpus.Entry,
	entryDigest, attemptID string,
	reduce, dryRun bool,
) error {
	if len(entries) == 0 {
		return errors.New("semantic fingerprint has no corpus entries")
	}
	selected := fuzzcorpus.Entry{}
	if entryDigest == "" {
		if len(entries) != 1 {
			return errors.New("fingerprint has multiple entries; --entry is required")
		}
		selected = entries[0]
	} else {
		for _, entry := range entries {
			if entry.Digest == entryDigest {
				selected = entry
				break
			}
		}
		if selected.Digest == "" {
			return errors.New("requested entry digest is absent from the fingerprint")
		}
	}
	if selected.Classification != "ConfirmedNetworkFailure" && reduce {
		return errors.New("automatic reduction requires a confirmed network failure")
	}
	descriptorReference, err := uniqueNamedReference(
		selected.Objects, "session-descriptor", "corpus entry",
	)
	if err != nil {
		return err
	}
	data, err := store.ReadObject(descriptorReference)
	if err != nil {
		return err
	}
	var descriptor fuzzplan.Descriptor
	if err := document.DecodeOne(data, &descriptor); err != nil {
		return err
	}
	if attemptID == "" {
		prefix := strings.TrimPrefix(selected.Digest, "sha256:")
		if reduce {
			attemptID = "reduce-" + prefix[:12]
		} else {
			attemptID = "replay-" + prefix[:12]
		}
	}
	if dryRun {
		operation := "corpus-replay"
		if reduce {
			operation = "reduction"
		}
		return app.writeFuzzDryRun(descriptor, operation, selected.Digest, selected.TrialOrdinal, attemptID)
	}
	if app.FuzzRuntimeFactory == nil {
		return errors.New("fuzz runtime is unavailable")
	}
	runtimeBoundary, err := app.FuzzRuntimeFactory(store.Root(), descriptor.Network.Template.Namespace)
	if err != nil {
		return err
	}
	engine := fuzzsession.Engine{Runtime: runtimeBoundary, Store: store, Now: app.Now}
	result, err := engine.ExecuteCorpus(ctx, descriptor, selected, attemptID, reduce)
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, result)
}

type fuzzDryRunResult struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	Operation      string                       `json:"operation"`
	SessionDigest  string                       `json:"sessionDigest"`
	EntryDigest    string                       `json:"entryDigest,omitempty"`
	MutatedCluster bool                         `json:"mutatedCluster"`
	Decisions      []fuzzplan.Trial             `json:"decisions"`
	Resources      []fuzzplan.MaterializedTrial `json:"resources"`
	Contingent     map[string]int32             `json:"contingentAttemptBounds"`
}

func (app *App) writeFuzzDryRun(
	descriptor fuzzplan.Descriptor,
	operation, entryDigest string,
	ordinal int32,
	attemptID string,
) error {
	result := fuzzDryRunResult{
		SchemaVersion: "stacks-attacknet-fuzz-dry-run/v1",
		Operation:     operation, SessionDigest: descriptor.Digest,
		EntryDigest: entryDigest, MutatedCluster: false,
		Contingent: map[string]int32{
			"confirmation": descriptor.Confirmation.MaxAttempts,
			"reduction":    descriptor.Reduction.MaxAttempts,
		},
	}
	ordinals := make([]int32, 0, len(descriptor.Trials))
	if ordinal != 0 {
		ordinals = append(ordinals, ordinal)
	} else {
		for _, trial := range descriptor.Trials {
			ordinals = append(ordinals, trial.Ordinal)
		}
	}
	for _, trialOrdinal := range ordinals {
		result.Decisions = append(result.Decisions, descriptor.Trials[trialOrdinal-1])
		id, kind := "source", "Source"
		if attemptID != "" {
			id, kind = attemptID, "Confirmation"
		}
		materialized, err := fuzzplan.MaterializeTrial(
			descriptor, trialOrdinal, id, kind,
			descriptor.Network.Template.Namespace,
		)
		if err != nil {
			return err
		}
		result.Resources = append(result.Resources, materialized)
	}
	return writeJSON(app.Stdout, result)
}

func readFuzzDescriptor(path string) (fuzzplan.Descriptor, error) {
	data, err := readPlanFile(".", path)
	if err != nil {
		return fuzzplan.Descriptor{}, err
	}
	var descriptor fuzzplan.Descriptor
	if err := document.DecodeOne(data, &descriptor); err != nil {
		return descriptor, fmt.Errorf("decode fuzz descriptor: %w", err)
	}
	if err := fuzzplan.VerifyDescriptor(descriptor); err != nil {
		return descriptor, err
	}
	return descriptor, nil
}

func resolvedFuzzTemplate(plan fuzzplan.TemplatePlan, object map[string]any) (fuzzplan.ResolvedTemplate, error) {
	result := fuzzplan.ResolvedTemplate{
		ID: plan.ID, Kind: plan.Kind, Name: plan.Name,
		Weight: plan.Weight, MaxUses: plan.MaxUses,
		ConflictGroups: append([]string(nil), plan.ConflictGroups...),
		Requires:       append([]string(nil), plan.Requires...),
	}
	switch plan.Kind {
	case "FaultCampaign":
		var value attacknetv1beta1.FaultCampaign
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object, &value); err != nil {
			return result, err
		}
		if !value.Spec.Template || value.Spec.NetworkRef != "" {
			return result, fmt.Errorf("fault template %s must be portable and set template=true", plan.Name)
		}
		result.Namespace, result.UID, result.Generation =
			value.Namespace, string(value.UID), value.Generation
		digest, err := canonical.ArtifactDigest(value.Spec)
		result.SpecDigest = digest
		result.FaultSpec = value.Spec.DeepCopy()
		return result, err
	case "UpgradeCampaign":
		var value attacknetv1beta1.UpgradeCampaign
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object, &value); err != nil {
			return result, err
		}
		if !value.Spec.Template || value.Spec.NetworkRef != "" {
			return result, fmt.Errorf("upgrade template %s must be portable and set template=true", plan.Name)
		}
		result.Namespace, result.UID, result.Generation =
			value.Namespace, string(value.UID), value.Generation
		digest, err := canonical.ArtifactDigest(value.Spec)
		result.SpecDigest = digest
		result.UpgradeSpec = value.Spec.DeepCopy()
		return result, err
	default:
		return result, fmt.Errorf("unsupported template kind %s", plan.Kind)
	}
}

func readPlanFile(base, requested string) ([]byte, error) {
	path := requested
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimitedInput(file, requested)
}
