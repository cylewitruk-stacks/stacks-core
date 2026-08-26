package attacknetcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

// TeardownEvidenceManifest binds the complete pre-deletion evidence roots to
// the resource whose finalizer cleanup completed.
type TeardownEvidenceManifest struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Network          string            `json:"network"`
	NetworkUID       string            `json:"networkUID"`
	InventoryDigest  string            `json:"inventoryDigest"`
	Run              string            `json:"run,omitempty"`
	Namespace        string            `json:"namespace"`
	Start            time.Time         `json:"start"`
	End              time.Time         `json:"end"`
	Artifacts        map[string]string `json:"artifacts"`
	DeletionComplete bool              `json:"deletionComplete"`
	CompletedAt      time.Time         `json:"completedAt"`
}

func (app *App) runTeardown(ctx context.Context, args []string) error {
	flags := newFlagSet("teardown", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "StacksNetwork namespace")
	output := flags.String("output", "", "new complete evidence directory")
	startValue := flags.String("start", "", "run start in RFC3339 format")
	runName := flags.String("run", "", "AttacknetRun whose status and start time are bound into the evidence")
	endValue := flags.String("end", "", "run end in RFC3339 format; defaults to now")
	timeout := flags.Duration("timeout", 15*time.Minute, "overall evidence and deletion timeout")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 1 || *output == "" || (*startValue == "") == (*runName == "") {
		return usageError("usage: attacknet teardown --output DIR (--start RFC3339 | --run RUN) [--end RFC3339] [--namespace NS] NETWORK")
	}
	if len(kubevalidation.IsDNS1123Label(*namespace)) != 0 || len(kubevalidation.IsDNS1123Subdomain(flags.Arg(0))) != 0 {
		return usageError("namespace and network must be valid Kubernetes names")
	}
	if *timeout <= 0 {
		return usageError("--timeout must be positive")
	}
	if *runName != "" && len(kubevalidation.IsDNS1123Subdomain(*runName)) != 0 {
		return usageError("--run must be a valid Kubernetes name")
	}
	start := time.Time{}
	var err error
	if *startValue != "" {
		start, err = time.Parse(time.RFC3339, *startValue)
		if err != nil {
			return usageError("--start must be RFC3339")
		}
	}
	end := time.Time{}
	if *endValue != "" {
		end, err = time.Parse(time.RFC3339, *endValue)
		if err != nil {
			return usageError("--end must be RFC3339")
		}
	}
	if _, err := os.Stat(*output); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("refusing to overwrite an existing teardown evidence path")
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		return fmt.Errorf("create teardown evidence root: %w", err)
	}
	operation, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	identityBackend, ok := backend.(IdentityDeleteBackend)
	if !ok {
		return errors.New("teardown requires a backend with identity-preconditioned deletion")
	}
	var runArtifact string
	if *runName != "" {
		runRef, refErr := resourceRef([]string{"AttacknetRun", *runName}, *namespace)
		if refErr != nil {
			return refErr
		}
		run, getErr := backend.Get(operation, runRef)
		if getErr != nil {
			return fmt.Errorf("read teardown AttacknetRun: %w", getErr)
		}
		networkRef, found, nestedErr := unstructured.NestedString(run.Object, "spec", "networkRef")
		if nestedErr != nil || !found || networkRef != flags.Arg(0) {
			return errors.New("teardown AttacknetRun does not target the requested StacksNetwork")
		}
		startedAt, found, nestedErr := unstructured.NestedString(run.Object, "status", "startedAt")
		if nestedErr != nil || !found {
			return errors.New("teardown AttacknetRun has no controller-observed start time")
		}
		start, err = time.Parse(time.RFC3339, startedAt)
		if err != nil {
			return errors.New("teardown AttacknetRun start time is invalid")
		}
		runArtifact = filepath.Join(*output, "attacknet-run.json")
		if err := writePrivateJSON(runArtifact, run.Object); err != nil {
			return err
		}
	}
	if !end.IsZero() && !start.Before(end) {
		return usageError("the observed start must precede --end")
	}
	reader, err := app.requireIncidentReader()
	if err != nil {
		return err
	}
	incidentPath := filepath.Join(*output, "incident")
	incident, err := CaptureIncidentEvidence(operation, reader, IncidentEvidenceOptions{
		Namespace: *namespace, NetworkName: flags.Arg(0), OutputDirectory: incidentPath,
		Timeout: *timeout / 2, Now: app.Now,
	})
	if err != nil {
		return fmt.Errorf("capture pre-teardown incident evidence: %w", err)
	}
	if len(incident.Errors) != 0 || len(incident.Omissions) != 0 {
		return fmt.Errorf("pre-teardown evidence is incomplete: %d errors, %d omissions", len(incident.Errors), len(incident.Omissions))
	}
	if end.IsZero() {
		end = app.Now().UTC()
		if !start.Before(end) {
			return usageError("--start must precede the observed export end")
		}
	}
	exporter, err := app.requireLogExporter()
	if err != nil {
		return err
	}
	lokiPath := filepath.Join(*output, "loki")
	logs, err := exporter.Export(operation, *namespace, flags.Arg(0), start.UTC(), end.UTC(), lokiPath)
	if err != nil || !logs.Complete {
		if err == nil {
			err = errors.New("Loki exporter reported an incomplete result")
		}
		return fmt.Errorf("complete retained-log export failed; StacksNetwork was preserved: %w", err)
	}
	artifacts := map[string]string{}
	for name, path := range map[string]string{
		"incident":     filepath.Join(incidentPath, "manifest.json"),
		"lokiSource":   filepath.Join(lokiPath, "kubernetes-source.json"),
		"lokiMetadata": filepath.Join(lokiPath, "export.json"),
		"lokiLogs":     filepath.Join(lokiPath, "logs.jsonl.gz"),
	} {
		digest, digestErr := fileSHA256(path)
		if digestErr != nil {
			return digestErr
		}
		artifacts[name] = digest
	}
	if runArtifact != "" {
		digest, digestErr := fileSHA256(runArtifact)
		if digestErr != nil {
			return digestErr
		}
		artifacts["attacknetRun"] = digest
	}
	manifest := TeardownEvidenceManifest{
		SchemaVersion: "stacks-attacknet-teardown-evidence/v1", Network: flags.Arg(0),
		NetworkUID: string(incident.Network.UID), InventoryDigest: incident.Network.InventoryDigest,
		Run: *runName, Namespace: *namespace,
		Start: start.UTC(), End: end.UTC(), Artifacts: artifacts, DeletionComplete: false,
	}
	manifestPath := filepath.Join(*output, "teardown.json")
	if err := writePrivateJSON(manifestPath, manifest); err != nil {
		return err
	}
	ref, err := resourceRef([]string{"StacksNetwork", flags.Arg(0)}, *namespace)
	if err != nil {
		return err
	}
	liveNetwork, err := reader.GetNetwork(operation, *namespace, flags.Arg(0))
	if err != nil {
		return fmt.Errorf("re-read StacksNetwork before teardown: %w", err)
	}
	if liveNetwork.UID != incident.Network.UID ||
		liveNetwork.Generation != incident.Network.Generation ||
		liveNetwork.Status.ObservedGeneration != incident.Network.ObservedGeneration ||
		!liveNetwork.Status.InventoryReady ||
		liveNetwork.Status.InventoryDigest != incident.Network.InventoryDigest {
		return errors.New("StacksNetwork identity changed after evidence capture; network was preserved")
	}
	if err := identityBackend.DeleteExact(
		operation, ref, liveNetwork.UID, liveNetwork.ResourceVersion,
	); err != nil {
		return err
	}
	for {
		_, getErr := backend.Get(operation, ref)
		if apierrors.IsNotFound(getErr) {
			break
		}
		if getErr != nil {
			return getErr
		}
		select {
		case <-operation.Done():
			return fmt.Errorf("wait for StacksNetwork deletion: %w", operation.Err())
		case <-time.After(time.Second):
		}
	}
	manifest.DeletionComplete = true
	manifest.CompletedAt = app.Now().UTC()
	if err := writePrivateJSON(manifestPath, manifest); err != nil {
		return err
	}
	return writeJSON(app.Stdout, manifest)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}
