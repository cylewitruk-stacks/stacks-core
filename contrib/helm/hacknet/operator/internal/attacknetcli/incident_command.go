package attacknetcli

import (
	"context"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

func (app *App) runIncidentEvidence(ctx context.Context, args []string) error {
	flags := newFlagSet("evidence incident", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "StacksNetwork namespace")
	output := flags.String("output", "", "new incident bundle directory")
	timeout := flags.Duration("timeout", 2*time.Minute, "overall capture timeout")
	concurrency := flags.Int("max-concurrency", 4, "maximum concurrent log reads")
	maxArtifacts := flags.Int("max-artifacts", 512, "maximum artifact count")
	maxArtifactBytes := flags.Int64("max-artifact-bytes", 2<<20, "maximum bytes per artifact")
	maxTotalBytes := flags.Int64("max-total-bytes", 64<<20, "maximum bytes in the bundle")
	maxResources := flags.Int("max-owned-resources", 256, "maximum owned Kubernetes resources")
	maxEvents := flags.Int("max-events", 512, "maximum Kubernetes Events")
	logTailLines := flags.Int64("log-tail-lines", 5000, "maximum lines requested from each container")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 1 || *output == "" {
		return usageError("usage: attacknet evidence incident --output DIR [--namespace NS] NETWORK")
	}
	if problems := kubevalidation.IsDNS1123Label(*namespace); len(problems) != 0 {
		return usageError("namespace is not a valid DNS label")
	}
	if problems := kubevalidation.IsDNS1123Subdomain(flags.Arg(0)); len(problems) != 0 {
		return usageError("network name is not a valid DNS subdomain")
	}
	reader, err := app.requireIncidentReader()
	if err != nil {
		return err
	}
	manifest, err := CaptureIncidentEvidence(ctx, reader, IncidentEvidenceOptions{
		Namespace: *namespace, NetworkName: flags.Arg(0), OutputDirectory: *output,
		Timeout: *timeout, MaxConcurrency: *concurrency, MaxArtifacts: *maxArtifacts,
		MaxArtifactBytes: *maxArtifactBytes, MaxTotalBytes: *maxTotalBytes,
		MaxOwnedResources: *maxResources, MaxEvents: *maxEvents, LogTailLines: *logTailLines,
		Now: app.Now,
	})
	if err != nil {
		return err
	}
	return writeJSON(app.Stdout, map[string]any{
		"path": *output, "network": manifest.Network, "artifactCount": len(manifest.Artifacts),
		"omissionCount": len(manifest.Omissions), "errorCount": len(manifest.Errors),
	})
}
