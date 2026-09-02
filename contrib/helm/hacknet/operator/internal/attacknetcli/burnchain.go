package attacknetcli

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
)

// runBurnchain exposes convenience mutations of BurnchainPolicy desired state.
// The controller remains the only component that applies policy to Bitcoin.
func (app *App) runBurnchain(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("usage: attacknet burnchain status|pause|resume|cadence|flash [OPTIONS] NAME")
	}
	switch args[0] {
	case "status":
		return app.runBurnchainStatus(ctx, args[1:])
	case "pause":
		return app.runBurnchainMutation(ctx, args[1:], func(policy *attacknetv1beta1.BurnchainPolicy) error {
			policy.Spec.Paused = true
			return nil
		})
	case "resume":
		return app.runBurnchainMutation(ctx, args[1:], func(policy *attacknetv1beta1.BurnchainPolicy) error {
			policy.Spec.Paused = false
			return nil
		})
	case "cadence":
		return app.runBurnchainCadence(ctx, args[1:])
	case "flash":
		return app.runBurnchainFlash(ctx, args[1:])
	default:
		return usageError(fmt.Sprintf("unknown burnchain command %q", args[0]))
	}
}

func (app *App) runBurnchainStatus(ctx context.Context, args []string) error {
	flags, namespace, output := readFlags("burnchain status", app)
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if err := validateResourceOutput(*output); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return usageError("usage: attacknet burnchain status [--namespace NS] [--output yaml|json] NAME")
	}
	object, err := app.getBurnchainPolicy(ctx, *namespace, flags.Arg(0))
	if err != nil {
		return err
	}
	return writeResource(app.Stdout, object, *output)
}

func (app *App) runBurnchainCadence(ctx context.Context, args []string) error {
	flags := newFlagSet("burnchain cadence", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	value := flags.Duration("value", 0, "positive steady-state mining cadence")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 1 || *value <= 0 {
		return usageError("usage: attacknet burnchain cadence --value DURATION [--namespace NS] NAME")
	}
	return app.mutateBurnchainPolicy(ctx, *namespace, flags.Arg(0), func(policy *attacknetv1beta1.BurnchainPolicy) error {
		policy.Spec.Cadence = metav1.Duration{Duration: *value}
		return nil
	})
}

func (app *App) runBurnchainFlash(ctx context.Context, args []string) error {
	flags := newFlagSet("burnchain flash", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	id := flags.String("id", "", "idempotency key")
	blocks := flags.Int("blocks", 0, "number of blocks")
	interval := flags.Duration("interval", 0, "optional interval between blocks")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 1 || *id == "" || *blocks < 1 || *blocks > 10000 || *interval < 0 {
		return usageError("usage: attacknet burnchain flash --id ID --blocks 1..10000 [--interval DURATION] [--namespace NS] NAME")
	}
	return app.mutateBurnchainPolicy(ctx, *namespace, flags.Arg(0), func(policy *attacknetv1beta1.BurnchainPolicy) error {
		policy.Spec.Flash = &attacknetv1beta1.BurnchainFlashRequest{
			ID: *id, Blocks: int32(*blocks), Interval: metav1.Duration{Duration: *interval},
		}
		return nil
	})
}

func (app *App) runBurnchainMutation(ctx context.Context, args []string, mutate func(*attacknetv1beta1.BurnchainPolicy) error) error {
	flags := newFlagSet("burnchain", app.Stderr)
	namespace := flags.String("namespace", app.DefaultNamespace, "resource namespace")
	if err := flags.Parse(args); err != nil {
		return commandUsageError{err.Error()}
	}
	if flags.NArg() != 1 {
		return usageError("burnchain mutation requires exactly one BurnchainPolicy name")
	}
	return app.mutateBurnchainPolicy(ctx, *namespace, flags.Arg(0), mutate)
}

func (app *App) mutateBurnchainPolicy(ctx context.Context, namespace, name string, mutate func(*attacknetv1beta1.BurnchainPolicy) error) error {
	object, err := app.getBurnchainPolicy(ctx, namespace, name)
	if err != nil {
		return err
	}
	policy := &attacknetv1beta1.BurnchainPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, policy); err != nil {
		return fmt.Errorf("decode BurnchainPolicy %s/%s: %w", namespace, name, err)
	}
	if err := mutate(policy); err != nil {
		return err
	}
	policy.TypeMeta = metav1.TypeMeta{APIVersion: attacknetv1beta1.GroupVersion.String(), Kind: "BurnchainPolicy"}
	policy.ObjectMeta = metav1.ObjectMeta{Name: name, Namespace: namespace}
	policy.Status = attacknetv1beta1.BurnchainPolicyStatus{}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	if err != nil {
		return fmt.Errorf("encode BurnchainPolicy %s/%s: %w", namespace, name, err)
	}
	delete(value, "status")
	kind, err := LookupKind("BurnchainPolicy")
	if err != nil {
		return err
	}
	desired := &unstructured.Unstructured{Object: value}
	desired.SetGroupVersionKind(kind.GVK)
	backend, err := app.requireBackend()
	if err != nil {
		return err
	}
	applied, err := backend.Apply(ctx, desired, kind)
	if err != nil {
		return err
	}
	return writeResource(app.Stdout, applied, "yaml")
}

func (app *App) getBurnchainPolicy(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	if name == "" {
		return nil, errors.New("BurnchainPolicy name is required")
	}
	kind, err := LookupKind("BurnchainPolicy")
	if err != nil {
		return nil, err
	}
	backend, err := app.requireBackend()
	if err != nil {
		return nil, err
	}
	return backend.Get(ctx, ResourceRef{Kind: kind, Namespace: resolveNamespace(namespace, app.DefaultNamespace), Name: name})
}
