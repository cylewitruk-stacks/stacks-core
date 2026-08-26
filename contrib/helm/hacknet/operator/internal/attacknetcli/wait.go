package attacknetcli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// Criterion describes a controller-owned state that a caller may observe.
type Criterion struct {
	Mode  string
	Value string
}

// ParseCriterion parses terminal, phase=VALUE, or condition=TYPE.
func ParseCriterion(value string) (Criterion, error) {
	value = strings.TrimSpace(value)
	if value == "terminal" {
		return Criterion{Mode: "terminal"}, nil
	}
	mode, expected, found := strings.Cut(value, "=")
	if !found || expected == "" || (mode != "phase" && mode != "condition") {
		return Criterion{}, errors.New("wait criterion must be terminal, phase=VALUE, or condition=TYPE")
	}
	return Criterion{Mode: mode, Value: expected}, nil
}

// Satisfied reports whether fresh controller status matches the criterion.
func (criterion Criterion) Satisfied(object *unstructured.Unstructured, kind Kind) (bool, error) {
	if object == nil {
		return false, errors.New("resource is required")
	}
	observed, found, err := unstructured.NestedInt64(object.Object, "status", "observedGeneration")
	if err != nil {
		return false, fmt.Errorf("read status.observedGeneration: %w", err)
	}
	if !found || observed < object.GetGeneration() {
		return false, nil
	}
	switch criterion.Mode {
	case "phase":
		phase, _, err := unstructured.NestedString(object.Object, "status", "phase")
		return phase == criterion.Value, err
	case "terminal":
		if !kind.HasTerminalContract() {
			return false, fmt.Errorf("%s has no terminal phase contract; wait for a condition or phase", kind.Name)
		}
		phase, _, err := unstructured.NestedString(object.Object, "status", "phase")
		if err != nil {
			return false, err
		}
		return kind.IsTerminal(phase), nil
	case "condition":
		conditions, _, err := unstructured.NestedSlice(object.Object, "status", "conditions")
		if err != nil {
			return false, fmt.Errorf("read status.conditions: %w", err)
		}
		for _, raw := range conditions {
			condition, ok := raw.(map[string]any)
			if !ok || condition["type"] != criterion.Value || condition["status"] != string(metav1.ConditionTrue) {
				continue
			}
			conditionGeneration, ok := condition["observedGeneration"].(int64)
			if !ok {
				if numeric, numericOK := condition["observedGeneration"].(float64); numericOK {
					conditionGeneration = int64(numeric)
				}
			}
			return conditionGeneration >= object.GetGeneration(), nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported wait criterion mode %q", criterion.Mode)
	}
}

// WaitFor waits for fresh controller status and reconnects cleanly when a
// Kubernetes watch ends or expires.
func WaitFor(ctx context.Context, backend Backend, ref ResourceRef, criterion Criterion) (*unstructured.Unstructured, error) {
	for {
		current, err := backend.Get(ctx, ref)
		if err != nil {
			return nil, err
		}
		done, err := criterion.Satisfied(current, ref.Kind)
		if err != nil {
			return nil, err
		}
		if done {
			return current, nil
		}
		stream, err := backend.Watch(ctx, ref, current.GetResourceVersion())
		if err != nil {
			return nil, err
		}
		result, reconnect, err := consumeUntil(ctx, stream, ref.Kind, criterion)
		stream.Stop()
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
		if !reconnect {
			return nil, errors.New("resource watch ended before the criterion was satisfied")
		}
	}
}

func consumeUntil(ctx context.Context, stream watch.Interface, kind Kind, criterion Criterion) (*unstructured.Unstructured, bool, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case event, open := <-stream.ResultChan():
			if !open {
				return nil, true, nil
			}
			if event.Type == watch.Bookmark {
				continue
			}
			if event.Type == watch.Error {
				statusErr := apiStatusError(event.Object)
				if statusErr != nil && statusErr.ErrStatus.Reason == metav1.StatusReasonExpired {
					return nil, true, nil
				}
				return nil, false, fmt.Errorf("resource watch failed: %w", statusErr)
			}
			if event.Type == watch.Deleted {
				return nil, false, errors.New("resource was deleted before the criterion was satisfied")
			}
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				return nil, false, fmt.Errorf("watch returned %T, expected Unstructured", event.Object)
			}
			done, err := criterion.Satisfied(object, kind)
			if err != nil {
				return nil, false, err
			}
			if done {
				return object, false, nil
			}
		}
	}
}

func apiStatusError(object runtime.Object) *apierrors.StatusError {
	if status, ok := object.(*metav1.Status); ok {
		return &apierrors.StatusError{ErrStatus: *status}
	}
	return &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonUnknown, Message: fmt.Sprintf("%#v", object)}}
}
