package fault

import (
	"container/list"
	"errors"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	attacknetv1beta1 "github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/api/v1beta1"
	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/canonical"
)

const defaultCompilationCacheCapacity = 128

type campaignCompileFunc func(*attacknetv1beta1.FaultCampaign, Manifest) (CompiledCampaign, error)

type compilationCacheKey struct {
	Namespace  string                             `json:"namespace"`
	Name       string                             `json:"name"`
	UID        types.UID                          `json:"uid"`
	Generation int64                              `json:"generation"`
	Spec       attacknetv1beta1.FaultCampaignSpec `json:"spec"`
	Manifest   Manifest                           `json:"manifest"`
}

type compilationCacheEntry struct {
	key      string
	ownerUID types.UID
	value    CompiledCampaign
}

// CompilationCache bounds successful campaign compilations by immutable
// campaign and admitted-manifest inputs. Cache misses retain fail-closed
// compiler semantics; cache state is never an admission authority.
type CompilationCache struct {
	mu       sync.Mutex
	capacity int
	compile  campaignCompileFunc
	entries  map[string]*list.Element
	lru      *list.List
}

// NewCompilationCache creates a bounded cache around the production compiler.
func NewCompilationCache(capacity int) (*CompilationCache, error) {
	return newCompilationCache(capacity, CompileV1Beta1)
}

func newCompilationCache(capacity int, compile campaignCompileFunc) (*CompilationCache, error) {
	if capacity < 1 {
		return nil, errors.New("compilation cache capacity must be positive")
	}
	if compile == nil {
		return nil, errors.New("compilation cache requires a compiler")
	}
	return &CompilationCache{
		capacity: capacity,
		compile:  compile,
		entries:  make(map[string]*list.Element, capacity),
		lru:      list.New(),
	}, nil
}

// Compile returns a defensive copy of a cached plan or compiles and caches a
// successful plan for the exact immutable inputs.
func (cache *CompilationCache) Compile(campaign *attacknetv1beta1.FaultCampaign, manifest Manifest) (CompiledCampaign, error) {
	if cache == nil {
		return CompiledCampaign{}, errors.New("compilation cache is required")
	}
	if campaign == nil {
		return cache.compile(nil, manifest)
	}
	key, err := canonical.ArtifactDigest(compilationCacheKey{
		Namespace: campaign.GetNamespace(), Name: campaign.GetName(), UID: campaign.GetUID(),
		Generation: campaign.GetGeneration(), Spec: *campaign.Spec.DeepCopy(), Manifest: manifest,
	})
	if err != nil {
		return CompiledCampaign{}, err
	}
	cache.mu.Lock()
	if element := cache.entries[key]; element != nil {
		cache.lru.MoveToFront(element)
		value := deepCopyCompiledCampaign(element.Value.(*compilationCacheEntry).value)
		cache.mu.Unlock()
		return value, nil
	}
	cache.mu.Unlock()

	compiled, err := cache.compile(campaign, manifest)
	if err != nil {
		return CompiledCampaign{}, err
	}
	cache.mu.Lock()
	if element := cache.entries[key]; element != nil {
		cache.lru.MoveToFront(element)
		compiled = element.Value.(*compilationCacheEntry).value
	} else {
		stored := deepCopyCompiledCampaign(compiled)
		element := cache.lru.PushFront(&compilationCacheEntry{key: key, ownerUID: campaign.GetUID(), value: stored})
		cache.entries[key] = element
		if cache.lru.Len() > cache.capacity {
			cache.removeElement(cache.lru.Back())
		}
	}
	cache.mu.Unlock()
	return deepCopyCompiledCampaign(compiled), nil
}

// Forget removes every cached generation owned by one campaign UID.
func (cache *CompilationCache) Forget(uid types.UID) {
	if cache == nil || uid == "" {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for element := cache.lru.Back(); element != nil; {
		previous := element.Prev()
		if element.Value.(*compilationCacheEntry).ownerUID == uid {
			cache.removeElement(element)
		}
		element = previous
	}
}

func (cache *CompilationCache) removeElement(element *list.Element) {
	if element == nil {
		return
	}
	delete(cache.entries, element.Value.(*compilationCacheEntry).key)
	cache.lru.Remove(element)
}

func deepCopyCompiledCampaign(source CompiledCampaign) CompiledCampaign {
	result := CompiledCampaign{AggregateImpact: source.AggregateImpact}
	result.AggregateImpact.PotentiallyOverlappingStages = append([]string(nil), source.AggregateImpact.PotentiallyOverlappingStages...)
	result.Stages = make([]CompiledStage, len(source.Stages))
	for stageIndex := range source.Stages {
		sourceStage := source.Stages[stageIndex]
		stage := CompiledStage{ID: sourceStage.ID, Trigger: *sourceStage.Trigger.DeepCopy()}
		stage.Actions = make([]CompiledAction, len(sourceStage.Actions))
		for actionIndex := range sourceStage.Actions {
			sourceAction := sourceStage.Actions[actionIndex]
			action := CompiledAction{ID: sourceAction.ID, Evidence: sourceAction.Evidence}
			action.Resource = sourceAction.Resource.DeepCopy()
			action.Evidence.SelectedActors = append([]string(nil), sourceAction.Evidence.SelectedActors...)
			action.Evidence.PeerSelectedActors = append([]string(nil), sourceAction.Evidence.PeerSelectedActors...)
			action.Evidence.IOPressure = deepCopyJSONMap(sourceAction.Evidence.IOPressure)
			action.Evidence.Parameters = deepCopyJSONMap(sourceAction.Evidence.Parameters)
			stage.Actions[actionIndex] = action
		}
		result.Stages[stageIndex] = stage
	}
	return result
}

func deepCopyJSONMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	return runtime.DeepCopyJSONValue(source).(map[string]any)
}
