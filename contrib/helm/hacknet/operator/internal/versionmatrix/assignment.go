package versionmatrix

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// ResolveAssignments produces a stable explicit actor-to-profile mapping.
func ResolveAssignments(plan Plan) ([]Assignment, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	overrides := map[string]string{}
	for _, assignment := range plan.Assignment.Overrides {
		if _, duplicate := overrides[assignment.Actor]; duplicate {
			return nil, fmt.Errorf("actor %q has duplicate explicit assignments", assignment.Actor)
		}
		overrides[assignment.Actor] = assignment.Profile
	}
	actors := append([]ActorPlan(nil), plan.Actors...)
	sort.Slice(actors, func(i, j int) bool { return actors[i].Name < actors[j].Name })
	result := make([]Assignment, 0, len(actors))
	for _, actor := range actors {
		profile := overrides[actor.Name]
		if profile == "" {
			profile = weightedProfile(plan.Assignment, actor)
		}
		if profile == "" {
			profile = plan.Assignment.DefaultProfile
		}
		result = append(result, Assignment{Actor: actor.Name, Profile: profile})
	}
	return result, nil
}

func weightedProfile(plan AssignmentPlan, actor ActorPlan) string {
	if len(plan.Weighted) == 0 {
		return ""
	}
	digest := sha256.Sum256([]byte(plan.Seed + "\x00" + actor.Name))
	bucket := int32(binary.BigEndian.Uint64(digest[:8]) % 10000)
	var upper int32
	for _, weighted := range plan.Weighted {
		if !matchesRole(weighted.Roles, actor.Role) {
			continue
		}
		upper += weighted.BasisPoints
		if bucket < upper {
			return weighted.Profile
		}
	}
	return ""
}

func matchesRole(roles []string, role string) bool {
	if len(roles) == 0 {
		return true
	}
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}
