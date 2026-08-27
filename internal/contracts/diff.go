package contracts

import (
	"encoding/json"
	"slices"
)

type ChangeSet struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
}

type ThreatModelDiff struct {
	FromVersion        string    `json:"from_version"`
	ToVersion          string    `json:"to_version"`
	Assets             ChangeSet `json:"assets"`
	TrustBoundaries    ChangeSet `json:"trust_boundaries"`
	Controls           ChangeSet `json:"controls"`
	Invariants         ChangeSet `json:"invariants"`
	AffectedAssets     []string  `json:"affected_assets"`
	AffectedBoundaries []string  `json:"affected_boundaries"`
	AffectedControls   []string  `json:"affected_controls"`
	AffectedInvariants []string  `json:"affected_invariants"`
}

func DiffThreatModels(before, after ThreatModel) ThreatModelDiff {
	assetChanges := diffByID(before.Assets, after.Assets, func(item Asset) string { return item.ID })
	boundaryChanges := diffByID(before.TrustBoundaries, after.TrustBoundaries, func(item TrustBoundary) string { return item.ID })
	controlChanges := diffByID(before.Controls, after.Controls, func(item Control) string { return item.ID })
	invariantChanges := diffByID(before.Invariants, after.Invariants, func(item Invariant) string { return item.ID })
	return ThreatModelDiff{
		FromVersion:        before.Version,
		ToVersion:          after.Version,
		Assets:             assetChanges,
		TrustBoundaries:    boundaryChanges,
		Controls:           controlChanges,
		Invariants:         invariantChanges,
		AffectedAssets:     changedIDs(assetChanges),
		AffectedBoundaries: changedIDs(boundaryChanges),
		AffectedControls:   changedIDs(controlChanges),
		AffectedInvariants: affectedInvariants(before, after, assetChanges, controlChanges, invariantChanges),
	}
}

func diffByID[T any](before, after []T, id func(T) string) ChangeSet {
	left := indexCanonical(before, id)
	right := indexCanonical(after, id)
	var result ChangeSet
	for key, value := range left {
		other, exists := right[key]
		if !exists {
			result.Removed = append(result.Removed, key)
		} else if value != other {
			result.Modified = append(result.Modified, key)
		}
	}
	for key := range right {
		if _, exists := left[key]; !exists {
			result.Added = append(result.Added, key)
		}
	}
	slices.Sort(result.Added)
	slices.Sort(result.Removed)
	slices.Sort(result.Modified)
	return result
}

func indexCanonical[T any](items []T, id func(T) string) map[string]string {
	result := make(map[string]string, len(items))
	for _, item := range items {
		data, _ := json.Marshal(item)
		result[id(item)] = string(data)
	}
	return result
}

func changedIDs(changes ChangeSet) []string {
	result := append([]string{}, changes.Added...)
	result = append(result, changes.Removed...)
	result = append(result, changes.Modified...)
	slices.Sort(result)
	return slices.Compact(result)
}

func affectedInvariants(before, after ThreatModel, assets, controls, invariants ChangeSet) []string {
	changedAssets := toSet(changedIDs(assets))
	changedControls := toSet(changedIDs(controls))
	affected := toSet(changedIDs(invariants))
	for _, invariant := range append(before.Invariants, after.Invariants...) {
		if intersects(invariant.AssetIDs, changedAssets) || intersects(invariant.ControlIDs, changedControls) {
			affected[invariant.ID] = true
		}
	}
	return sortedKeys(affected)
}

func toSet(items []string) map[string]bool {
	result := make(map[string]bool, len(items))
	for _, item := range items {
		result[item] = true
	}
	return result
}

func intersects(items []string, changed map[string]bool) bool {
	for _, item := range items {
		if changed[item] {
			return true
		}
	}
	return false
}

func sortedKeys(items map[string]bool) []string {
	result := make([]string, 0, len(items))
	for item := range items {
		result = append(result, item)
	}
	slices.Sort(result)
	return result
}
