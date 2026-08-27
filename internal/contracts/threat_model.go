package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

func LoadThreatModel(path string) (ThreatModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ThreatModel{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var model ThreatModel
	if err := decoder.Decode(&model); err != nil {
		return ThreatModel{}, fmt.Errorf("decode threat model: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ThreatModel{}, errors.New("decode threat model: trailing JSON value")
	}
	if err := model.Validate(); err != nil {
		return ThreatModel{}, err
	}
	return model, nil
}

func (model ThreatModel) Validate() error {
	var problems []string
	require := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, field+" is required")
		}
	}
	require("schema_version", model.SchemaVersion)
	if model.SchemaVersion != "" && model.SchemaVersion != SchemaVersion {
		problems = append(problems, "schema_version must be "+SchemaVersion)
	}
	require("id", model.ID)
	require("version", model.Version)
	require("owner", model.Owner)
	require("review_date", model.ReviewDate)
	if model.ReviewDate != "" {
		if _, err := time.Parse(time.DateOnly, model.ReviewDate); err != nil {
			problems = append(problems, "review_date must use YYYY-MM-DD")
		}
	}
	if len(model.Assets) == 0 {
		problems = append(problems, "assets must not be empty")
	}
	if len(model.TrustBoundaries) == 0 {
		problems = append(problems, "trust_boundaries must not be empty")
	}
	if len(model.Invariants) == 0 {
		problems = append(problems, "invariants must not be empty")
	}

	assets := validateIDs("assets", assetIDs(model.Assets), &problems)
	boundaries := validateIDs("trust_boundaries", boundaryIDs(model.TrustBoundaries), &problems)
	controls := validateIDs("controls", controlIDs(model.Controls), &problems)
	validateIDs("identities", identityIDs(model.Identities), &problems)
	validateIDs("entry_points", entryPointIDs(model.EntryPoints), &problems)
	validateIDs("dependencies", dependencyIDs(model.Dependencies), &problems)
	validateIDs("assumptions", assumptionIDs(model.Assumptions), &problems)
	validateIDs("invariants", invariantIDs(model.Invariants), &problems)
	validateIDs("evidence_sources", evidenceIDs(model.EvidenceSources), &problems)

	for _, entry := range model.EntryPoints {
		require("entry_points."+entry.ID+".method", entry.Method)
		require("entry_points."+entry.ID+".path", entry.Path)
		if !boundaries[entry.BoundaryID] {
			problems = append(problems, fmt.Sprintf("entry point %s references unknown boundary %s", entry.ID, entry.BoundaryID))
		}
	}
	for _, control := range model.Controls {
		require("controls."+control.ID+".description", control.Description)
		require("controls."+control.ID+".evidence", control.Evidence)
		for _, id := range control.AssetIDs {
			if !assets[id] {
				problems = append(problems, fmt.Sprintf("control %s references unknown asset %s", control.ID, id))
			}
		}
	}
	for _, invariant := range model.Invariants {
		require("invariants."+invariant.ID+".description", invariant.Description)
		if invariant.Kind != "required" && invariant.Kind != "prohibited" {
			problems = append(problems, fmt.Sprintf("invariant %s kind must be required or prohibited", invariant.ID))
		}
		for _, id := range invariant.AssetIDs {
			if !assets[id] {
				problems = append(problems, fmt.Sprintf("invariant %s references unknown asset %s", invariant.ID, id))
			}
		}
		for _, id := range invariant.ControlIDs {
			if !controls[id] {
				problems = append(problems, fmt.Sprintf("invariant %s references unknown control %s", invariant.ID, id))
			}
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateIDs(kind string, ids []string, problems *[]string) map[string]bool {
	seen := make(map[string]bool, len(ids))
	for index, id := range ids {
		if strings.TrimSpace(id) == "" {
			*problems = append(*problems, fmt.Sprintf("%s[%d].id is required", kind, index))
			continue
		}
		if seen[id] {
			*problems = append(*problems, fmt.Sprintf("%s contains duplicate id %s", kind, id))
		}
		seen[id] = true
	}
	return seen
}

func CanonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func Digest(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func assetIDs(items []Asset) []string {
	return mapIDs(items, func(item Asset) string { return item.ID })
}
func identityIDs(items []Identity) []string {
	return mapIDs(items, func(item Identity) string { return item.ID })
}
func boundaryIDs(items []TrustBoundary) []string {
	return mapIDs(items, func(item TrustBoundary) string { return item.ID })
}
func entryPointIDs(items []EntryPoint) []string {
	return mapIDs(items, func(item EntryPoint) string { return item.ID })
}
func dependencyIDs(items []Dependency) []string {
	return mapIDs(items, func(item Dependency) string { return item.ID })
}
func assumptionIDs(items []Assumption) []string {
	return mapIDs(items, func(item Assumption) string { return item.ID })
}
func controlIDs(items []Control) []string {
	return mapIDs(items, func(item Control) string { return item.ID })
}
func invariantIDs(items []Invariant) []string {
	return mapIDs(items, func(item Invariant) string { return item.ID })
}
func evidenceIDs(items []EvidenceRef) []string {
	return mapIDs(items, func(item EvidenceRef) string { return item.ID })
}

func mapIDs[T any](items []T, getID func(T) string) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, getID(item))
	}
	return ids
}
