package contracts

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadThreatModelAndStableDigest(t *testing.T) {
	model, err := LoadThreatModel(filepath.Join("..", "..", "fixtures", "threat-models", "order-service-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Digest(model)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest(model)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("unstable digest: %q versus %q", first, second)
	}
}

func TestLoadThreatModelRejectsUnknownAndTrailingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"appsec-harness.dev/v1","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadThreatModel(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}

	if err := os.WriteFile(path, []byte(`{} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadThreatModel(path); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing JSON error, got %v", err)
	}
}

func TestValidateRejectsDuplicateAndUnknownReferences(t *testing.T) {
	model := validModel()
	model.Assets = append(model.Assets, model.Assets[0])
	model.EntryPoints[0].BoundaryID = "missing"
	model.Invariants[0].ControlIDs = []string{"missing"}
	err := model.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, want := range []string{"duplicate id orders", "unknown boundary missing", "unknown control missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestDiffThreatModelsPropagatesAffectedInvariants(t *testing.T) {
	before := validModel()
	after := validModel()
	after.Version = "2.0.0"
	after.Controls[0].Description = "Changed control"
	after.Assets = append(after.Assets, Asset{ID: "audit", Name: "Audit", Classification: "synthetic"})

	diff := DiffThreatModels(before, after)
	if !slices.Equal(diff.Controls.Modified, []string{"parameterized-search"}) {
		t.Fatalf("unexpected control changes: %#v", diff.Controls)
	}
	if !slices.Contains(diff.AffectedInvariants, "order-query-bounded") {
		t.Fatalf("expected affected invariant, got %#v", diff.AffectedInvariants)
	}
	if !slices.Contains(diff.AffectedAssets, "audit") {
		t.Fatalf("expected added asset, got %#v", diff.AffectedAssets)
	}
}

func validModel() ThreatModel {
	return ThreatModel{
		SchemaVersion:   SchemaVersion,
		ID:              "model",
		Version:         "1.0.0",
		Owner:           "owner",
		ReviewDate:      "2026-08-27",
		Assets:          []Asset{{ID: "orders", Name: "Orders", Classification: "synthetic"}},
		TrustBoundaries: []TrustBoundary{{ID: "http", Name: "HTTP", Description: "Loopback"}},
		EntryPoints:     []EntryPoint{{ID: "search", Method: "GET", Path: "/search", BoundaryID: "http"}},
		Controls:        []Control{{ID: "parameterized-search", Description: "Parameters", AssetIDs: []string{"orders"}, Evidence: "test://search"}},
		Invariants:      []Invariant{{ID: "order-query-bounded", Description: "Bounded", AssetIDs: []string{"orders"}, ControlIDs: []string{"parameterized-search"}, Kind: "required"}},
	}
}
