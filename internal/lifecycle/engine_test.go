package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeCreatesCleanLocalOnlyWorkspace(t *testing.T) {
	root := t.TempDir()
	engine := NewEngine(root)
	snapshot, err := engine.Initialize(testManifest("trial-one"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != StateNew {
		t.Fatalf("state = %s", snapshot.State)
	}
	for _, path := range []string{"input", "work", "output", "receipts", "manifest.json", "policy.json"} {
		if _, err := os.Stat(filepath.Join(root, "trial-one", path)); err != nil {
			t.Errorf("missing workspace path %s: %v", path, err)
		}
	}
	policy, err := os.ReadFile(filepath.Join(root, "trial-one", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policy), `"public_network":false`) {
		t.Fatalf("unexpected policy: %s", policy)
	}
	reused := testManifest("trial-one")
	reused.Target = "different-target"
	if _, err := engine.Initialize(reused); err == nil || !strings.Contains(err.Error(), "different manifest") {
		t.Fatalf("expected manifest conflict, got %v", err)
	}
}

func TestLifecycleRejectsInvalidTransitionsAndUnverifiedRemediation(t *testing.T) {
	engine := initializedEngine(t, "gated")
	if _, err := engine.Execute("gated", request(StateDiscover, "skip", nil)); err == nil || !strings.Contains(err.Error(), "invalid transition") {
		t.Fatalf("expected invalid transition, got %v", err)
	}
	advance(t, engine, "gated", StatePrepare, nil)
	advance(t, engine, "gated", StateDiscover, nil)
	advance(t, engine, "gated", StateVerify, nil)
	advance(t, engine, "gated", StateTriage, nil)
	if _, err := engine.Execute("gated", request(StateContain, "contain-without-proof", nil)); err == nil || !strings.Contains(err.Error(), "independently verified") {
		t.Fatalf("expected proof gate, got %v", err)
	}
	advance(t, engine, "gated", StateContain, []string{"finding-1"})
}

func TestBudgetsFailClosed(t *testing.T) {
	engine := initializedEngine(t, "budget")
	request := request(StatePrepare, "over-budget", nil)
	request.Usage = Usage{DurationMS: 1, ToolCalls: 11, CostMicros: 1}
	if _, err := engine.Execute("budget", request); err == nil || !strings.Contains(err.Error(), "tool-call budget exhausted") {
		t.Fatalf("expected budget error, got %v", err)
	}
	snapshot, err := engine.Load("budget")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != StateNew || len(snapshot.Receipts) != 0 {
		t.Fatalf("failed step mutated trial: %#v", snapshot)
	}
}

func TestNegativeBudgetIsRejected(t *testing.T) {
	manifest := testManifest("negative-budget")
	manifest.Budget.MaxCostMicros = -1
	if _, err := NewEngine(t.TempDir()).Initialize(manifest); err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("expected invalid budget error, got %v", err)
	}
}

func TestIdempotencySurvivesRestartAndRejectsConflicts(t *testing.T) {
	root := t.TempDir()
	engine := NewEngine(root)
	if _, err := engine.Initialize(testManifest("restart")); err != nil {
		t.Fatal(err)
	}
	firstRequest := request(StatePrepare, "same-key", nil)
	first, err := engine.Execute("restart", firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewEngine(root)
	second, err := restarted.Execute("restart", firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReceiptDigest != second.ReceiptDigest || first.Sequence != second.Sequence {
		t.Fatalf("idempotent replay changed receipt")
	}
	conflict := firstRequest
	conflict.Evidence = map[string]any{"changed": true}
	if _, err := restarted.Execute("restart", conflict); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected key conflict, got %v", err)
	}
}

func TestReceiptsAreSanitizedAndTamperEvident(t *testing.T) {
	engine := initializedEngine(t, "sanitize")
	request := request(StatePrepare, "sanitize-key", nil)
	request.Evidence = map[string]any{
		"message": "token=abc123",
		"nested":  []any{"SYNTHETIC_CANARY_DO_NOT_EMIT_184", "safe"},
	}
	receipt, err := engine.Execute("sanitize", request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(engine.receiptPath("sanitize"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abc123") || strings.Contains(string(data), syntheticCanary) {
		t.Fatalf("receipt leaked a secret: %s", data)
	}
	if receipt.Evidence["message"] != "[REDACTED]" {
		t.Fatalf("evidence was not redacted: %#v", receipt.Evidence)
	}

	tampered := strings.Replace(string(data), `"message":"[REDACTED]"`, `"message":"changed"`, 1)
	if err := os.WriteFile(engine.receiptPath("sanitize"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Load("sanitize"); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected tamper detection, got %v", err)
	}
}

func initializedEngine(t *testing.T, trialID string) *Engine {
	t.Helper()
	engine := NewEngine(t.TempDir())
	if _, err := engine.Initialize(testManifest(trialID)); err != nil {
		t.Fatal(err)
	}
	return engine
}

func testManifest(trialID string) Manifest {
	return Manifest{
		SchemaVersion:     lifecycleSchemaVersion,
		TrialID:           trialID,
		Target:            "synthetic-order-service",
		ThreatModelDigest: "sha256:test",
		Budget:            Budget{MaxDurationMS: 1000, MaxToolCalls: 10, MaxCostMicros: 100},
		NetworkPolicy:     "local-only",
	}
}

func request(state State, key string, verified []string) StepRequest {
	return StepRequest{
		State:              state,
		IdempotencyKey:     key,
		Usage:              Usage{DurationMS: 1, ToolCalls: 1, CostMicros: 1},
		VerifiedFindingIDs: verified,
		Evidence:           map[string]any{"workspace": "ready"},
	}
}

func advance(t *testing.T, engine *Engine, trialID string, state State, verified []string) Receipt {
	t.Helper()
	receipt, err := engine.Execute(trialID, request(state, trialID+":"+string(state), verified))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
