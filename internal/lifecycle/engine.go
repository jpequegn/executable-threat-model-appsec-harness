package lifecycle

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jpequegn/executable-threat-model-appsec-harness/internal/contracts"
)

const lifecycleSchemaVersion = "appsec-harness.dev/lifecycle/v1"

var safeTrialID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Engine struct {
	root string
}

func NewEngine(root string) *Engine {
	return &Engine{root: root}
}

func (engine *Engine) Initialize(manifest Manifest) (Snapshot, error) {
	if manifest.SchemaVersion != lifecycleSchemaVersion {
		return Snapshot{}, fmt.Errorf("schema_version must be %s", lifecycleSchemaVersion)
	}
	if !safeTrialID.MatchString(manifest.TrialID) {
		return Snapshot{}, fmt.Errorf("trial_id must contain only letters, digits, dots, dashes, and underscores")
	}
	if strings.TrimSpace(manifest.Target) == "" || strings.TrimSpace(manifest.ThreatModelDigest) == "" {
		return Snapshot{}, fmt.Errorf("target and threat_model_digest are required")
	}
	if manifest.NetworkPolicy != "local-only" {
		return Snapshot{}, fmt.Errorf("network_policy must be local-only")
	}
	if err := manifest.Budget.Check(Usage{}); err != nil {
		return Snapshot{}, err
	}
	directory := engine.trialDirectory(manifest.TrialID)
	if _, err := os.Stat(directory); err == nil {
		existing, loadErr := engine.Load(manifest.TrialID)
		if loadErr != nil {
			return Snapshot{}, loadErr
		}
		requestedDigest, digestErr := contracts.Digest(manifest)
		if digestErr != nil {
			return Snapshot{}, digestErr
		}
		existingDigest, digestErr := contracts.Digest(existing.Manifest)
		if digestErr != nil {
			return Snapshot{}, digestErr
		}
		if requestedDigest != existingDigest {
			return Snapshot{}, fmt.Errorf("trial_id %s already exists with a different manifest", manifest.TrialID)
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	for _, name := range []string{"input", "work", "output", "receipts"} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0o700); err != nil {
			return Snapshot{}, err
		}
	}
	if err := writeExclusiveJSON(filepath.Join(directory, "manifest.json"), manifest); err != nil {
		return Snapshot{}, err
	}
	policy := map[string]any{
		"network":          "local-only",
		"allowed_hosts":    []string{"127.0.0.1", "::1", "localhost"},
		"public_network":   false,
		"private_networks": false,
		"reference_paths":  "denied-to-discovery",
	}
	if err := writeExclusiveJSON(filepath.Join(directory, "policy.json"), policy); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Manifest: manifest, State: StateNew, Usage: Usage{}, Receipts: []Receipt{}}, nil
}

func (engine *Engine) Execute(trialID string, request StepRequest) (Receipt, error) {
	snapshot, err := engine.Load(trialID)
	if err != nil {
		return Receipt{}, err
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return Receipt{}, fmt.Errorf("idempotency_key is required")
	}
	request.VerifiedFindingIDs = append([]string{}, request.VerifiedFindingIDs...)
	slices.Sort(request.VerifiedFindingIDs)
	request.VerifiedFindingIDs = slices.Compact(request.VerifiedFindingIDs)
	request.Evidence = sanitizeMap(request.Evidence)
	inputDigest, err := contracts.Digest(request)
	if err != nil {
		return Receipt{}, err
	}
	for _, receipt := range snapshot.Receipts {
		if receipt.IdempotencyKey == request.IdempotencyKey {
			if receipt.State != request.State || receipt.InputDigest != inputDigest {
				return Receipt{}, fmt.Errorf("idempotency key conflict for %s", request.IdempotencyKey)
			}
			return receipt, nil
		}
	}
	expected, exists := nextState[snapshot.State]
	if !exists || request.State != expected {
		return Receipt{}, fmt.Errorf("invalid transition %s -> %s; expected %s", snapshot.State, request.State, expected)
	}
	if requiresVerifiedFinding(request.State) && len(request.VerifiedFindingIDs) == 0 {
		return Receipt{}, fmt.Errorf("state %s requires at least one independently verified finding", request.State)
	}
	cumulative := snapshot.Usage.Add(request.Usage)
	if err := snapshot.Manifest.Budget.Check(cumulative); err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		SchemaVersion:      lifecycleSchemaVersion,
		Sequence:           len(snapshot.Receipts) + 1,
		TrialID:            trialID,
		PreviousState:      snapshot.State,
		State:              request.State,
		IdempotencyKey:     request.IdempotencyKey,
		InputDigest:        inputDigest,
		Usage:              request.Usage,
		CumulativeUsage:    cumulative,
		VerifiedFindingIDs: request.VerifiedFindingIDs,
		Evidence:           request.Evidence,
	}
	digestable := receipt
	digestable.ReceiptDigest = ""
	receipt.ReceiptDigest, err = contracts.Digest(digestable)
	if err != nil {
		return Receipt{}, err
	}
	if err := appendJSONLine(engine.receiptPath(trialID), receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (engine *Engine) Load(trialID string) (Snapshot, error) {
	if !safeTrialID.MatchString(trialID) {
		return Snapshot{}, fmt.Errorf("invalid trial_id")
	}
	manifestData, err := os.ReadFile(filepath.Join(engine.trialDirectory(trialID), "manifest.json"))
	if err != nil {
		return Snapshot{}, err
	}
	var manifest Manifest
	if err := decodeStrict(manifestData, &manifest); err != nil {
		return Snapshot{}, fmt.Errorf("load manifest: %w", err)
	}
	receipts, err := readReceipts(engine.receiptPath(trialID))
	if err != nil {
		return Snapshot{}, err
	}
	state := StateNew
	usage := Usage{}
	for index, receipt := range receipts {
		if receipt.Sequence != index+1 || receipt.PreviousState != state || nextState[state] != receipt.State {
			return Snapshot{}, fmt.Errorf("receipt sequence is invalid at line %d", index+1)
		}
		digestable := receipt
		digestable.ReceiptDigest = ""
		digest, err := contracts.Digest(digestable)
		if err != nil || digest != receipt.ReceiptDigest {
			return Snapshot{}, fmt.Errorf("receipt digest mismatch at line %d", index+1)
		}
		state = receipt.State
		usage = receipt.CumulativeUsage
	}
	return Snapshot{Manifest: manifest, State: state, Usage: usage, Receipts: receipts}, nil
}

func requiresVerifiedFinding(state State) bool {
	switch state {
	case StateContain, StatePatch, StateRegress, StateStage, StatePromoteOrRollback:
		return true
	default:
		return false
	}
}

func (engine *Engine) trialDirectory(trialID string) string {
	return filepath.Join(engine.root, trialID)
}

func (engine *Engine) receiptPath(trialID string) string {
	return filepath.Join(engine.trialDirectory(trialID), "receipts", "receipts.jsonl")
}

func writeExclusiveJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(data, '\n'))
	return err
}

func appendJSONLine(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(data, '\n'))
	return err
}

func readReceipts(path string) ([]Receipt, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Receipt{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var receipts []Receipt
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var receipt Receipt
		if err := decodeStrict(scanner.Bytes(), &receipt); err != nil {
			return nil, fmt.Errorf("decode receipt line %d: %w", len(receipts)+1, err)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, scanner.Err()
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
