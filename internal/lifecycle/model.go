package lifecycle

import "fmt"

type State string

const (
	StateNew               State = "NEW"
	StatePrepare           State = "PREPARE"
	StateDiscover          State = "DISCOVER"
	StateVerify            State = "VERIFY"
	StateTriage            State = "TRIAGE"
	StateContain           State = "CONTAIN"
	StatePatch             State = "PATCH"
	StateRegress           State = "REGRESS"
	StateStage             State = "STAGE"
	StatePromoteOrRollback State = "PROMOTE_OR_ROLLBACK"
	StateReport            State = "REPORT"
)

var nextState = map[State]State{
	StateNew:               StatePrepare,
	StatePrepare:           StateDiscover,
	StateDiscover:          StateVerify,
	StateVerify:            StateTriage,
	StateTriage:            StateContain,
	StateContain:           StatePatch,
	StatePatch:             StateRegress,
	StateRegress:           StateStage,
	StateStage:             StatePromoteOrRollback,
	StatePromoteOrRollback: StateReport,
}

type Budget struct {
	MaxDurationMS int64 `json:"max_duration_ms"`
	MaxToolCalls  int64 `json:"max_tool_calls"`
	MaxCostMicros int64 `json:"max_cost_micros"`
}

type Usage struct {
	DurationMS int64 `json:"duration_ms"`
	ToolCalls  int64 `json:"tool_calls"`
	CostMicros int64 `json:"cost_micros"`
}

func (usage Usage) Add(other Usage) Usage {
	return Usage{
		DurationMS: usage.DurationMS + other.DurationMS,
		ToolCalls:  usage.ToolCalls + other.ToolCalls,
		CostMicros: usage.CostMicros + other.CostMicros,
	}
}

func (budget Budget) Check(usage Usage) error {
	if budget.MaxDurationMS < 0 || budget.MaxToolCalls < 0 || budget.MaxCostMicros < 0 {
		return fmt.Errorf("budget limits must be non-negative")
	}
	if usage.DurationMS < 0 || usage.ToolCalls < 0 || usage.CostMicros < 0 {
		return fmt.Errorf("usage values must be non-negative")
	}
	if budget.MaxDurationMS > 0 && usage.DurationMS > budget.MaxDurationMS {
		return fmt.Errorf("duration budget exhausted: %d > %d", usage.DurationMS, budget.MaxDurationMS)
	}
	if budget.MaxToolCalls > 0 && usage.ToolCalls > budget.MaxToolCalls {
		return fmt.Errorf("tool-call budget exhausted: %d > %d", usage.ToolCalls, budget.MaxToolCalls)
	}
	if budget.MaxCostMicros > 0 && usage.CostMicros > budget.MaxCostMicros {
		return fmt.Errorf("cost budget exhausted: %d > %d", usage.CostMicros, budget.MaxCostMicros)
	}
	return nil
}

type Manifest struct {
	SchemaVersion     string `json:"schema_version"`
	TrialID           string `json:"trial_id"`
	Target            string `json:"target"`
	ThreatModelDigest string `json:"threat_model_digest"`
	Budget            Budget `json:"budget"`
	NetworkPolicy     string `json:"network_policy"`
}

type StepRequest struct {
	State              State          `json:"state"`
	IdempotencyKey     string         `json:"idempotency_key"`
	Usage              Usage          `json:"usage"`
	VerifiedFindingIDs []string       `json:"verified_finding_ids"`
	Evidence           map[string]any `json:"evidence"`
}

type Receipt struct {
	SchemaVersion      string         `json:"schema_version"`
	Sequence           int            `json:"sequence"`
	TrialID            string         `json:"trial_id"`
	PreviousState      State          `json:"previous_state"`
	State              State          `json:"state"`
	IdempotencyKey     string         `json:"idempotency_key"`
	InputDigest        string         `json:"input_digest"`
	Usage              Usage          `json:"usage"`
	CumulativeUsage    Usage          `json:"cumulative_usage"`
	VerifiedFindingIDs []string       `json:"verified_finding_ids"`
	Evidence           map[string]any `json:"evidence"`
	ReceiptDigest      string         `json:"receipt_digest"`
}

type Snapshot struct {
	Manifest Manifest  `json:"manifest"`
	State    State     `json:"state"`
	Usage    Usage     `json:"usage"`
	Receipts []Receipt `json:"receipts"`
}
