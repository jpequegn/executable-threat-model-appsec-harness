package contracts

const SchemaVersion = "appsec-harness.dev/v1"

type EvidenceRef struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	URI    string `json:"uri"`
	Digest string `json:"digest,omitempty"`
}

type Asset struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Classification string `json:"classification"`
}

type Identity struct {
	ID    string   `json:"id"`
	Roles []string `json:"roles"`
}

type TrustBoundary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type EntryPoint struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BoundaryID string `json:"boundary_id"`
}

type Dependency struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Local    bool   `json:"local"`
}

type Assumption struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Evidence string `json:"evidence"`
}

type Control struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	AssetIDs    []string `json:"asset_ids"`
	Evidence    string   `json:"evidence"`
}

type Invariant struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	AssetIDs    []string `json:"asset_ids"`
	ControlIDs  []string `json:"control_ids"`
	Kind        string   `json:"kind"`
}

type ThreatModel struct {
	SchemaVersion   string          `json:"schema_version"`
	ID              string          `json:"id"`
	Version         string          `json:"version"`
	Owner           string          `json:"owner"`
	ReviewDate      string          `json:"review_date"`
	EvidenceSources []EvidenceRef   `json:"evidence_sources"`
	Assets          []Asset         `json:"assets"`
	Identities      []Identity      `json:"identities"`
	TrustBoundaries []TrustBoundary `json:"trust_boundaries"`
	EntryPoints     []EntryPoint    `json:"entry_points"`
	Dependencies    []Dependency    `json:"dependencies"`
	Assumptions     []Assumption    `json:"assumptions"`
	Controls        []Control       `json:"controls"`
	Invariants      []Invariant     `json:"invariants"`
}

type Finding struct {
	SchemaVersion       string        `json:"schema_version"`
	ID                  string        `json:"id"`
	TrialID             string        `json:"trial_id"`
	Component           string        `json:"component"`
	Location            string        `json:"location"`
	Hypothesis          string        `json:"hypothesis"`
	AttackPreconditions []string      `json:"attack_preconditions"`
	ClaimedImpact       string        `json:"claimed_impact"`
	AssetID             string        `json:"asset_id"`
	Evidence            []EvidenceRef `json:"evidence"`
	DiscoveryAdapter    string        `json:"discovery_adapter"`
	Confidence          float64       `json:"confidence"`
}

type VerificationProof struct {
	SchemaVersion        string        `json:"schema_version"`
	ID                   string        `json:"id"`
	FindingID            string        `json:"finding_id"`
	EnvironmentID        string        `json:"environment_id"`
	VerifierAdapter      string        `json:"verifier_adapter"`
	VerifierInputDigest  string        `json:"verifier_input_digest"`
	DiscoveryInputDigest string        `json:"discovery_input_digest"`
	Status               string        `json:"status"`
	ReasonCode           string        `json:"reason_code"`
	Observed             string        `json:"observed"`
	Expected             string        `json:"expected"`
	ArtifactDigest       string        `json:"artifact_digest,omitempty"`
	Checks               []EvidenceRef `json:"checks"`
}

type TriageDecision struct {
	SchemaVersion    string   `json:"schema_version"`
	FindingID        string   `json:"finding_id"`
	ProofID          string   `json:"proof_id"`
	AssetSensitivity string   `json:"asset_sensitivity"`
	Reachability     string   `json:"reachability"`
	TenantScope      string   `json:"tenant_scope"`
	Preconditions    []string `json:"preconditions"`
	ControlEvidence  []string `json:"control_evidence"`
	Unknowns         []string `json:"unknowns"`
	Severity         string   `json:"severity"`
	Priority         int      `json:"priority"`
	ReviewerStatus   string   `json:"reviewer_status"`
}

type PatchEvidence struct {
	SchemaVersion        string        `json:"schema_version"`
	FindingID            string        `json:"finding_id"`
	ProofID              string        `json:"proof_id"`
	PatchDigest          string        `json:"patch_digest"`
	Rationale            string        `json:"rationale"`
	ExploitRegression    bool          `json:"exploit_regression"`
	FunctionalTests      bool          `json:"functional_tests"`
	NegativeTests        bool          `json:"negative_tests"`
	PolicyDecision       string        `json:"policy_decision"`
	ReviewerStatus       string        `json:"reviewer_status"`
	RemainingRisk        string        `json:"remaining_risk"`
	RollbackInstructions string        `json:"rollback_instructions"`
	Evidence             []EvidenceRef `json:"evidence"`
}

type TrialReport struct {
	SchemaVersion  string         `json:"schema_version"`
	TrialID        string         `json:"trial_id"`
	ManifestDigest string         `json:"manifest_digest"`
	Metrics        map[string]any `json:"metrics"`
	Artifacts      []EvidenceRef  `json:"artifacts"`
}
