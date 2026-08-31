// Package policy turns a risk assessment into an access decision.
//
// Policies are data, not code: conditions and actions are stored, versioned and
// immutable, so every decision can cite the exact policy text that was in force
// when it was made (spec §25). Editing a policy creates a new version; it never
// rewrites the one a past decision referenced.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/netra/backend/internal/risk"
)

// Decision is what the policy engine concluded.
type Decision string

const (
	DecisionAllow        Decision = "ALLOW"
	DecisionAllowMonitor Decision = "ALLOW_MONITOR"
	DecisionVerify       Decision = "VERIFY"
	DecisionStepUpMFA    Decision = "STEP_UP_MFA"
	DecisionRestrict     Decision = "RESTRICT"
	DecisionIsolate      Decision = "ISOLATE"
	DecisionDeny         Decision = "DENY"
)

var knownDecisions = map[Decision]bool{
	DecisionAllow: true, DecisionAllowMonitor: true, DecisionVerify: true,
	DecisionStepUpMFA: true, DecisionRestrict: true, DecisionIsolate: true,
	DecisionDeny: true,
}

// severity orders decisions from least to most restrictive, so that when
// several policies match, the most restrictive wins.
var severity = map[Decision]int{
	DecisionAllow: 0, DecisionAllowMonitor: 1, DecisionVerify: 2,
	DecisionStepUpMFA: 3, DecisionRestrict: 4, DecisionIsolate: 5, DecisionDeny: 6,
}

// FailMode is what to do when the control plane cannot be reached (spec §29).
type FailMode string

const (
	// FailOpen keeps working on the cached policy. Suitable for ordinary
	// internal applications where an outage must not stop work.
	FailOpen FailMode = "fail-open"
	// FailClosed refuses access. Suitable where the cost of wrongful access
	// exceeds the cost of downtime.
	FailClosed FailMode = "fail-closed"
	// FailSafe keeps low-sensitivity access and restricts the rest.
	FailSafe FailMode = "fail-safe"
)

// ErrInvalidPolicy wraps every rejection caused by the policy definition.
var ErrInvalidPolicy = errors.New("invalid policy")

// Conditions is when a policy applies. An empty field means "any", so a policy
// states only what it actually constrains.
type Conditions struct {
	MinRisk             *int     `json:"min_risk,omitempty"`
	MaxRisk             *int     `json:"max_risk,omitempty"`
	Levels              []string `json:"levels,omitempty"`
	ResourceSensitivity []string `json:"resource_sensitivity,omitempty"`
	// RequireFactors matches only when every named risk factor is present, so a
	// policy can target a specific combination rather than a bare score.
	RequireFactors []string `json:"require_factors,omitempty"`
}

// Actions is what happens when a policy matches.
type Actions struct {
	Decision       Decision `json:"decision"`
	CreateIncident bool     `json:"create_incident,omitempty"`
	AlertSOC       bool     `json:"alert_soc,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// Policy is one versioned rule.
type Policy struct {
	ID          uuid.UUID  `json:"id"`
	PolicyID    string     `json:"policy_id"`
	Version     int        `json:"version"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Priority    int        `json:"priority"`
	Enabled     bool       `json:"enabled"`
	Conditions  Conditions `json:"conditions"`
	Actions     Actions    `json:"actions"`
	FailMode    FailMode   `json:"fail_mode"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Validate rejects a policy that could not produce a meaningful decision.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.PolicyID) == "" || len(p.PolicyID) > 64 {
		return fmt.Errorf("%w: policy_id must be 1..64 characters", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 128 {
		return fmt.Errorf("%w: name must be 1..128 characters", ErrInvalidPolicy)
	}
	if !knownDecisions[p.Actions.Decision] {
		return fmt.Errorf("%w: unknown decision %q", ErrInvalidPolicy, p.Actions.Decision)
	}
	switch p.FailMode {
	case FailOpen, FailClosed, FailSafe:
	default:
		return fmt.Errorf("%w: fail_mode must be fail-open, fail-closed or fail-safe", ErrInvalidPolicy)
	}

	c := p.Conditions
	if c.MinRisk != nil && (*c.MinRisk < 0 || *c.MinRisk > 100) {
		return fmt.Errorf("%w: min_risk must be 0..100", ErrInvalidPolicy)
	}
	if c.MaxRisk != nil && (*c.MaxRisk < 0 || *c.MaxRisk > 100) {
		return fmt.Errorf("%w: max_risk must be 0..100", ErrInvalidPolicy)
	}
	if c.MinRisk != nil && c.MaxRisk != nil && *c.MinRisk > *c.MaxRisk {
		return fmt.Errorf("%w: min_risk must not exceed max_risk", ErrInvalidPolicy)
	}
	// A policy with no conditions at all matches everything, which is almost
	// certainly a mistake rather than an intent.
	if c.MinRisk == nil && c.MaxRisk == nil && len(c.Levels) == 0 &&
		len(c.ResourceSensitivity) == 0 && len(c.RequireFactors) == 0 {
		return fmt.Errorf("%w: a policy must constrain something", ErrInvalidPolicy)
	}
	return nil
}

// Request is the context a decision is made about.
type Request struct {
	Assessment          risk.Assessment
	ResourceSensitivity string
	ResourceID          *uuid.UUID
	// Degraded marks an evaluation made without a live control plane, which
	// selects the fail mode instead of the normal conditions.
	Degraded bool
}

// Result is a policy decision with its justification.
type Result struct {
	Decision       Decision      `json:"decision"`
	Reason         string        `json:"reason"`
	PolicyID       string        `json:"policy_id,omitempty"`
	PolicyVersion  int           `json:"policy_version,omitempty"`
	CreateIncident bool          `json:"create_incident"`
	AlertSOC       bool          `json:"alert_soc"`
	Message        string        `json:"message,omitempty"`
	Matched        []string      `json:"matched_policies,omitempty"`
	EvaluatedAt    time.Time     `json:"evaluated_at"`
	Latency        time.Duration `json:"-"`
}

// Engine evaluates policies against a request.
type Engine struct {
	policies []Policy
}

// NewEngine builds an engine over a set of policies, most specific first.
func NewEngine(policies []Policy) *Engine {
	active := make([]Policy, 0, len(policies))
	for _, candidate := range policies {
		if candidate.Enabled {
			active = append(active, candidate)
		}
	}
	// Lower priority number evaluates first; ties break on policy id so the
	// outcome does not depend on the order rows came back from the database.
	sort.SliceStable(active, func(i, j int) bool {
		if active[i].Priority != active[j].Priority {
			return active[i].Priority < active[j].Priority
		}
		return active[i].PolicyID < active[j].PolicyID
	})
	return &Engine{policies: active}
}

// Evaluate returns the decision for a request.
//
// Every matching policy is considered and the most restrictive outcome wins.
// First-match-wins would let a permissive policy that happens to sort earlier
// mask a restrictive one that also applies, which is the wrong failure
// direction for a security control.
func (e *Engine) Evaluate(request Request) Result {
	started := time.Now()

	if request.Degraded {
		return e.degraded(request, started)
	}

	result := Result{
		Decision:    DecisionAllow,
		Reason:      "no policy matched; default allow",
		EvaluatedAt: started.UTC(),
	}

	for _, candidate := range e.policies {
		if !matches(candidate.Conditions, request) {
			continue
		}
		result.Matched = append(result.Matched, fmt.Sprintf("%s@v%d", candidate.PolicyID, candidate.Version))

		if severity[candidate.Actions.Decision] >= severity[result.Decision] {
			result.Decision = candidate.Actions.Decision
			result.Reason = candidate.Name
			result.PolicyID = candidate.PolicyID
			result.PolicyVersion = candidate.Version
			result.Message = candidate.Actions.Message
		}
		// Incident and alert actions accumulate across every match: a policy
		// asking for an incident must get one even if a more restrictive
		// policy determined the decision.
		result.CreateIncident = result.CreateIncident || candidate.Actions.CreateIncident
		result.AlertSOC = result.AlertSOC || candidate.Actions.AlertSOC
	}

	result.Latency = time.Since(started)
	return result
}

// degraded decides without a live control plane, using the fail mode of the
// most restrictive applicable policy.
func (e *Engine) degraded(request Request, started time.Time) Result {
	mode := FailSafe
	for _, candidate := range e.policies {
		if matches(candidate.Conditions, request) && candidate.FailMode == FailClosed {
			mode = FailClosed
			break
		}
	}

	result := Result{EvaluatedAt: started.UTC()}
	switch mode {
	case FailClosed:
		result.Decision = DecisionDeny
		result.Reason = "control plane unavailable; policy is fail-closed"
	case FailOpen:
		result.Decision = DecisionAllow
		result.Reason = "control plane unavailable; policy is fail-open"
	default:
		// Fail-safe: ordinary access continues, sensitive access does not.
		// An outage must never silently unlock a critical resource, and must
		// never lock an entire fleet out of routine work either.
		if isSensitive(request.ResourceSensitivity) {
			result.Decision = DecisionRestrict
			result.Reason = "control plane unavailable; sensitive access restricted"
		} else {
			result.Decision = DecisionAllowMonitor
			result.Reason = "control plane unavailable; continuing on cached policy"
		}
	}
	result.Latency = time.Since(started)
	return result
}

func matches(conditions Conditions, request Request) bool {
	score := request.Assessment.Score

	if conditions.MinRisk != nil && score < *conditions.MinRisk {
		return false
	}
	if conditions.MaxRisk != nil && score > *conditions.MaxRisk {
		return false
	}
	if len(conditions.Levels) > 0 && !containsFold(conditions.Levels, string(request.Assessment.Level)) {
		return false
	}
	if len(conditions.ResourceSensitivity) > 0 &&
		!containsFold(conditions.ResourceSensitivity, request.ResourceSensitivity) {
		return false
	}
	if len(conditions.RequireFactors) > 0 {
		present := map[string]bool{}
		for _, factor := range request.Assessment.Factors {
			present[factor.Code] = true
		}
		for _, required := range conditions.RequireFactors {
			if !present[strings.ToUpper(required)] {
				return false
			}
		}
	}
	return true
}

func containsFold(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if strings.EqualFold(candidate, needle) {
			return true
		}
	}
	return false
}

func isSensitive(sensitivity string) bool {
	return strings.EqualFold(sensitivity, "SENSITIVE") || strings.EqualFold(sensitivity, "CRITICAL")
}
