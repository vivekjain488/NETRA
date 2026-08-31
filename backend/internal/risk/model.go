// Package risk turns session context into an explainable risk score.
//
// The model is deliberately transparent: every signal contributes a fixed
// number of points, the score is their clamped sum, and the factors shown to
// an analyst therefore reconcile with the number by construction rather than
// by approximation. Nothing here is claimed to be statistically optimal — the
// properties that matter for a security control are that it is explainable,
// deterministic, fast, and tunable (spec §14).
//
// Machine learning contributes at most one input to this model, as a bounded
// anomaly signal computed asynchronously. It never replaces the deterministic
// signals and never sits in the request path.
package risk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Dimension groups signals for display (spec §13).
type Dimension string

const (
	DimIdentity  Dimension = "IDENTITY"
	DimDevice    Dimension = "DEVICE"
	DimBehaviour Dimension = "BEHAVIOUR"
	DimNetwork   Dimension = "NETWORK"
	DimResource  Dimension = "RESOURCE"
	DimHistory   Dimension = "HISTORY"
)

// Level is a risk band.
type Level string

const (
	LevelLow      Level = "LOW"
	LevelMedium   Level = "MEDIUM"
	LevelElevated Level = "ELEVATED"
	LevelHigh     Level = "HIGH"
	LevelCritical Level = "CRITICAL"
)

// Action is the response the risk engine recommends. The policy engine decides
// what is actually applied; this is advice, not enforcement (spec §17).
type Action string

const (
	ActionAllow        Action = "ALLOW"
	ActionAllowMonitor Action = "ALLOW_MONITOR"
	ActionVerify       Action = "VERIFY"
	ActionStepUpMFA    Action = "STEP_UP_MFA"
	ActionRestrict     Action = "RESTRICT"
	ActionIsolate      Action = "ISOLATE"
)

// Thresholds are the inclusive upper bounds of each band.
type Thresholds struct {
	Low      int
	Medium   int
	Elevated int
	High     int
}

// DefaultThresholds matches the shipped configuration (spec §19).
func DefaultThresholds() Thresholds {
	return Thresholds{Low: 30, Medium: 50, Elevated: 70, High: 85}
}

// Validate checks the bands are strictly increasing and in range.
func (t Thresholds) Validate() error {
	if t.Low <= 0 || t.Low >= t.Medium || t.Medium >= t.Elevated ||
		t.Elevated >= t.High || t.High >= 100 {
		return fmt.Errorf("risk thresholds must satisfy 0 < low < medium < elevated < high < 100, got %d/%d/%d/%d",
			t.Low, t.Medium, t.Elevated, t.High)
	}
	return nil
}

// Level maps a score onto its band.
func (t Thresholds) Level(score int) Level {
	switch {
	case score <= t.Low:
		return LevelLow
	case score <= t.Medium:
		return LevelMedium
	case score <= t.Elevated:
		return LevelElevated
	case score <= t.High:
		return LevelHigh
	default:
		return LevelCritical
	}
}

// RecommendedAction maps a band onto a response.
func (l Level) RecommendedAction() Action {
	switch l {
	case LevelLow:
		return ActionAllow
	case LevelMedium:
		return ActionAllowMonitor
	case LevelElevated:
		return ActionVerify
	case LevelHigh:
		return ActionStepUpMFA
	default:
		return ActionIsolate
	}
}

// Weights scale each dimension's contribution. They are configuration, so a
// deployment can weigh device trust differently from behaviour without a code
// change (spec §14).
type Weights struct {
	Identity  float64
	Device    float64
	Behaviour float64
	Network   float64
	Resource  float64
	History   float64
}

// DefaultWeights is the shipped model: every dimension counted at face value.
func DefaultWeights() Weights {
	return Weights{Identity: 1, Device: 1, Behaviour: 1, Network: 1, Resource: 1, History: 1}
}

// Validate rejects weights that would silence a dimension entirely or let one
// dominate beyond recognition.
func (w Weights) Validate() error {
	for name, value := range map[string]float64{
		"identity": w.Identity, "device": w.Device, "behaviour": w.Behaviour,
		"network": w.Network, "resource": w.Resource, "history": w.History,
	} {
		if value < 0 || value > 5 {
			return fmt.Errorf("risk weight for %s must be between 0 and 5, got %.2f", name, value)
		}
	}
	return nil
}

func (w Weights) forDimension(d Dimension) float64 {
	switch d {
	case DimIdentity:
		return w.Identity
	case DimDevice:
		return w.Device
	case DimBehaviour:
		return w.Behaviour
	case DimNetwork:
		return w.Network
	case DimResource:
		return w.Resource
	case DimHistory:
		return w.History
	default:
		return 1
	}
}

// Factor is one contribution to the score.
type Factor struct {
	Code         string    `json:"code"`
	Label        string    `json:"label"`
	Dimension    Dimension `json:"dimension"`
	Contribution int       `json:"contribution"`
	Detail       string    `json:"detail,omitempty"`
}

// Assessment is a scored session.
type Assessment struct {
	SessionID    uuid.UUID         `json:"session_id"`
	Score        int               `json:"score"`
	Level        Level             `json:"level"`
	Action       Action            `json:"recommended_action"`
	Factors      []Factor          `json:"factors"`
	Dimensions   map[Dimension]int `json:"dimensions"`
	ComputedAt   time.Time         `json:"computed_at"`
	ModelVersion string            `json:"model_version"`
	TriggerEvent string            `json:"trigger_event,omitempty"`
}

// Codes returns the factor codes, which is what an incident summary lists.
func (a Assessment) Codes() []string {
	codes := make([]string, 0, len(a.Factors))
	for _, f := range a.Factors {
		codes = append(codes, f.Code)
	}
	return codes
}

// Explain renders the score the way it is shown to an analyst (spec §20).
func (a Assessment) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "RISK: %d/100 (%s)\n", a.Score, a.Level)
	for _, f := range a.Factors {
		fmt.Fprintf(&b, "  +%d %s\n", f.Contribution, f.Label)
	}
	fmt.Fprintf(&b, "  = %d", a.Score)
	return b.String()
}

// sortFactors orders factors by contribution, largest first, so the reason a
// score moved is the first thing read.
func sortFactors(factors []Factor) {
	sort.SliceStable(factors, func(i, j int) bool {
		if factors[i].Contribution != factors[j].Contribution {
			return factors[i].Contribution > factors[j].Contribution
		}
		return factors[i].Code < factors[j].Code
	})
}
