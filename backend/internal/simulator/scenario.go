// Package simulator generates synthetic security activity for demonstration
// and testing.
//
// The rule that governs this package (spec §50): the simulator produces real
// events that travel the real ingest path, the real risk engine and the real
// policy engine. It never writes a risk score, never opens an incident
// directly, and never touches the console's state. If the dashboard shows a
// session at 94, the risk engine put it there.
//
// Everything it creates is marked SIMULATOR at the source, so simulated
// activity is always distinguishable from a real endpoint's.
package simulator

import (
	"fmt"
	"time"
)

// Scenario is one demonstrable situation.
type Scenario struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// Expectation states what the operator should see. It is a description of
	// intent, not a promise: the actual score is whatever the engine computes.
	Expectation string `json:"expectation"`
	steps       []step
}

// step is one action within a scenario.
type step struct {
	label string
	run   func(*run) error
}

// Catalogue is the scenario set offered to an operator (spec §42).
func Catalogue() []Scenario {
	return []Scenario{
		normalSession(),
		newDevice(),
		unusualLoginTime(),
		sensitiveAccess(),
		abnormalVolume(),
		networkAnomaly(),
		compromisedSession(),
	}
}

// Find returns a scenario by name.
func Find(name string) (Scenario, bool) {
	for _, candidate := range Catalogue() {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return Scenario{}, false
}

// StepResult is what one step did and what the platform made of it.
type StepResult struct {
	Step        string    `json:"step"`
	At          time.Time `json:"at"`
	EventsAdded int       `json:"events_added"`
	// Score and Level come from the risk engine, not from the scenario.
	Score      *int     `json:"risk_score,omitempty"`
	Level      string   `json:"risk_level,omitempty"`
	Decision   string   `json:"decision,omitempty"`
	Factors    []string `json:"factors,omitempty"`
	IncidentID string   `json:"incident_id,omitempty"`
}

// Result is a completed scenario run.
type Result struct {
	Scenario   string       `json:"scenario"`
	SessionID  string       `json:"session_id"`
	UserName   string       `json:"user"`
	DeviceName string       `json:"device"`
	StartedAt  time.Time    `json:"started_at"`
	Steps      []StepResult `json:"steps"`
	FinalScore int          `json:"final_score"`
	FinalLevel string       `json:"final_level"`
	Decision   string       `json:"final_decision"`
	IncidentID string       `json:"incident_id,omitempty"`
}

// Summary renders a run the way the demonstration narrates it.
func (r Result) Summary() string {
	out := fmt.Sprintf("%s — %s on %s\n", r.Scenario, r.UserName, r.DeviceName)
	for _, step := range r.Steps {
		score := "—"
		if step.Score != nil {
			score = fmt.Sprintf("%d", *step.Score)
		}
		out += fmt.Sprintf("  %-34s risk %-4s %-9s %s\n",
			step.Step, score, step.Level, step.Decision)
	}
	return out
}
