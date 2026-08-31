package policy

import (
	"testing"

	"github.com/netra/backend/internal/risk"
)

func assessment(score int, level risk.Level, codes ...string) risk.Assessment {
	a := risk.Assessment{Score: score, Level: level}
	for _, code := range codes {
		a.Factors = append(a.Factors, risk.Factor{Code: code})
	}
	return a
}

func defaults() *Engine { return NewEngine(DefaultPolicies()) }

func TestDefaultPoliciesAreValid(t *testing.T) {
	for _, p := range DefaultPolicies() {
		if err := p.Validate(); err != nil {
			t.Errorf("shipped policy %s is invalid: %v", p.PolicyID, err)
		}
	}
}

func TestRiskBandsMapToDecisions(t *testing.T) {
	cases := []struct {
		level risk.Level
		score int
		want  Decision
	}{
		{risk.LevelLow, 12, DecisionAllow},
		{risk.LevelMedium, 40, DecisionAllowMonitor},
		{risk.LevelElevated, 60, DecisionVerify},
		{risk.LevelHigh, 78, DecisionStepUpMFA},
		{risk.LevelCritical, 94, DecisionIsolate},
	}
	for _, tt := range cases {
		t.Run(string(tt.level), func(t *testing.T) {
			got := defaults().Evaluate(Request{Assessment: assessment(tt.score, tt.level)})

			if got.Decision != tt.want {
				t.Errorf("decision = %s, want %s (matched %v)", got.Decision, tt.want, got.Matched)
			}
		})
	}
}

func TestMostRestrictiveMatchWins(t *testing.T) {
	// First-match-wins would let a permissive policy that happens to sort
	// earlier mask a restrictive one that also applies.
	got := defaults().Evaluate(Request{
		Assessment:          assessment(60, risk.LevelElevated),
		ResourceSensitivity: "CRITICAL",
	})

	if got.Decision != DecisionRestrict {
		t.Errorf("decision = %s, want RESTRICT (matched %v)", got.Decision, got.Matched)
	}
	if len(got.Matched) < 2 {
		t.Errorf("expected several policies to match, got %v", got.Matched)
	}
}

func TestCriticalResourceRaisesTheAnswer(t *testing.T) {
	elevated := assessment(60, risk.LevelElevated)

	internal := defaults().Evaluate(Request{Assessment: elevated, ResourceSensitivity: "INTERNAL"})
	critical := defaults().Evaluate(Request{Assessment: elevated, ResourceSensitivity: "CRITICAL"})

	if severity[critical.Decision] <= severity[internal.Decision] {
		t.Errorf("critical resource decided %s, internal %s; critical must be stricter",
			critical.Decision, internal.Decision)
	}
}

func TestFactorCombinationMatchesWithoutAHighScore(t *testing.T) {
	// A policy can target a specific combination rather than a bare score.
	got := defaults().Evaluate(Request{
		Assessment:          assessment(35, risk.LevelMedium, "NEW_DEVICE"),
		ResourceSensitivity: "SENSITIVE",
	})

	if got.Decision != DecisionStepUpMFA {
		t.Errorf("decision = %s, want STEP_UP_MFA (matched %v)", got.Decision, got.Matched)
	}
}

func TestUnattestedSessionIsDenied(t *testing.T) {
	got := defaults().Evaluate(Request{
		Assessment: assessment(40, risk.LevelMedium, "UNATTESTED_SESSION"),
	})

	if got.Decision != DecisionDeny {
		t.Errorf("decision = %s, want DENY", got.Decision)
	}
	if !got.CreateIncident {
		t.Error("an unattested session did not open an incident")
	}
}

func TestIncidentActionsAccumulateAcrossMatches(t *testing.T) {
	// A policy asking for an incident must get one even when a more
	// restrictive policy determined the decision.
	got := defaults().Evaluate(Request{
		Assessment:          assessment(94, risk.LevelCritical, "NEW_DEVICE"),
		ResourceSensitivity: "CRITICAL",
	})

	if !got.CreateIncident || !got.AlertSOC {
		t.Errorf("incident=%v alert=%v, want both set (matched %v)",
			got.CreateIncident, got.AlertSOC, got.Matched)
	}
}

func TestNoMatchAllowsButSaysSo(t *testing.T) {
	got := NewEngine(nil).Evaluate(Request{Assessment: assessment(50, risk.LevelMedium)})

	if got.Decision != DecisionAllow {
		t.Errorf("decision = %s, want ALLOW", got.Decision)
	}
	if got.Reason == "" {
		t.Error("an unmatched decision carries no reason")
	}
}

func TestDisabledPoliciesAreIgnored(t *testing.T) {
	policies := DefaultPolicies()
	for i := range policies {
		policies[i].Enabled = false
	}

	got := NewEngine(policies).Evaluate(Request{Assessment: assessment(94, risk.LevelCritical)})

	if got.Decision != DecisionAllow {
		t.Errorf("a disabled policy was applied: %s", got.Decision)
	}
}

func TestDegradedModeRespectsFailMode(t *testing.T) {
	cases := []struct {
		name        string
		score       int
		level       risk.Level
		sensitivity string
		want        Decision
	}{
		// Fail-safe: routine work continues, sensitive access does not. An
		// outage must neither unlock a critical resource nor stop a fleet.
		{"routine access continues", 12, risk.LevelLow, "INTERNAL", DecisionAllowMonitor},
		{"sensitive access restricted", 12, risk.LevelLow, "SENSITIVE", DecisionRestrict},
		{"critical access restricted", 12, risk.LevelLow, "CRITICAL", DecisionRestrict},
		// When a fail-closed policy applies, it denies outright: at critical
		// risk on a critical resource, an outage is not a reason to proceed.
		{"fail-closed policy denies", 94, risk.LevelCritical, "CRITICAL", DecisionDeny},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := defaults().Evaluate(Request{
				Assessment:          assessment(tt.score, tt.level),
				ResourceSensitivity: tt.sensitivity,
				Degraded:            true,
			})

			if got.Decision != tt.want {
				t.Errorf("decision = %s, want %s (%s)", got.Decision, tt.want, got.Reason)
			}
			if got.Reason == "" {
				t.Error("a degraded decision carries no reason")
			}
		})
	}
}

func TestEvaluationIsDeterministic(t *testing.T) {
	// Ties must not depend on the order rows came back from the database.
	request := Request{Assessment: assessment(94, risk.LevelCritical, "NEW_DEVICE"),
		ResourceSensitivity: "CRITICAL"}

	first := defaults().Evaluate(request)
	for i := 0; i < 20; i++ {
		if got := defaults().Evaluate(request); got.Decision != first.Decision {
			t.Fatalf("decision varied between runs: %s then %s", first.Decision, got.Decision)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	valid := DefaultPolicies()[0]

	mutations := map[string]func(Policy) Policy{
		"no policy id":      func(p Policy) Policy { p.PolicyID = ""; return p },
		"no name":           func(p Policy) Policy { p.Name = ""; return p },
		"unknown decision":  func(p Policy) Policy { p.Actions.Decision = "MAYBE"; return p },
		"unknown fail mode": func(p Policy) Policy { p.FailMode = "shrug"; return p },
		// A policy with no conditions matches everything, which is almost
		// certainly a mistake rather than an intent.
		"no conditions": func(p Policy) Policy { p.Conditions = Conditions{}; return p },
		"inverted range": func(p Policy) Policy {
			min, max := 90, 10
			p.Conditions = Conditions{MinRisk: &min, MaxRisk: &max}
			return p
		},
		"out of range": func(p Policy) Policy {
			min := 900
			p.Conditions = Conditions{MinRisk: &min}
			return p
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := mutate(valid).Validate(); err == nil {
				t.Errorf("an invalid policy (%s) was accepted", name)
			}
		})
	}
}

func TestLatencyIsMeasured(t *testing.T) {
	// Policy evaluation sits in the access path, so its cost must be visible.
	got := defaults().Evaluate(Request{Assessment: assessment(50, risk.LevelMedium)})

	if got.Latency <= 0 {
		t.Error("policy evaluation reported no latency")
	}
}
