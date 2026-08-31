package risk

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func now() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) }

// trusted is the baseline: known user, known device, healthy posture, normal
// behaviour. It must score in the LOW band or the model is miscalibrated.
func trusted() Inputs {
	recent := now().Add(-time.Minute)
	enrolled := now().AddDate(0, 0, -60)
	score := 92
	return Inputs{
		SessionID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(), Now: now(),
		SessionAttested: true, DeviceTrustScore: &score, DeviceKeyProtection: "tpm",
		DeviceEnrolledAt: &enrolled, AgentLastHeartbeat: &recent,
		LoginHourTypical: true, BaselineEstablished: true,
		NetworkFamiliar: true, NetworkKnown: true,
		ResourceSensitivity: SensitivityInternal,
	}
}

func engine() *Engine { return NewEngine(DefaultWeights(), DefaultThresholds()) }

func hasFactor(a Assessment, code string) bool {
	for _, f := range a.Factors {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestTrustedSessionScoresLow(t *testing.T) {
	got := engine().Evaluate(trusted())

	if got.Level != LevelLow {
		t.Errorf("level = %s (score %d), want LOW\n%s", got.Level, got.Score, got.Explain())
	}
	if got.Action != ActionAllow {
		t.Errorf("action = %s, want ALLOW", got.Action)
	}
}

func TestFactorsAlwaysSumToTheScore(t *testing.T) {
	// The explanation an analyst reads must reconcile with the number.
	cases := map[string]func(Inputs) Inputs{
		"baseline":       func(in Inputs) Inputs { return in },
		"new device":     func(in Inputs) Inputs { in.DeviceFirstSeenForUser = true; return in },
		"unusual hour":   func(in Inputs) Inputs { in.LoginHourTypical = false; return in },
		"critical":       func(in Inputs) Inputs { in.ResourceSensitivity = SensitivityCritical; return in },
		"no baseline":    func(in Inputs) Inputs { in.BaselineEstablished = false; return in },
		"unattested":     func(in Inputs) Inputs { in.SessionAttested = false; return in },
		"everything bad": worstCase,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			got := engine().Evaluate(mutate(trusted()))

			total := 0
			for _, f := range got.Factors {
				total += f.Contribution
			}
			if total != got.Score {
				t.Errorf("factors sum to %d but score is %d\n%s", total, got.Score, got.Explain())
			}
		})
	}
}

func worstCase(in Inputs) Inputs {
	in.SessionAttested = false
	in.DeviceFirstSeenForUser = true
	in.LoginHourTypical = false
	in.AccessVolumeZScore = 9
	in.NetworkFamiliar = false
	in.ResourceSensitivity = SensitivityCritical
	in.RecentIncidents = 5
	in.RecentDenials = 9
	in.AnomalyScore = 1
	in.DeviceKeyProtection = "software"
	low := 5
	in.DeviceTrustScore = &low
	in.AgentLastHeartbeat = nil
	return in
}

func TestScoreIsClampedAndStillReconciles(t *testing.T) {
	got := engine().Evaluate(worstCase(trusted()))

	if got.Score != 100 {
		t.Errorf("score = %d, want 100 for a maximally bad session", got.Score)
	}
	total := 0
	for _, f := range got.Factors {
		total += f.Contribution
	}
	if total != 100 {
		t.Errorf("clamping broke the sum: factors total %d, score 100", total)
	}
	if got.Level != LevelCritical {
		t.Errorf("level = %s, want CRITICAL", got.Level)
	}
}

func TestEachSignalRaisesRisk(t *testing.T) {
	base := engine().Evaluate(trusted()).Score

	signals := map[string]func(Inputs) Inputs{
		"NEW_DEVICE":             func(in Inputs) Inputs { in.DeviceFirstSeenForUser = true; return in },
		"UNUSUAL_LOGIN_TIME":     func(in Inputs) Inputs { in.LoginHourTypical = false; return in },
		"ABNORMAL_ACCESS_VOLUME": func(in Inputs) Inputs { in.AccessVolumeZScore = 4; return in },
		"UNUSUAL_NETWORK":        func(in Inputs) Inputs { in.NetworkFamiliar = false; return in },
		"CRITICAL_RESOURCE":      func(in Inputs) Inputs { in.ResourceSensitivity = SensitivityCritical; return in },
		"AGENT_SILENT":           func(in Inputs) Inputs { in.AgentLastHeartbeat = nil; return in },
		"LOW_DEVICE_TRUST":       func(in Inputs) Inputs { v := 30; in.DeviceTrustScore = &v; return in },
		"RECENT_INCIDENT":        func(in Inputs) Inputs { in.RecentIncidents = 2; return in },
	}
	for code, mutate := range signals {
		t.Run(code, func(t *testing.T) {
			got := engine().Evaluate(mutate(trusted()))

			if got.Score <= base {
				t.Errorf("score %d did not rise above the baseline %d", got.Score, base)
			}
			if !hasFactor(got, code) {
				t.Errorf("factor %s is absent: %v", code, got.Codes())
			}
		})
	}
}

func TestResourceSensitivityChangesTheAnswer(t *testing.T) {
	// The same behaviour must be worth more against a critical resource. This
	// is the contextual part of the trust model.
	in := trusted()
	in.DeviceFirstSeenForUser = true
	in.LoginHourTypical = false

	internal := engine().Evaluate(in)
	in.ResourceSensitivity = SensitivityCritical
	critical := engine().Evaluate(in)

	if critical.Score <= internal.Score {
		t.Errorf("critical resource scored %d, internal %d", critical.Score, internal.Score)
	}
}

func TestUnattestedSessionDominates(t *testing.T) {
	// A session without device proof should not exist; if one does, it must be
	// the largest single contribution.
	in := trusted()
	in.SessionAttested = false

	got := engine().Evaluate(in)

	if got.Factors[0].Code != "UNATTESTED_SESSION" {
		t.Errorf("largest factor = %s, want UNATTESTED_SESSION", got.Factors[0].Code)
	}
}

func TestMissingBaselineDoesNotManufactureAlarm(t *testing.T) {
	// A new joiner with no history must not be treated as an intruder.
	in := trusted()
	in.BaselineEstablished = false
	in.LoginHourTypical = false
	in.AccessVolumeZScore = 8

	got := engine().Evaluate(in)

	if hasFactor(got, "UNUSUAL_LOGIN_TIME") || hasFactor(got, "ABNORMAL_ACCESS_VOLUME") {
		t.Errorf("behavioural deviation was scored without a baseline: %v", got.Codes())
	}
	if got.Level != LevelLow {
		t.Errorf("level = %s (score %d), want LOW for a user with no history", got.Level, got.Score)
	}
}

func TestAnomalyModelCannotDominate(t *testing.T) {
	// The model informs the score; it does not decide it.
	in := trusted()
	in.AnomalyScore = 1.0

	got := engine().Evaluate(in)

	for _, f := range got.Factors {
		if f.Code == "BEHAVIOUR_ANOMALY" && f.Contribution > 10 {
			t.Errorf("anomaly contributed %d points; it must stay bounded", f.Contribution)
		}
	}
	if got.Level == LevelCritical {
		t.Error("the anomaly model alone drove the session to CRITICAL")
	}
}

func TestFactorsAreOrderedBySignificance(t *testing.T) {
	got := engine().Evaluate(worstCase(trusted()))

	for i := 1; i < len(got.Factors); i++ {
		if got.Factors[i-1].Contribution < got.Factors[i].Contribution {
			t.Fatalf("factors are not ordered largest first: %+v", got.Factors)
		}
	}
}

func TestThresholdsAndActions(t *testing.T) {
	thresholds := DefaultThresholds()

	cases := []struct {
		score  int
		level  Level
		action Action
	}{
		{0, LevelLow, ActionAllow},
		{30, LevelLow, ActionAllow},
		{31, LevelMedium, ActionAllowMonitor},
		{50, LevelMedium, ActionAllowMonitor},
		{51, LevelElevated, ActionVerify},
		{70, LevelElevated, ActionVerify},
		{71, LevelHigh, ActionStepUpMFA},
		{85, LevelHigh, ActionStepUpMFA},
		{86, LevelCritical, ActionIsolate},
		{100, LevelCritical, ActionIsolate},
	}
	for _, tt := range cases {
		if got := thresholds.Level(tt.score); got != tt.level {
			t.Errorf("Level(%d) = %s, want %s", tt.score, got, tt.level)
		}
		if got := thresholds.Level(tt.score).RecommendedAction(); got != tt.action {
			t.Errorf("action for %d = %s, want %s", tt.score, got, tt.action)
		}
	}
}

func TestThresholdsValidate(t *testing.T) {
	if err := DefaultThresholds().Validate(); err != nil {
		t.Fatalf("shipped thresholds are invalid: %v", err)
	}
	for _, bad := range []Thresholds{
		{50, 30, 70, 85}, {30, 30, 70, 85}, {30, 50, 70, 100}, {0, 50, 70, 85},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("invalid thresholds %+v were accepted", bad)
		}
	}
}

func TestWeightsValidate(t *testing.T) {
	if err := DefaultWeights().Validate(); err != nil {
		t.Fatalf("shipped weights are invalid: %v", err)
	}
	if err := (Weights{Device: -1}).Validate(); err == nil {
		t.Error("a negative weight was accepted")
	}
	if err := (Weights{Device: 50}).Validate(); err == nil {
		t.Error("an unbounded weight was accepted")
	}
}

func TestWeightsScaleContributions(t *testing.T) {
	in := trusted()
	in.DeviceFirstSeenForUser = true

	normal := NewEngine(DefaultWeights(), DefaultThresholds()).Evaluate(in)
	weights := DefaultWeights()
	weights.Device = 2
	doubled := NewEngine(weights, DefaultThresholds()).Evaluate(in)

	if doubled.Score <= normal.Score {
		t.Errorf("doubling the device weight did not raise the score: %d vs %d",
			doubled.Score, normal.Score)
	}
}

func TestExplainReconcilesWithTheScore(t *testing.T) {
	got := engine().Evaluate(worstCase(trusted()))
	explanation := got.Explain()

	if explanation == "" {
		t.Fatal("Explain produced nothing")
	}
	if got.Score != 100 {
		t.Fatalf("unexpected score %d", got.Score)
	}
	if want := "= 100"; !contains(explanation, want) {
		t.Errorf("explanation does not close with the score:\n%s", explanation)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
