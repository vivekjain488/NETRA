package posture

import (
	"testing"
	"time"
)

func ptr(b bool) *bool { return &b }

func now() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) }

func healthyContext() DeviceContext {
	recent := now().Add(-time.Minute)
	return DeviceContext{
		Active:          true,
		KeyProtection:   "tpm",
		AgentVersion:    "0.1.0",
		ExpectedAgent:   "0.1.0",
		LastHeartbeatAt: &recent,
		Now:             now(),
	}
}

func healthySignals() Signals {
	return Signals{
		DiskEncryption: ptr(true),
		SecureBoot:     ptr(true),
		Firewall:       ptr(true),
		ScreenLock:     ptr(true),
		AntiMalware:    ptr(true),
		OSName:         "windows",
		OSVersion:      "11",
	}
}

func factorByCode(t *testing.T, a Assessment, code string) Factor {
	t.Helper()
	for _, f := range a.Factors {
		if f.Code == code {
			return f
		}
	}
	t.Fatalf("assessment has no factor %q", code)
	return Factor{}
}

func TestDefaultWeightsAreValid(t *testing.T) {
	if err := DefaultWeights().Validate(); err != nil {
		t.Fatalf("the shipped weights are invalid: %v", err)
	}
}

func TestWeightsMustSumToOneHundred(t *testing.T) {
	// Otherwise the score stops being interpretable as a percentage.
	w := DefaultWeights()
	w.Firewall += 5

	if err := w.Validate(); err == nil {
		t.Error("weights summing to 105 were accepted")
	}
}

func TestWeightsRejectNegatives(t *testing.T) {
	w := DefaultWeights()
	w.Firewall = -10
	w.DiskEncryption += 10

	if err := w.Validate(); err == nil {
		t.Error("a negative weight was accepted")
	}
}

func TestFullyCompliantDeviceScoresOneHundred(t *testing.T) {
	got := Evaluate(healthySignals(), healthyContext(), DefaultWeights())

	if got.Score != 100 {
		t.Errorf("score = %d, want 100 (factors %+v)", got.Score, got.Factors)
	}
}

func TestFactorsAlwaysSumToTheScore(t *testing.T) {
	// The explanation shown to an analyst must reconcile with the number.
	cases := map[string]struct {
		signals Signals
		context DeviceContext
	}{
		"fully compliant":  {healthySignals(), healthyContext()},
		"nothing reported": {Signals{}, healthyContext()},
		"partial": {
			Signals{DiskEncryption: ptr(true), Firewall: ptr(false), OSName: "macos", OSVersion: "26"},
			healthyContext(),
		},
		"inactive device": {healthySignals(), DeviceContext{Now: now()}},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(tt.signals, tt.context, DefaultWeights())

			total := 0
			for _, f := range got.Factors {
				total += f.Contribution
			}
			if total != got.Score {
				t.Errorf("factors sum to %d but score is %d", total, got.Score)
			}
		})
	}
}

func TestUnknownSignalsScoreZeroNotFull(t *testing.T) {
	// Unverifiable is not the same as safe. A collector that failed to run must
	// not look like one that found a control enabled.
	got := Evaluate(Signals{}, healthyContext(), DefaultWeights())

	encryption := factorByCode(t, got, "DISK_ENCRYPTION")
	if encryption.Contribution != 0 {
		t.Errorf("unreported disk encryption contributed %d, want 0", encryption.Contribution)
	}
	if encryption.Detail == "" {
		t.Error("an unreported signal has no explanation")
	}
}

func TestReportedFalseAndUnreportedAreDistinguishable(t *testing.T) {
	unreported := Evaluate(Signals{}, healthyContext(), DefaultWeights())
	disabled := Evaluate(Signals{DiskEncryption: ptr(false)}, healthyContext(), DefaultWeights())

	a := factorByCode(t, unreported, "DISK_ENCRYPTION").Detail
	b := factorByCode(t, disabled, "DISK_ENCRYPTION").Detail
	if a == b {
		t.Errorf("an unreported control and a disabled one read identically: %q", a)
	}
}

func TestHardwareBackedKeyScoresAboveSoftware(t *testing.T) {
	// A software key is a genuine identity, but it can be copied by anything
	// running with the agent's privileges.
	hardware := healthyContext()
	software := healthyContext()
	software.KeyProtection = "software"

	hardwareScore := Evaluate(healthySignals(), hardware, DefaultWeights()).Score
	softwareScore := Evaluate(healthySignals(), software, DefaultWeights()).Score

	if softwareScore >= hardwareScore {
		t.Errorf("software key scored %d, hardware %d; hardware must score higher",
			softwareScore, hardwareScore)
	}
}

func TestInactiveDeviceLosesItsIdentityFactor(t *testing.T) {
	context := healthyContext()
	context.Active = false

	got := Evaluate(healthySignals(), context, DefaultWeights())

	if identity := factorByCode(t, got, "DEVICE_IDENTITY"); identity.Contribution != 0 {
		t.Errorf("an inactive device scored %d for identity, want 0", identity.Contribution)
	}
}

func TestSilentAgentLosesItsHealthFactor(t *testing.T) {
	// Silence is a signal: a device whose agent stopped reporting is no longer
	// under observation and should not keep conferring trust.
	tests := map[string]DeviceContext{
		"never reported": func() DeviceContext { c := healthyContext(); c.LastHeartbeatAt = nil; return c }(),
		"stale": func() DeviceContext {
			c := healthyContext()
			old := now().Add(-2 * AgentStaleAfter)
			c.LastHeartbeatAt = &old
			return c
		}(),
	}
	for name, context := range tests {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(healthySignals(), context, DefaultWeights())

			if health := factorByCode(t, got, "AGENT_HEALTH"); health.Contribution != 0 {
				t.Errorf("a silent agent scored %d, want 0", health.Contribution)
			}
		})
	}
}

func TestOutdatedAgentScoresPartially(t *testing.T) {
	context := healthyContext()
	context.AgentVersion = "0.0.9"

	health := factorByCode(t, Evaluate(healthySignals(), context, DefaultWeights()), "AGENT_HEALTH")

	weights := DefaultWeights()
	if health.Contribution == 0 || health.Contribution == weights.AgentHealth {
		t.Errorf("outdated agent contributed %d, want partial credit between 0 and %d",
			health.Contribution, weights.AgentHealth)
	}
}

func TestOSCurrency(t *testing.T) {
	tests := []struct {
		name      string
		osName    string
		osVersion string
		wantFull  bool
	}{
		{"current windows", "windows", "11", true},
		{"minimum windows", "windows", "10", true},
		{"old windows", "windows", "8.1", false},
		{"current macos", "macos", "26.5.2", true},
		{"old macos", "macos", "12.7", false},
		{"unknown os", "plan9", "4", false},
		{"missing version", "windows", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signals := healthySignals()
			signals.OSName, signals.OSVersion = tt.osName, tt.osVersion

			factor := factorByCode(t, Evaluate(signals, healthyContext(), DefaultWeights()), "OS_SUPPORTED")

			if got := factor.Satisfied(); got != tt.wantFull {
				t.Errorf("satisfied = %v, want %v (detail: %s)", got, tt.wantFull, factor.Detail)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"11", "10", 1},
		{"10", "11", -1},
		{"10", "10", 0},
		{"26.5.2", "26.5.2", 0},
		{"26.5.2", "26.5", 1},
		{"14.0", "14", 0},
		{"11-preview", "11", 0},
		{"", "10", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			if got := compareVersions(tt.a, tt.b); got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestVerifiedIsHonestAboutEndpointClaims(t *testing.T) {
	// Most signals come from the endpoint, so a fully verified assessment is
	// not achievable today. Reporting otherwise would overstate what NETRA
	// actually established.
	got := Evaluate(healthySignals(), healthyContext(), DefaultWeights())

	if got.Verified {
		t.Error("assessment claims to be fully verified despite resting on endpoint claims")
	}

	identity := factorByCode(t, got, "DEVICE_IDENTITY")
	if identity.Source != SourceVerified {
		t.Error("device identity should be marked as verified by the backend")
	}
	encryption := factorByCode(t, got, "DISK_ENCRYPTION")
	if encryption.Source != SourceReported {
		t.Error("disk encryption is an endpoint claim and must be marked as reported")
	}
}

func TestWeakestRanksTheBiggestLossesFirst(t *testing.T) {
	// An operator needs to know what to fix, not just the number.
	signals := healthySignals()
	signals.DiskEncryption = ptr(false) // 20 points
	signals.ScreenLock = ptr(false)     // 5 points

	weakest := Evaluate(signals, healthyContext(), DefaultWeights()).Weakest(5)

	if len(weakest) < 2 {
		t.Fatalf("weakest returned %d factors, want at least 2", len(weakest))
	}
	if weakest[0].Code != "DISK_ENCRYPTION" {
		t.Errorf("worst factor = %s, want DISK_ENCRYPTION", weakest[0].Code)
	}
}

func TestWeakestExcludesSatisfiedControls(t *testing.T) {
	if got := Evaluate(healthySignals(), healthyContext(), DefaultWeights()).Weakest(5); len(got) != 0 {
		t.Errorf("a fully compliant device reported weaknesses: %+v", got)
	}
}

func TestScoreIsClampedToRange(t *testing.T) {
	got := Evaluate(healthySignals(), healthyContext(), DefaultWeights())

	if got.Score < 0 || got.Score > 100 {
		t.Errorf("score = %d, want 0..100", got.Score)
	}
}

func TestSignalsValidate(t *testing.T) {
	if err := healthySignals().Validate(); err != nil {
		t.Fatalf("valid signals rejected: %v", err)
	}

	oversized := Signals{OSName: string(make([]byte, 100))}
	if err := oversized.Validate(); err == nil {
		t.Error("an oversized os_name was accepted")
	}

	tooManyErrors := Signals{CollectionErrors: map[string]string{}}
	for i := 0; i < 40; i++ {
		tooManyErrors.CollectionErrors[string(rune('a'+i%26))+string(rune('0'+i/26))] = "x"
	}
	if err := tooManyErrors.Validate(); err == nil {
		t.Error("an unbounded collection_errors map was accepted")
	}
}
