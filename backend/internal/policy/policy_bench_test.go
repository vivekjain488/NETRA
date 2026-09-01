package policy

import (
	"testing"

	"github.com/netra/backend/internal/risk"
)

// Policy evaluation happens on every access decision, so its cost belongs in a
// measurement rather than an assumption.

func BenchmarkEvaluateDefaultPolicySet(b *testing.B) {
	engine := NewEngine(DefaultPolicies())
	request := Request{
		Assessment:          assessment(94, risk.LevelCritical, "NEW_DEVICE", "CRITICAL_RESOURCE"),
		ResourceSensitivity: "CRITICAL",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(request)
	}
}

func BenchmarkEvaluateNoMatch(b *testing.B) {
	engine := NewEngine(DefaultPolicies())
	request := Request{Assessment: assessment(5, risk.LevelLow)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(request)
	}
}
