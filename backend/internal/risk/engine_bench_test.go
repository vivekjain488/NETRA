package risk

import "testing"

// The risk engine sits in the access path, so its cost is a product
// requirement rather than a curiosity. These benchmarks measure it; they make
// no claim about what the number should be.

func BenchmarkEvaluateTrustedSession(b *testing.B) {
	engine := NewEngine(DefaultWeights(), DefaultThresholds())
	inputs := trusted()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(inputs)
	}
}

func BenchmarkEvaluateWorstCase(b *testing.B) {
	// Every signal firing is the most work the engine can be asked to do.
	engine := NewEngine(DefaultWeights(), DefaultThresholds())
	inputs := worstCase(trusted())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(inputs)
	}
}
