package posture

import "testing"

// Posture is scored on every report from every endpoint, so the per-report
// cost bounds how large a fleet one instance can serve.
func BenchmarkEvaluatePosture(b *testing.B) {
	signals := healthySignals()
	context := healthyContext()
	weights := DefaultWeights()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(signals, context, weights)
	}
}
