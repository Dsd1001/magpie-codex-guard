package fingerprint

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestLoadOfficialArtifact(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Models()) != 64 {
		t.Fatalf("want 64 models from upstream 2026-10-27, got %d", len(d.Models()))
	}
	if canonicalExpected("codex/gpt-6.1-sol") != "gpt-6-astra" {
		t.Fatal("merged-model alias broken")
	}
	known := map[string]bool{}
	for _, m := range d.Models() {
		known[m.ID] = true
		if m.ID == "gpt-6-astra" && m.DisplayName != "gpt-6-astra/6.1-sol" {
			t.Fatal("merged model label missing")
		}
	}
	for _, id := range []string{"gpt-6.1-terra", "kimi-k3.1-pro", "gemini-3.5-flash-lite", "minimax-m3.1-flash"} {
		if !known[id] {
			t.Fatalf("new upstream fingerprint model missing: %s", id)
		}
		if _, found := d.ResolveExpected("codex/" + id); !found {
			t.Fatalf("upstream model missing from expected-model resolver: %s", id)
		}
	}
}
func TestThreeSampleRanker(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	outputs := make([]Output, 3)
	for k := 0; k < 3; k++ {
		var b strings.Builder
		for i := 0; i < 310; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			// Artificial oscillatory data to exercise the mathematical ranker only.
			val := 12 + (k+i%4)*3
			if i%2 == 0 {
				val += 310
			}
			fmt.Fprint(&b, val)
		}
		outputs[k] = Output{Text: b.String(), ExpectedCount: 310}
	}
	r, err := d.Analyze(outputs, "codex/gpt-6.1-sol")
	if err != nil {
		t.Fatal(err)
	}
	if r.Used != 3 {
		t.Fatalf("unexpected parse result: %+v", r)
	}
	if len(r.Candidates) != 5 {
		t.Fatalf("ranking failed: %+v", r)
	}
	if math.IsNaN(r.Confidence) || r.Confidence < 0 || r.Confidence > 1 {
		t.Fatalf("invalid confidence %v", r.Confidence)
	}
	t.Logf("synthetic rank top=%s prob=%.3f outcome=%s", r.Predicted, r.Confidence, r.Decision)
}
func TestIndeterminateOnPartialOrUnsupported(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := d.Analyze([]Output{{Text: "1 2 3", ExpectedCount: 300}}, "codex/gpt-6.1-sol")
	if a.Decision != "indeterminate" {
		t.Fatalf("unexpected %s", a.Decision)
	}
}

func TestSequenceShapeMatchesLatestUpstreamORRule(t *testing.T) {
	// A model-like number sequence only needs one of the two signals:
	// either sufficiently negative lag-1 autocorrelation, OR few short
	// steps. This changed upstream on 2026-10-24 (ef6badb71016).
	alternating := make([]int, 300)
	largeSteps := make([]int, 300)
	sorted := make([]int, 300)
	for i := range alternating {
		if i%2 == 0 {
			alternating[i] = 145
		} else {
			alternating[i] = 155 // short steps but negative autocorrelation
		}
		largeSteps[i] = 20 + (i%6)*60 // positive autocorrelation; no short steps
		sorted[i] = i + 1             // positive autocorrelation with many short steps
	}
	if !sequenceLike([][]int{alternating, alternating, alternating}) {
		t.Fatal("negative autocorrelation alone must count as model-like")
	}
	if !sequenceLike([][]int{largeSteps, largeSteps, largeSteps}) {
		t.Fatal("few short steps alone must count as model-like")
	}
	if sequenceLike([][]int{sorted, sorted, sorted}) {
		t.Fatal("sorted or near-sequential values must remain non-model")
	}
}
