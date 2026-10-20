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
	if len(d.Models()) != 60 {
		t.Fatalf("want 60 models, got %d", len(d.Models()))
	}
	if canonicalExpected("codex/gpt-6.1-sol") != "gpt-6-astra" {
		t.Fatal("merged-model alias broken")
	}
	for _, m := range d.Models() {
		if m.ID == "gpt-6-astra" && m.DisplayName != "gpt-6-astra/6.1-sol" {
			t.Fatal("merged model label missing")
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
