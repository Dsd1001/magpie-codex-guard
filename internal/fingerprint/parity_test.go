package fingerprint

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The golden file is output by the ORIGINAL JavaScript implementation
// of shared-detector-v2 (Ikaleio/lm-detector) using the unmodified public
// unified_reference.jsonl answers and the pinned bank/artifact. Any change
// to reference artifact must regenerate+verify the goldens with that source.
func TestOriginalJavaScriptParity(t *testing.T) {
	var input struct {
		Cases []struct {
			ID            string   `json:"id"`
			ExpectedModel string   `json:"expected_model"`
			Outputs       []Output `json:"outputs"`
		} `json:"cases"`
	}
	var gold struct {
		Results []struct {
			ID        string `json:"id"`
			Predicted string `json:"predicted"`
			Used      int    `json:"used_outputs"`
			Top5      []struct {
				Model       string   `json:"model"`
				Probability *float64 `json:"probability"`
				Score       float64  `json:"score"`
			} `json:"top5"`
		} `json:"results"`
	}
	b, err := os.ReadFile("testdata/official_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &input); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/official_results.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &gold); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(gold.Results) {
		t.Fatalf("cases %d != official %d", len(input.Cases), len(gold.Results))
	}
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range input.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			expected := gold.Results[i]
			if tc.ID != expected.ID {
				t.Fatalf("mismatched fixture %q vs %q", tc.ID, expected.ID)
			}
			got, err := d.Analyze(tc.Outputs, tc.ExpectedModel)
			if err != nil {
				t.Fatal(err)
			}
			if got.Used != expected.Used {
				t.Errorf("valid outputs expected %d, got %d", expected.Used, got.Used)
			}
			if got.Predicted != expected.Predicted {
				t.Errorf("predicted %q, official %q", got.Predicted, expected.Predicted)
			}
			if len(got.Candidates) != len(expected.Top5) {
				t.Fatalf("candidate length %d, official %d", len(got.Candidates), len(expected.Top5))
			}
			for j, c := range got.Candidates {
				other := expected.Top5[j]
				if c.Model != other.Model {
					t.Errorf("rank %d: got %q, official %q", j, c.Model, other.Model)
				}
				if other.Probability != nil && math.Abs(c.Probability-*other.Probability) > 1e-6 {
					t.Errorf("probability %d (%s): got %.9f official %.9f", j, c.Model, c.Probability, *other.Probability)
				}
				if math.Abs(c.Score-other.Score) > 1e-6 {
					t.Errorf("score %d (%s): got %.9f official %.9f", j, c.Model, c.Score, other.Score)
				}
			}
		})
	}
}
