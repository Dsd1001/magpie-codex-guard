package check

import (
	"testing"
	"time"
)

func TestObjectiveSuspectToFingerprint(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol", Enabled: true}
	for i := 1; i <= 3; i++ {
		now := start.Add(time.Duration(i-1) * 2 * time.Minute)
		yes, _ := objectiveTransition(target, nil, "failed", "milk", now)
		if (i == 3) != yes {
			t.Fatalf("at %d expected fingerprint? %v", i, yes)
		}
		if i < 3 && !target.NextCheckAt.Equal(now.Add(2*time.Minute)) {
			t.Fatal("suspect time incorrect")
		}
	}
	if target.State != PhaseFingerprint {
		t.Fatal(target.State)
	}
}
func TestRisk48And6Then24(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		verdict, risk   string
		initial, repeat time.Duration
	}{
		{"mismatch", "high", 48 * time.Hour, 48 * time.Hour},
		{"match", "low", 6 * time.Hour, 24 * time.Hour},
		{"indeterminate", "low", 6 * time.Hour, 24 * time.Hour},
	} {
		t.Run(tc.verdict, func(t *testing.T) {
			target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
			hold := startHold(*target, start)
			classifyHold(&hold, FingerprintReport{Verdict: tc.verdict}, start)
			if hold.Risk != tc.risk || !hold.NextCheckAt.Equal(start.Add(tc.initial)) {
				t.Fatalf("first hold %+v", hold)
			}
			first := hold.NextCheckAt
			_, release := objectiveTransition(target, &hold, "failed", "milk", first)
			if release || !hold.NextCheckAt.Equal(first.Add(tc.repeat)) {
				t.Fatalf("next hold %+v", hold)
			}
		})
	}
}
func TestRecoveryRequiresTwoAndNotAffectedByUnavailable(t *testing.T) {
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	tgt := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
	hold := startHold(*tgt, start)
	classifyHold(&hold, FingerprintReport{Verdict: "mismatch"}, start)
	_, release := objectiveTransition(tgt, &hold, "passed", "milk", start.Add(48*time.Hour))
	if release || hold.ConfirmationPasses != 1 || !tgt.NextCheckAt.Equal(start.Add(48*time.Hour+2*time.Minute)) {
		t.Fatal("not in confirmation phase")
	}
	_, release = objectiveTransition(tgt, &hold, "unavailable", "milk", tgt.NextCheckAt)
	if release || hold.ConfirmationPasses != 1 {
		t.Fatal("unavailable must be neutral")
	}
	_, release = objectiveTransition(tgt, &hold, "passed", "milk", tgt.NextCheckAt)
	if !release {
		t.Fatal("second valid pass must recover")
	}
}
func TestIndeterminateNeverHigh(t *testing.T) {
	var hold = QuarantineHold{Risk: "pending"}
	classifyHold(&hold, FingerprintReport{Verdict: "indeterminate", Diagnostic: "timeout"}, time.Now())
	if hold.Risk != "low" {
		t.Fatalf("got %s", hold.Risk)
	}
}
