package check

import (
	"testing"
	"time"
)

func TestOrdinaryObjectiveRequiresThreeWrongAnswersOnSameQuestion(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol", Enabled: true}
	for n := 1; n <= 3; n++ {
		create, _ := objectiveTransition(target, nil, "failed", "milk", now)
		if create != (n == 3) {
			t.Fatalf("wrong threshold for ordinary objective n=%d", n)
		}
		if n < 3 && !target.NextCheckAt.Equal(now.Add(SuspectInterval)) {
			t.Fatalf("unexpected retry time for n=%d", n)
		}
		now = now.Add(SuspectInterval)
	}
	if target.State != PhaseIsolated || target.ConsecutiveFails != 3 {
		t.Fatalf("ordinary objective not isolated on third error: %+v", target)
	}
	hold := startHold(*target, now)
	if hold.Risk != "isolated" || hold.Prompt != "milk" || !hold.NextCheckAt.Equal(now.Add(6*time.Hour)) {
		t.Fatalf("incorrect unified hold: %+v", hold)
	}
}

func TestDifferentObjectivePromptDoesNotAccumulateFailures(t *testing.T) {
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
	now := time.Now()
	objectiveTransition(target, nil, "failed", "milk", now)
	objectiveTransition(target, nil, "failed", "custom-1", now)
	if target.ConsecutiveFails != 1 || target.LastAutoPrompt != "custom-1" {
		t.Fatalf("wrong questions combined in one fail streak: %+v", target)
	}
}

func TestFingerprintOneCompleteMismatchImmediatelyIsolates(t *testing.T) {
	now := time.Now()
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
	create, release := objectiveTransition(target, nil, "failed", FingerprintPromptID, now)
	if !create || release || target.State != PhaseIsolated || target.ConsecutiveFails != 1 {
		t.Fatalf("fingerprint mismatch did not isolate on one scored turn: %+v", target)
	}
	hold := startHold(*target, now)
	if hold.Prompt != FingerprintPromptID || hold.Risk != "isolated" {
		t.Fatalf("fingerprint hold incorrect: %+v", hold)
	}
}

func TestUnifiedQuarantineFirstSixThenTwentyFour(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol", LastAutoPrompt: "milk"}
	hold := startHold(*target, now)
	if !hold.NextCheckAt.Equal(now.Add(6 * time.Hour)) {
		t.Fatal("initial unified quarantine not six hours")
	}
	next := hold.NextCheckAt
	_, release := objectiveTransition(target, &hold, "failed", "milk", next)
	if release || !hold.NextCheckAt.Equal(next.Add(24*time.Hour)) {
		t.Fatalf("repeat unified quarantine not 24 hours: %+v", hold)
	}
}

func TestRecoveryRequiresTwoConsecutiveValidPasses(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
	hold := startHold(*target, now)
	first := hold.NextCheckAt
	_, release := objectiveTransition(target, &hold, "passed", "milk", first)
	if release || hold.ConfirmationPasses != 1 || !target.NextCheckAt.Equal(first.Add(SuspectInterval)) {
		t.Fatal("first pass was not confirmation stage")
	}
	_, release = objectiveTransition(target, &hold, "unavailable", "milk", target.NextCheckAt)
	if release || hold.ConfirmationPasses != 0 || !target.NextCheckAt.Equal(first.Add(SuspectInterval+UnavailableInterval)) {
		t.Fatal("unavailable must keep hold and invalidate recovery streak")
	}
	_, release = objectiveTransition(target, &hold, "passed", "milk", target.NextCheckAt)
	if release || hold.ConfirmationPasses != 1 {
		t.Fatal("first pass after unavailable must not release")
	}
	_, release = objectiveTransition(target, &hold, "passed", "milk", target.NextCheckAt)
	if !release {
		t.Fatal("two consecutive passes must recover")
	}
}

func TestIndeterminateFingerprintRemainsUnavailableVerdict(t *testing.T) {
	if got := fingerprintAsObjectiveVerdict(FingerprintReport{Verdict: "indeterminate", UsedOutputs: 3}, "gpt-6-astra"); got != "unavailable" {
		t.Fatal("indeterminate fingerprint must be neutral")
	}
	if got := fingerprintAsObjectiveVerdict(FingerprintReport{Verdict: "mismatch", UsedOutputs: 2}, "gpt-6-astra"); got != "unavailable" {
		t.Fatal("partial fingerprint batch must be neutral")
	}
}

func TestUnavailableAutomaticCheckCreatesHoldWithoutFalseAnswerCount(t *testing.T) {
	now := time.Date(2026, 10, 27, 6, 0, 0, 0, time.UTC)
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol", Enabled: true, State: PhaseHealthy}
	timing := DefaultTimingPolicy()
	timing.UnavailableSeconds = 90
	create, release := objectiveTransitionWithTiming(target, nil, "unavailable", "milk", now, timing)
	if !create || release || target.State != PhaseIsolated || target.ConsecutiveFails != 0 || target.LastAutoPrompt != "milk" {
		t.Fatalf("unavailable automatic check must isolate without scoring an incorrect answer: %+v", target)
	}
	hold := startHoldWithTiming(*target, now, timing)
	if hold.Cause != "unavailable" || !hold.NextCheckAt.Equal(now.Add(90*time.Second)) {
		t.Fatalf("unavailable hold must use customized retry interval: %+v", hold)
	}
	_, release = objectiveTransitionWithTiming(target, &hold, "unavailable", "milk", hold.NextCheckAt, timing)
	if release || hold.ConfirmationPasses != 0 {
		t.Fatal("second unavailable check must not release hold")
	}
	for n := 1; n <= 2; n++ {
		_, release = objectiveTransitionWithTiming(target, &hold, "passed", "milk", hold.NextCheckAt, timing)
		if release != (n == 2) {
			t.Fatalf("recovery requires two valid passes, n=%d release=%v", n, release)
		}
	}
}

func TestUnavailableFingerprintIsolatesWithoutCountingMismatch(t *testing.T) {
	target := &AccountTarget{Account: "acct", Model: "codex/gpt-6.1-sol"}
	now := time.Now()
	report := FingerprintReport{Verdict: "indeterminate", UsedOutputs: 2}
	verdict := fingerprintAsObjectiveVerdict(report, "gpt-6-astra")
	if verdict != "unavailable" {
		t.Fatalf("unexpected fingerprint verdict: %s", verdict)
	}
	create, _ := objectiveTransition(target, nil, verdict, FingerprintPromptID, now)
	if !create || target.ConsecutiveFails != 0 || target.State != PhaseIsolated {
		t.Fatalf("inconclusive fingerprint must isolate without mismatch count: %+v", target)
	}
}
