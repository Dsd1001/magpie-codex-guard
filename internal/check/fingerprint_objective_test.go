package check

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

type incompleteFingerprint struct{}

func (incompleteFingerprint) Evaluate(_ []fingerprint.Output, _ string) FingerprintReport {
	return FingerprintReport{Verdict: "mismatch", UsedOutputs: 2, Version: "test-v1"}
}

func TestFingerprintObjectiveOptInAndQuestionRotation(t *testing.T) {
	s, _, close := fingerprintBankFixture(t)
	defer close()
	if p := s.activeAccountPromptsLocked(); len(p) != 1 || p[0].ID != "milk" {
		t.Fatalf("default question pool changed: %v", p)
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, false, FingerprintObjective); err == nil {
		t.Fatal("fingerprint rotation without rotation enabled was accepted")
	}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintOnFailure); err == nil {
		t.Fatal("legacy mode accepted empty objective bank")
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	active := s.activeAccountPromptsLocked()
	if len(active) != 2 || active[0].ID != "milk" || active[1].ID != FingerprintPromptID {
		t.Fatalf("fingerprint not in selected objective rotation: %v", active)
	}
	target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if chosen := selectAutomaticPrompt(*target, false, true, active); chosen != "milk" {
		t.Fatalf("unconfigured target should continue objective checks: %q", chosen)
	}
	target.FingerprintExpected = "gpt-6-astra"
	target.PromptRotation = 1
	if chosen := selectAutomaticPrompt(*target, false, true, active); chosen != FingerprintPromptID {
		t.Fatalf("fingerprint not selected by round robin: %q", chosen)
	}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	selected := s.activeAccountPromptsLocked()
	if len(selected) != 1 || selected[0].ID != FingerprintPromptID {
		t.Fatalf("fingerprint-only selection failed: %v", selected)
	}
	s.reconcileAutoPromptPolicyLocked()
	if len(s.state.AutoPromptPolicy.PromptIDs) != 0 {
		t.Fatal("fingerprint-only mode was replaced with milk")
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintOnFailure); err != nil {
		t.Fatal(err)
	}
	if len(s.activeAccountPromptsLocked()) != 1 {
		t.Fatal("old mode incorrectly retained fingerprint in objective pool")
	}
	if s.state.Route.AutoApply {
		t.Fatal("changing question mode enabled production routing")
	}
}

func TestFingerprintObjectiveMatchIsSinglePassedCheckWithThreeSamples(t *testing.T) {
	s, calls, close := fingerprintBankFixture(t)
	defer close()
	fake := &fakeFingerprint{verdict: "match"}
	s.fingerprint = fake
	if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", "gpt-6-astra"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	target.PromptRotation = 1
	target.NextCheckAt = time.Time{}
	s.state.Route.ScheduleEnabled = true
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleOneAccount(time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if calls.Load() != 3 || fake.call.Load() != 1 {
		t.Fatalf("fingerprint should run once with 3 requests, got %d/%d", calls.Load(), fake.call.Load())
	}
	target = s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if target.State != PhaseHealthy || target.LastAutoPrompt != FingerprintPromptID || target.ConsecutiveFails != 0 || target.PromptRotation != 2 {
		t.Fatalf("fingerprint was not processed as a passed question: %+v", target)
	}
	if time.Until(target.NextCheckAt) < 59*time.Minute {
		t.Fatal("normal next check not hourly")
	}
	if len(s.state.Holds) != 0 {
		t.Fatal("passing fingerprint created a quarantine")
	}
	results := s.state.AccountResults
	final := results[len(results)-1]
	if final.Prompt != FingerprintPromptID || final.Verdict != "passed" || final.Fingerprint == nil || final.Fingerprint.Verdict != "match" {
		t.Fatalf("missing integrated scored fingerprint record: %+v", final)
	}
	dir := s.dir
	_ = dir
}

func TestFingerprintObjectiveThreeStrongMismatchesCreateHighRiskHold(t *testing.T) {
	s, calls, close := fingerprintBankFixture(t)
	defer close()
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", "gpt-6-astra"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	s.state.Route.ScheduleEnabled = true
	for n := 1; n <= 3; n++ {
		target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
		target.NextCheckAt = time.Time{}
		if err := s.saveLocked(); err != nil {
			t.Fatal(err)
		}
		if err := s.ScheduleOneAccount(time.Now()); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
		target = s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
		if target.ConsecutiveFails != n {
			t.Fatalf("after %d mismatches got failures=%d", n, target.ConsecutiveFails)
		}
		if n < 3 {
			if target.State != PhaseSuspect {
				t.Fatalf("failure %d not suspect: %+v", n, target)
			}
			if len(s.state.Holds) != 0 {
				t.Fatal("fingerprint hold created before three failures")
			}
		}
	}
	hold, ok := s.state.Holds["aaa"]
	if !ok || hold.Risk != "high" || hold.Fingerprint.Verdict != "mismatch" {
		t.Fatalf("third strong mismatch did not enter normal high-risk classification: %+v", hold)
	}
	// 3 automatic question batches (9 requests) plus the existing
	// post-third-failure risk confirmation (3 requests).
	if calls.Load() != 12 || fake.call.Load() != 4 {
		t.Fatalf("unexpected fingerprint count: upstream=%d eval=%d", calls.Load(), fake.call.Load())
	}
	if time.Until(hold.NextCheckAt) < 47*time.Hour {
		t.Fatal("high risk recheck incorrectly scheduled")
	}
}

func TestFingerprintObjectiveIndeterminateAndIncompleteDoNotCountAsFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner FingerprintRunner
	}{
		{"indeterminate", &fakeFingerprint{verdict: "indeterminate"}},
		{"incomplete", incompleteFingerprint{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls, close := fingerprintBankFixture(t)
			defer close()
			s.fingerprint = tc.runner
			if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", "gpt-6-astra"); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
				t.Fatal(err)
			}
			target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
			target.ConsecutiveFails = 2
			target.State = PhaseSuspect
			target.LastAutoPrompt = FingerprintPromptID
			if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err != nil {
				t.Fatal(err)
			}
			s.wg.Wait()
			target = s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
			if target.ConsecutiveFails != 2 || target.State != "unavailable" || len(s.state.Holds) != 0 {
				t.Fatalf("uncertain fingerprint incorrectly changed state: %+v", target)
			}
			final := s.state.AccountResults[len(s.state.AccountResults)-1]
			if final.Verdict != "unavailable" || final.Fingerprint == nil {
				t.Fatalf("uncertain fingerprint missing record: %+v", final)
			}
			if calls.Load() != 3 {
				t.Fatalf("unexpected attempts: %d", calls.Load())
			}
		})
	}
}

func TestFingerprintObjectiveWithoutExpectedModelIsUnscoredAndMakesNoCalls(t *testing.T) {
	s, calls, close := fingerprintBankFixture(t)
	defer close()
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if calls.Load() != 0 {
		t.Fatal("unknown reference model should not trigger requests")
	}
	target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if target.ConsecutiveFails != 0 || len(s.state.Holds) != 0 || target.State != "unavailable" {
		t.Fatalf("missing reference was treated as wrong: %+v", target)
	}
	result := s.state.AccountResults[len(s.state.AccountResults)-1]
	if result.Verdict != "unavailable" || result.Error == "" {
		t.Fatalf("missing explicit configuration diagnosis: %+v", result)
	}
}

func TestFingerprintObjectiveModePersistsAndPreservesExistingHolds(t *testing.T) {
	s, _, _ := fingerprintBankFixture(t)
	target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	target.State = PhaseHigh
	target.ConsecutiveFails = 3
	timeDue := time.Now().Add(23 * time.Hour).Round(time.Second)
	target.NextCheckAt = timeDue
	s.state.Holds["aaa"] = QuarantineHold{
		Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "high", NextCheckAt: timeDue,
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	target = s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if target.State != PhaseHigh || target.ConsecutiveFails != 3 || !target.NextCheckAt.Equal(timeDue) {
		t.Fatalf("option change modified isolated account: %+v", target)
	}
	dir := s.dir
	s.Close()
	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.AutoPromptSettings().FingerprintMode != FingerprintObjective {
		t.Fatal("mode not persisted")
	}
	if reopened.state.Holds["aaa"].Risk != "high" {
		t.Fatal("hold lost on restart")
	}
}

// Integration: the optional fingerprint question uses the SAME safe routing
// controller and two-pass recovery as an ordinary graded objective question.
func TestFingerprintObjectiveProductionRoutingAndRecovery(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Magpie-Account") != "a@example.com" ||
			r.Header.Get("Authorization") != "Bearer PROBE_SECRET_LONG_ENOUGH" {
			t.Error("automatic fingerprint used a production key or wrong account")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":20}}`))
	}))
	defer srv.Close()
	s.state.Config.GatewayURL = srv.URL
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", "gpt-6-astra"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if requests.Load() != 12 {
		t.Fatalf("3 scored rounds plus quarantine confirmation expected 12 samples: %d", requests.Load())
	}
	if h := s.state.Holds["aaa"]; h.Risk != "high" {
		t.Fatalf("high-risk hold not created: %+v", h)
	}
	keys := decodeKeyStates(t, path)
	if !reflect.DeepEqual(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatalf("production still allows held account: %v", keys["production"].Accounts)
	}
	if !keys["restricted"].Off || keys["probe"].Off {
		t.Fatal("production isolation touched probe or left restricted key enabled")
	}
	if !s.state.Route.Quarantined["aaa"] {
		t.Fatal("routing journal has no quarantine")
	}
	// Recovery is also judged by the selected fingerprint question, never
	// by the three individual sample rows.
	fake.verdict = "match"
	for n := 0; n < 2; n++ {
		if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if _, exists := s.state.Holds["aaa"]; exists {
		t.Fatal("two passing fingerprint rounds did not release hold")
	}
	keys = decodeKeyStates(t, path)
	// The original production key was unrestricted (empty scope means all).
	// Recovery must restore that EXACT pre-quarantine baseline.
	if keys["production"].Off || len(keys["production"].Accounts) != 0 {
		t.Fatalf("production did not restore allowed identities: %+v", keys["production"])
	}
	if keys["restricted"].Off || keys["probe"].Off || !keys["alreadyoff"].Off {
		t.Fatal("recovery changed unrelated production or probe key status")
	}
}
