package check

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const fpTargetID = "codex/gpt-6.1-sol"

// The gateway starts out unavailable. A complete second round must replace
// the transient error, not require three new fingerprint mismatch rounds.
func TestIncompleteFingerprintThenDefinitiveResult(t *testing.T) {
	for _, tc := range []struct {
		name     string
		final    string
		isolated bool
	}{
		{"consistent", "match", false},
		{"inconsistent", "mismatch", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := emergencyFixture(t)
			defer s.Close()
			var mode atomic.Int32
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if mode.Load() == 0 {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":12}}`))
			}))
			defer server.Close()
			s.state.Config.GatewayURL = server.URL
			s.state.Config.DailyLimit = 100
			target := s.state.AccountTargets[accountTargetID("aaa", fpTargetID)]
			timing := DefaultTimingPolicy()
			timing.UnavailableSeconds = 75
			target.TimingOverride = &timing
			classifier := &fakeFingerprint{verdict: tc.final}
			s.fingerprint = classifier
			if err := s.TriggerAutomaticFingerprint("aaa", fpTargetID); err != nil {
				t.Fatal(err)
			}
			s.wg.Wait()
			if target.ConsecutiveUnavailable != 1 || target.UnavailablePrompt != FingerprintPromptID ||
				target.State != "unavailable" || len(s.state.Holds) != 0 ||
				target.NextCheckAt.Sub(target.CheckedAt) != 75*time.Second {
				t.Fatalf("first incomplete round must retry at configured interval: %+v holds=%v", target, s.state.Holds)
			}
			if n := requests.Load(); n != 1 {
				t.Fatalf("429 must terminate incomplete round: %d calls", n)
			}
			mode.Store(1)
			if err := s.TriggerAutomaticFingerprint("aaa", fpTargetID); err != nil {
				t.Fatal(err)
			}
			s.wg.Wait()
			if target.ConsecutiveUnavailable != 0 || target.UnavailablePrompt != "" {
				t.Fatalf("complete result must clear unavailable streak: %+v", target)
			}
			if got := len(s.state.Holds) > 0; got != tc.isolated {
				t.Fatalf("complete fingerprint decision wrong: state=%s holds=%v", target.State, s.state.Holds)
			}
			if n := requests.Load(); n != 4 {
				t.Fatalf("one 429 plus three complete samples expected, got %d", n)
			}
			if tc.isolated {
				if target.State != PhaseIsolated || target.ConsecutiveFails != 1 ||
					s.state.Holds["aaa"].Prompt != FingerprintPromptID ||
					!s.state.Route.Quarantined["aaa"] {
					t.Fatalf("one reliable mismatch must immediately isolate and route: %+v %+v", target, s.state.Route)
				}
				keys := decodeKeyStates(t, path)
				if len(keys["production"].Accounts) != 1 || keys["production"].Accounts[0] != "codex/bbb" {
					t.Fatalf("isolated account still accessible from production: %+v", keys["production"])
				}
			} else if target.State != PhaseHealthy || target.ConsecutiveFails != 0 ||
				target.NextCheckAt.Sub(target.CheckedAt) != 30*time.Minute {
				t.Fatalf("complete match must pass without isolation: %+v", target)
			}
		})
	}
}

func TestThreeIncompleteFingerprintRoundsIsolateWithCustomTiming(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	s.state.Config.GatewayURL = server.URL
	s.state.Config.DailyLimit = 100
	s.state.Route.AutoApply = false
	t0 := s.state.AccountTargets[accountTargetID("aaa", fpTargetID)]
	timing := DefaultTimingPolicy()
	timing.UnavailableSeconds = 92
	t0.TimingOverride = &timing
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	for round := 1; round <= 3; round++ {
		if err := s.TriggerAutomaticFingerprint("aaa", fpTargetID); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
		if t0.ConsecutiveUnavailable != round || t0.ConsecutiveFails != 0 {
			t.Fatalf("round %d wrongly counted mismatch: %+v", round, t0)
		}
		if round < 3 {
			if len(s.state.Holds) != 0 || t0.State != "unavailable" ||
				t0.NextCheckAt.Sub(t0.CheckedAt) != 92*time.Second {
				t.Fatalf("round %d not scheduled at custom unavailable interval: %+v", round, t0)
			}
		}
	}
	if requests.Load() != 3 || len(s.state.Holds) != 1 || s.state.Holds["aaa"].Cause != "unavailable" ||
		t0.State != PhaseIsolated {
		t.Fatalf("three unavailable rounds must isolate: requests=%d target=%+v hold=%+v",
			requests.Load(), t0, s.state.Holds)
	}
	hold := s.state.Holds["aaa"]
	if hold.NextCheckAt.Sub(hold.Since) != 92*time.Second {
		t.Fatalf("unavailable quarantine recovery must keep custom timing: %+v", hold)
	}
}

func TestGateway401And404ImmediateIsolationDuringFingerprintSample(t *testing.T) {
	for _, tc := range []struct {
		status, at int
	}{
		{401, 1}, {404, 1}, {401, 2}, {404, 3},
	} {
		t.Run(fmt.Sprintf("%d_at_sample_%d", tc.status, tc.at), func(t *testing.T) {
			s, path := emergencyFixture(t)
			defer s.Close()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(calls.Add(1))
				if n == tc.at {
					w.WriteHeader(tc.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":12}}`))
			}))
			defer server.Close()
			s.state.Config.GatewayURL = server.URL
			classifier := &fakeFingerprint{verdict: "match"}
			s.fingerprint = classifier
			if err := s.TriggerAutomaticFingerprint("aaa", fpTargetID); err != nil {
				t.Fatal(err)
			}
			s.wg.Wait()
			target := s.state.AccountTargets[accountTargetID("aaa", fpTargetID)]
			verdict := fmt.Sprintf("http_%d", tc.status)
			if len(s.state.Holds) != 1 || s.state.Holds["aaa"].Cause != verdict ||
				target.State != PhaseIsolated || target.ConsecutiveUnavailable != 0 {
				t.Fatalf("HTTP %d must immediately isolate: target=%+v holds=%+v", tc.status, target, s.state.Holds)
			}
			if int(calls.Load()) != tc.at || classifier.call.Load() != 0 {
				t.Fatalf("HTTP %d must stop after sample %d without scoring: requests=%d scoring=%d",
					tc.status, tc.at, calls.Load(), classifier.call.Load())
			}
			final := s.state.AccountResults[len(s.state.AccountResults)-1]
			if final.Verdict != verdict || final.Fingerprint == nil ||
				final.Fingerprint.UsedOutputs != tc.at-1 {
				t.Fatalf("HTTP status not exposed in batch result: %+v", final)
			}
			if !s.state.Route.Quarantined["aaa"] {
				t.Fatalf("HTTP %d did not update production route", tc.status)
			}
			if keys := decodeKeyStates(t, path); keys["production"].Accounts[0] != "codex/bbb" {
				t.Fatalf("HTTP %d failed to exclude account: %+v", tc.status, keys)
			}
		})
	}
}

func TestOrdinaryObjective401And404AreImmediateBut429Retries(t *testing.T) {
	for _, status := range []int{401, 404, 429} {
		t.Run(fmt.Sprintf("HTTP_%d", status), func(t *testing.T) {
			s, _ := emergencyFixture(t)
			defer s.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			s.state.Config.GatewayURL = server.URL
			if err := s.TriggerAccount("aaa", fpTargetID, "milk", false); err != nil {
				t.Fatal(err)
			}
			s.wg.Wait()
			target := s.state.AccountTargets[accountTargetID("aaa", fpTargetID)]
			if status == 429 {
				if len(s.state.Holds) > 0 || target.State != "unavailable" || target.ConsecutiveUnavailable != 1 {
					t.Fatalf("HTTP 429 must retry ordinary question: %+v", target)
				}
			} else {
				verdict := fmt.Sprintf("http_%d", status)
				if len(s.state.Holds) != 1 || s.state.Holds["aaa"].Cause != verdict ||
					target.State != PhaseIsolated {
					t.Fatalf("HTTP %d must immediately isolate ordinary objective: %+v", status, target)
				}
			}
		})
	}
}

func TestImmediateGatewayStatusRequiresStructuredHTTPError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&gatewayHTTPStatusError{status: 401}, "http_401"},
		{&gatewayHTTPStatusError{status: 404}, "http_404"},
		{&gatewayHTTPStatusError{status: 429}, ""},
		{&gatewayHTTPStatusError{status: 500}, ""},
		{errors.New("context deadline exceeded: Magpie HTTP 404"), ""},
		{context.DeadlineExceeded, ""},
	} {
		if actual := immediateGatewayVerdict(tc.err); actual != tc.want {
			t.Fatalf("status classification wrong for %v: got %q want %q", tc.err, actual, tc.want)
		}
	}
}

func TestUnavailableRetryPinsFingerprintInRotatingQuestionBank(t *testing.T) {
	prompts := []Prompt{{ID: "milk"}, {ID: FingerprintPromptID}}
	target := AccountTarget{
		ConsecutiveUnavailable: 1, UnavailablePrompt: FingerprintPromptID,
		ConsecutiveFails: 2, LastAutoPrompt: "milk", PromptRotation: 0,
	}
	if got := selectAutomaticPrompt(target, false, true, prompts); got != FingerprintPromptID {
		t.Fatalf("retry must keep the same fingerprint instead of rotating to milk: %q", got)
	}
	t0 := time.Now()
	stateTarget := &target
	timing := DefaultTimingPolicy()
	timing.UnavailableSeconds = 85
	create, _ := objectiveTransitionWithTiming(stateTarget, nil, "unavailable", FingerprintPromptID, t0, timing)
	if create || target.ConsecutiveUnavailable != 2 ||
		target.NextCheckAt.Sub(t0) != 85*time.Second {
		t.Fatalf("second unavailable must retain custom retry timing: %+v", target)
	}
	create, _ = objectiveTransitionWithTiming(stateTarget, nil, "passed", FingerprintPromptID, target.NextCheckAt, timing)
	if create || target.ConsecutiveUnavailable != 0 || target.UnavailablePrompt != "" ||
		target.State != PhaseHealthy || target.ConsecutiveFails != 0 {
		t.Fatalf("definitive match after two incomplete rounds must reset streak: %+v", target)
	}
}

// A nearly complete fingerprint round with 2 successful samples and a 429
// on its third request must not be scored as a reliable mismatch.
func TestThirdFingerprintSample429RemainsUnavailable(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":12}}`))
	}))
	defer server.Close()
	s.state.Config.GatewayURL = server.URL
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	if err := s.TriggerAutomaticFingerprint("aaa", fpTargetID); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	target := s.state.AccountTargets[accountTargetID("aaa", fpTargetID)]
	final := s.state.AccountResults[len(s.state.AccountResults)-1]
	if target.State != "unavailable" || target.ConsecutiveUnavailable != 1 ||
		len(s.state.Holds) != 0 || final.Verdict != "unavailable" || final.Fingerprint.UsedOutputs != 2 ||
		int(requests.Load()) != 3 {
		t.Fatalf("incomplete third sample must be unavailable: target=%+v final=%+v calls=%d",
			target, final, requests.Load())
	}
}
