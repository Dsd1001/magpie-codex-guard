package check

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func timingFixture(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	target := &AccountTarget{
		Account: "acct", Model: "codex/gpt-6.1-sol", Enabled: true,
		State: PhaseHealthy, CheckedAt: time.Now().Add(-time.Minute),
		NextCheckAt: time.Now().Add(4 * time.Hour),
	}
	s.state.AccountTargets[accountTargetID(target.Account, target.Model)] = target
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestTimingPolicyValidationAndPersistence(t *testing.T) {
	s, dir := timingFixture(t)
	p := DefaultTimingPolicy()
	p.NormalSeconds = 900
	p.SuspectSeconds = 75
	p.RecoverySeconds = 75
	p.RequestTimeoutSeconds = 150
	p.ScanSeconds = 20
	id := accountTargetID("acct", "codex/gpt-6.1-sol")
	beforeDue := s.state.AccountTargets[id].NextCheckAt
	if err := s.ConfigureTimingPolicy(p, "", "", false, false); err != nil {
		t.Fatal(err)
	}
	if !s.state.AccountTargets[id].NextCheckAt.Equal(beforeDue) {
		t.Fatal("global edit must not reschedule existing work by default")
	}

	perTarget := p
	perTarget.NormalSeconds = 120
	perTarget.SuspectSeconds = 40
	perTarget.QuarantineFirstSeconds = 5400
	if err := s.ConfigureTimingPolicy(perTarget, "acct", "codex/gpt-6.1-sol", false, false); err != nil {
		t.Fatal(err)
	}
	if s.requestTimeout("acct", "codex/gpt-6.1-sol") != 150*time.Second {
		t.Fatal("per target timeout lost")
	}
	if s.timingForTargetLocked(s.state.AccountTargets[id]).normal() != 120*time.Second {
		t.Fatal("per target interval not effective")
	}
	if s.timingForTargetLocked(nil).normal() != 900*time.Second {
		t.Fatal("global interval not effective")
	}
	s.Close()

	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.state.AccountTargets[id]
	if !got.NextCheckAt.Equal(beforeDue) || got.TimingOverride == nil || got.TimingOverride.NormalSeconds != 120 {
		t.Fatalf("time policy and existing deadline must survive restart: %+v", got)
	}
	if reopened.state.TimingPolicy.NormalSeconds != 900 || reopened.state.TimingPolicy.ScanSeconds != 20 {
		t.Fatalf("global time policy not persistent: %+v", reopened.state.TimingPolicy)
	}
	if err := reopened.ConfigureTimingPolicy(TimingPolicy{}, "acct", "codex/gpt-6.1-sol", true, false); err != nil {
		t.Fatal(err)
	}
	if reopened.state.AccountTargets[id].TimingOverride != nil {
		t.Fatal("inherit did not clear override")
	}
	if !reopened.state.AccountTargets[id].NextCheckAt.Equal(beforeDue) {
		t.Fatal("inherit unexpectedly rescheduled")
	}
}

func TestTimingPolicyRejectInvalidWithoutStateChanges(t *testing.T) {
	s, _ := timingFixture(t)
	defer s.Close()
	p := DefaultTimingPolicy()
	p.NormalSeconds = 0
	if err := s.ConfigureTimingPolicy(p, "", "", false, false); err == nil {
		t.Fatal("invalid zero interval accepted")
	}
	p = DefaultTimingPolicy()
	p.ScanSeconds = 5
	if err := s.ConfigureTimingPolicy(p, "", "", false, false); err == nil {
		t.Fatal("unsafe scheduler tick accepted")
	}
	if s.state.TimingPolicy != DefaultTimingPolicy() {
		t.Fatal("failed validation modified persisted policy")
	}
	if err := s.ConfigureTimingPolicy(DefaultTimingPolicy(), "missing", "codex/gpt-6.1-sol", false, false); err == nil {
		t.Fatal("unknown account policy accepted")
	}
}

func TestTimingPolicyOptionalRescheduleKeepsHoldAndCounters(t *testing.T) {
	s, _ := timingFixture(t)
	defer s.Close()
	id := accountTargetID("acct", "codex/gpt-6.1-sol")
	now := time.Now()
	tgt := s.state.AccountTargets[id]
	tgt.LastAutoPrompt = "milk"
	tgt.ConsecutiveFails = 3
	tgt.State = PhaseIsolated
	tgt.CheckedAt = now
	oldDue := now.Add(6 * time.Hour)
	tgt.NextCheckAt = oldDue
	s.state.Holds[tgt.Account] = QuarantineHold{
		Account: tgt.Account, Model: tgt.Model, Risk: "isolated", Prompt: "milk",
		Since: now, NextCheckAt: oldDue,
	}
	custom := DefaultTimingPolicy()
	custom.QuarantineFirstSeconds = 3600
	if err := s.ConfigureTimingPolicy(custom, "", "", false, false); err != nil {
		t.Fatal(err)
	}
	if !s.state.Holds[tgt.Account].NextCheckAt.Equal(oldDue) {
		t.Fatal("default change mutated hold deadline")
	}
	if err := s.ConfigureTimingPolicy(custom, "", "", false, true); err != nil {
		t.Fatal(err)
	}
	hold := s.state.Holds[tgt.Account]
	if hold.Risk != "isolated" || hold.Prompt != "milk" || tgt.ConsecutiveFails != 3 {
		t.Fatalf("rescheduling changed hold evidence or counts: %+v %+v", hold, tgt)
	}
	if delta := hold.NextCheckAt.Sub(now); delta < 59*time.Minute || delta > 61*time.Minute {
		t.Fatalf("reschedule interval not effective: %v", delta)
	}
	if _, exists := s.state.Route.Quarantined[tgt.Account]; exists {
		t.Fatal("time change edited production routing")
	}
}

func TestTimingPolicyManagementEndpointRejectsBadInputs(t *testing.T) {
	s, _ := timingFixture(t)
	defer s.Close()
	handler := s.ManagementHandler(NewGuardAccess("control", "http://127.0.0.1:3333"))
	send := func(policy TimingPolicy) int {
		t.Helper()
		b, err := json.Marshal(map[string]any{"policy": policy})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3333/api/timing", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer control")
		req.Header.Set("Origin", "http://127.0.0.1:3333")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res.Code
	}
	if status := send(DefaultTimingPolicy()); status != http.StatusOK {
		t.Fatalf("valid time policy HTTP %d", status)
	}
	invalid := DefaultTimingPolicy()
	invalid.NormalSeconds = 1
	if status := send(invalid); status != http.StatusConflict {
		t.Fatalf("invalid policy HTTP %d", status)
	}
}
