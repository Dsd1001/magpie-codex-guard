package check

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestResetAllStatesRestoresRoutingAndKeepsHistory(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Route.ScheduleEnabled = true
	beforeKeys := decodeKeyStates(t, path)
	for _, target := range s.state.AccountTargets {
		target.State = PhaseIsolated
		target.Reason = "旧错误"
		target.ConsecutiveFails = 3
		target.ConsecutiveUnavailable = 2
		target.ConsecutivePasses = 1
		target.LastAutoPrompt = FingerprintPromptID
		target.PromptRotation = 5
		target.CheckedAt = time.Now()
		target.NextCheckAt = time.Now().Add(24 * time.Hour)
		target.LastFingerprintAt = time.Now()
		target.NextFingerprintAt = time.Now().Add(time.Hour)
		target.FingerprintVersion = "old-bank"
		target.FingerprintExpected = "gpt-6-astra"
	}
	s.state.AccountResults = append(s.state.AccountResults, AccountResult{ID: "history", Verdict: "failed"})
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "isolated"}
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !decodeKeyStates(t, path)["production"].Off {
		t.Fatal("setup did not disable the production key")
	}
	plan, err := s.ApplyRouting(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != "observe_only" || len(plan.Quarantined) != 0 {
		t.Fatalf("reset preview should have no holds: %+v", plan)
	}
	gotKeys := decodeKeyStates(t, path)
	if !reflect.DeepEqual(gotKeys, beforeKeys) {
		t.Fatalf("reset did not restore original gateway key configuration: got %+v want %+v", gotKeys, beforeKeys)
	}
	if len(s.state.Holds) != 0 || len(s.state.Route.Quarantined) != 0 {
		t.Fatal("reset left quarantine records")
	}
	if s.state.Route.AutoApply || s.state.Route.ScheduleEnabled {
		t.Fatal("reset must pause both production routing and the scheduler")
	}
	if hasManagedRoutes(s.state.Route) {
		t.Fatal("reset left managed routing baselines")
	}
	if len(s.state.AccountResults) != 1 || s.state.AccountResults[0].ID != "history" {
		t.Fatal("reset erased historical detections")
	}
	for _, target := range s.state.AccountTargets {
		if target.State != "unverified" || target.Reason != "" ||
			target.ConsecutiveFails != 0 || target.ConsecutiveUnavailable != 0 ||
			target.ConsecutivePasses != 0 || target.LastAutoPrompt != "" ||
			target.PromptRotation != 0 || !target.CheckedAt.IsZero() ||
			!target.NextCheckAt.IsZero() || !target.LastFingerprintAt.IsZero() ||
			!target.NextFingerprintAt.IsZero() || target.FingerprintVersion != "" {
			t.Fatalf("target not fully reset: %+v", target)
		}
		if !target.Enabled || target.FingerprintExpected != "gpt-6-astra" {
			t.Fatalf("reset changed monitoring configuration: %+v", target)
		}
	}
	if got := s.state.Route.Audit[len(s.state.Route.Audit)-1].Action; got != "reset" {
		t.Fatalf("reset audit record missing: %s", got)
	}
	var persisted State
	if err := s.store.Load(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Route.ScheduleEnabled || len(persisted.Holds) != 0 {
		t.Fatal("reset state not persisted in SQLite")
	}
}

func TestResetWithoutManagedRoutesWorksWithoutGatewayKeys(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Route = RoutingState{ScheduleEnabled: true, AutoApply: false}
	s.state.Config.GatewayKey = ""
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "isolated"}
	s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")].ConsecutiveFails = 3
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), true); err != nil {
		t.Fatalf("observation-only reset should not require a gateway key: %v", err)
	}
	if len(s.state.Holds) != 0 || s.state.Route.ScheduleEnabled ||
		s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")].ConsecutiveFails != 0 {
		t.Fatal("observation-only state was not reset")
	}
}

func TestResetRestoresWhenProbeKeyMissingAndAccountCountChanged(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	s.state.Route.ProbeKeyID = "deleted-probe-key"
	s.state.Route.ExpectedCodexCount = 99
	s.state.Config.GatewayKey = ""
	if _, err := s.ApplyRouting(context.Background(), true); err != nil {
		t.Fatalf("reset should restore verified baselines even without the probe key: %v", err)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off || len(keys["production"].Accounts) != 0 || keys["restricted"].Off {
		t.Fatalf("managed routes were not restored: %+v", keys)
	}
}

func TestResetRejectsExternalKeyEditsWithoutClearingHolds(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Route.ScheduleEnabled = true
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	documents, _, err := loadKeyDocuments(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range documents {
		var id string
		if err := json.Unmarshal(d["id"], &id); err != nil {
			t.Fatal(err)
		}
		if id == "production" {
			d["accounts"] = json.RawMessage(`["codex/aaa"]`)
		}
	}
	b, err := json.Marshal(documents)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), true); err == nil {
		t.Fatal("reset must reject conflicting administrator edits")
	}
	if len(s.state.Holds) == 0 || !s.state.Route.ScheduleEnabled {
		t.Fatal("reset must not clear state when live route restoration is unsafe")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(b) {
		t.Fatal("reset overwrote a conflicting production file")
	}
}

func TestResetRejectsRunningAccountProbe(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	s.accountProbeActive = true
	if _, err := s.ApplyRouting(context.Background(), true); err == nil {
		t.Fatal("reset must not race with an active probe")
	}
	if !s.state.Route.AutoApply {
		t.Fatal("a rejected reset modified routing state")
	}
}
