package check

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const departedID = "deadbeef12345678"

func swapCodexLoginFile(t *testing.T, path string, includeOld, includeNew bool) {
	t.Helper()
	data := []map[string]string{
		{"id": "aaa", "agent": "codex", "user": "a@example.com"},
		{"id": "bbb", "agent": "codex", "user": "b@example.com"},
	}
	if includeOld {
		data = append(data, map[string]string{"id": departedID, "agent": "codex", "user": "old@example.com"})
	}
	if includeNew {
		data = append(data, map[string]string{"id": "ccdd112233445566", "agent": "codex", "user": "new@example.com"})
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "logins.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func accountSwapFixture(t *testing.T) (*Service, string) {
	t.Helper()
	s, path := emergencyFixture(t)
	swapCodexLoginFile(t, path, true, false)
	editMockKeyScope(t, path, "production", []string{"codex/aaa", "codex/bbb", "codex/" + departedID})
	s.state.Route.ExpectedCodexCount = 3
	model := "codex/gpt-6.1-sol"
	s.state.AccountTargets[accountTargetID(departedID, model)] = &AccountTarget{
		Account: departedID, Model: model, Enabled: true, State: "quarantined_high",
		NextCheckAt: time.Now().Add(-time.Hour),
	}
	s.state.Holds[departedID] = QuarantineHold{
		Account: departedID, Model: model, Risk: "high",
		Since: time.Now().Add(-2 * time.Hour), NextCheckAt: time.Now().Add(-time.Hour),
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		s.Close()
		t.Fatal(err)
	}
	return s, path
}

func TestAutoDiscoveryNewAccountsStayPendingUntilPassed(t *testing.T) {
	s, path := accountSwapFixture(t)
	defer s.Close()
	swapCodexLoginFile(t, path, false, true)
	summary, err := s.SyncLiveAccountTargets()
	if err != nil {
		t.Fatal(err)
	}
	if summary.LiveCount != 3 || summary.Added != 1 || summary.Missing != 1 {
		t.Fatalf("bad discovery summary %+v", summary)
	}
	const newID = "ccdd112233445566"
	target := s.state.AccountTargets[accountTargetID(newID, "codex/gpt-6.1-sol")]
	if target == nil || target.State != "unverified" || target.RouteEligible {
		t.Fatal("new login bypassed detection")
	}
	editMockKeyScope(t, path, "production", []string{"codex/" + newID, "codex/" + departedID})
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := decodeKeyStates(t, path)["production"].Accounts; !slices.Equal(got, []string{"codex/aaa", "codex/bbb"}) {
		t.Fatal("new/deleted login routed", got)
	}
	s.mu.Lock()
	s.applyDetectionVerdictLocked(target, "passed", "milk", time.Now())
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := decodeKeyStates(t, path)["production"].Accounts; !slices.Contains(got, "codex/"+newID) || slices.Contains(got, "codex/"+departedID) {
		t.Fatal(got)
	}
	if _, ok := s.state.Holds[departedID]; !ok {
		t.Fatal("deleted login history lost")
	}
}

func TestDeletedLoginLeavesQueueAndCannotReturnFromOldWhitelist(t *testing.T) {
	s, path := accountSwapFixture(t)
	defer s.Close()
	swapCodexLoginFile(t, path, false, false)
	if _, err := s.SyncLiveAccountTargets(); err != nil {
		t.Fatal(err)
	}
	old := s.state.AccountTargets[accountTargetID(departedID, "codex/gpt-6.1-sol")]
	if old == nil || !old.Missing {
		t.Fatal("deleted login not marked missing")
	}
	s.state.Route.ScheduleEnabled = true
	for _, target := range s.state.AccountTargets {
		if !target.Missing {
			target.NextCheckAt = time.Now().Add(time.Hour)
		}
	}
	if err := s.ScheduleOneAccount(time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.accountProbeActive {
		t.Fatal("deleted login was probed")
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if s.state.Route.Quarantined[departedID] {
		t.Fatal("deleted login still in active routing")
	}
	swapCodexLoginFile(t, path, true, false)
	if _, err := s.SyncLiveAccountTargets(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(decodeKeyStates(t, path)["production"].Accounts, "codex/"+departedID) {
		t.Fatal("re-added held login was silently released")
	}
}

func TestEmptyRosterAndOrphanHistoryDoNotStopRouting(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["old-email@example.com"] = QuarantineHold{Account: "old-email@example.com", Model: "codex/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "logins.json"), []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncLiveAccountTargets(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if len(keys["production"].Accounts) != 0 || !keys["production"].Off || keys["probe"].Off {
		t.Fatal("empty roster did not fail closed without blocking the probe")
	}
}

func TestRosterAndHeldDeadlinesSurviveRestart(t *testing.T) {
	s, path := accountSwapFixture(t)
	swapCodexLoginFile(t, path, false, true)
	if _, err := s.SyncLiveAccountTargets(); err != nil {
		t.Fatal(err)
	}
	held := s.state.Holds[departedID]
	dir := s.dir
	s.Close()
	loaded, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	got := loaded.state.Holds[departedID]
	if got.Risk != "isolated" || !got.NextCheckAt.Equal(held.NextCheckAt) || !got.Since.Equal(held.Since) {
		t.Fatal("restart changed isolation deadlines")
	}
	if !loaded.state.AccountTargets[accountTargetID(departedID, "codex/gpt-6.1-sol")].Missing || !loaded.state.Route.AutoSyncAccounts {
		t.Fatal("roster discovery did not survive restart")
	}
}
