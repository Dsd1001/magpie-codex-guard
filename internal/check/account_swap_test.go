package check

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestAccountSwapMissingHighRiskHoldRetainedAndNextProbesSkipDeleted(t *testing.T) {
	s, path := accountSwapFixture(t)
	defer s.Close()
	swapCodexLoginFile(t, path, false, true)
	if got := len(s.state.Holds); got != 1 {
		t.Fatal("hold changed on login deletion", got)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatalf("missing held login must not halt healthy routing: %v", err)
	}
	if err := s.verifySafeReadOnlyProbes(); err != nil {
		t.Fatal(err)
	}
	// Historical high-risk hold and quarantine journal are deliberately kept.
	if s.state.Holds[departedID].Risk != "high" || !s.state.Route.Quarantined[departedID] {
		t.Fatal("the deleted account was released")
	}
	// Old account due long ago must NOT become the first scheduled job.
	s.state.Route.ScheduleEnabled = true
	for _, target := range s.state.AccountTargets {
		if target.Account != departedID {
			target.NextCheckAt = time.Now().Add(48 * time.Hour)
		}
	}
	if err := s.ScheduleOneAccount(time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.accountProbeActive || len(s.state.AccountResults) > 0 {
		t.Fatal("scheduler probed deleted account instead of ignoring it")
	}
}

func TestApproveLiveLoginAdditionRequiresExplicitConsentPreservesHold(t *testing.T) {
	s, path := accountSwapFixture(t)
	defer s.Close()
	swapCodexLoginFile(t, path, false, true)
	added := "codex/ccdd112233445566"
	// This is an admin edit: not an automatic route or baseline modification.
	editMockKeyScope(t, path, "production", []string{"codex/aaa", "codex/bbb", added})
	original, _ := os.ReadFile(path)
	if _, err := s.ApplyRouting(context.Background(), false); err == nil {
		t.Fatal("silent adoption of expanded production scope")
	}
	if err := s.verifySafeReadOnlyProbes(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveCurrentScopes(context.Background(), ""); err == nil {
		t.Fatal("scope widening did not require explicit operator approval")
	}
	if _, err := s.ApproveCurrentScopes(context.Background(), "APPROVE_CURRENT_PRODUCTION_SCOPES"); err != nil {
		t.Fatalf("confirmed safe login added but cannot adopt: %v", err)
	}
	updated, _ := os.ReadFile(path)
	if string(original) != string(updated) {
		t.Fatal("approval wrote Gateway Key file")
	}
	if got := s.state.Route.Expected["production"]; !reflect.DeepEqual(got, []string{"codex/aaa", "codex/bbb", added}) {
		t.Fatalf("new admin baseline not persisted: %v", got)
	}
	if got := s.state.Route.Baselines["production"]; !reflect.DeepEqual(got, []string{"codex/aaa", "codex/bbb", added}) {
		t.Fatalf("old deleted account will be restored: %v", got)
	}
	if !s.state.Route.Quarantined[departedID] || len(s.state.Holds) != 1 {
		t.Fatal("orphan quarantine removed")
	}
	audit := s.state.Route.Audit
	if audit[len(audit)-1].Action != "admin-scope-change-approved" {
		t.Fatal("no operator approval audit")
	}
	// This is only a test of the hypothetical *explicit* hold removal; it
	// verifies the old, deleted login cannot be re-added from a stale baseline.
	delete(s.state.Holds, departedID)
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := decodeKeyStates(t, path)["production"].Accounts
	if !reflect.DeepEqual(got, []string{"codex/aaa", "codex/bbb", added}) {
		t.Fatalf("deleted login was restored to production: %v", got)
	}
}

func TestAccountRosterSyncKeepsTombstoneAndEnrollsReplacementOptIn(t *testing.T) {
	s, path := accountSwapFixture(t)
	swapCodexLoginFile(t, path, false, true)
	original, _ := os.ReadFile(path)
	if err := s.ConfigureAccountAutoSync(true, ""); err == nil {
		t.Fatal("auto enrolling new logins did not require consent")
	}
	if err := s.ConfigureAccountAutoSync(true, "AUTO_SYNC_CODEX_ACCOUNTS"); err != nil {
		t.Fatal(err)
	}
	summary, err := s.SyncLiveAccountTargets()
	if err != nil {
		t.Fatal(err)
	}
	if summary.LiveCount != 3 || summary.Added != 1 || summary.Missing != 1 {
		t.Fatalf("wrong roster counts: %+v", summary)
	}
	newTarget := s.state.AccountTargets[accountTargetID("ccdd112233445566", "codex/gpt-6.1-sol")]
	if newTarget == nil || !newTarget.Enabled || newTarget.Missing {
		t.Fatal("replacement not auto enrolled")
	}
	oldTarget := s.state.AccountTargets[accountTargetID(departedID, "codex/gpt-6.1-sol")]
	if oldTarget == nil || !oldTarget.Missing || oldTarget.State != "quarantined_high" {
		t.Fatal("old held login must be marked missing but not forgotten")
	}
	if !s.state.Route.Quarantined[departedID] || s.state.Holds[departedID].Risk != "high" {
		t.Fatal("automatic sync cleared existing isolation")
	}
	same, _ := os.ReadFile(path)
	if string(same) != string(original) {
		t.Fatal("account monitoring sync modified Gateway Key")
	}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	dataDir := s.dir
	s.Close()
	reloaded, err := New(dataDir, filepath.Join(dataDir, "middleware.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if !reloaded.state.Route.AutoSyncAccounts || !reloaded.state.AccountTargets[accountTargetID(departedID, "codex/gpt-6.1-sol")].Missing {
		t.Fatal("auto-sync mode or tombstone did not survive restart")
	}
	if reloaded.state.Holds[departedID].Risk != "high" {
		t.Fatal("persistent high risk hold disappeared")
	}
}

func TestWidenToQuarantinedOrUnknownAccountNeverApproved(t *testing.T) {
	cases := []struct {
		name  string
		scope []string
	}{
		{"quarantined_orphan", []string{"codex/aaa", "codex/bbb", "codex/" + departedID}},
		{"unrecognized", []string{"codex/aaa", "codex/bbb", "codex/unknown"}},
		{"empty_allow_all", []string{}},
		{"different_provider", []string{"codex/aaa", "codex/bbb", "claude/new"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, path := accountSwapFixture(t)
			defer s.Close()
			swapCodexLoginFile(t, path, false, true)
			editMockKeyScope(t, path, "production", tc.scope)
			original, _ := os.ReadFile(path)
			if _, err := s.ApproveCurrentScopes(context.Background(), "APPROVE_CURRENT_PRODUCTION_SCOPES"); err == nil {
				t.Fatal("unsafe administrator edit was allowed")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(original) {
				t.Fatal("unsafe approval wrote production Key")
			}
		})
	}
}

func TestMissingHoldWithoutIdentityProofFailsClosed(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	bad := "old-email@example.com"
	s.state.Holds[bad] = QuarantineHold{Account: bad, Model: "codex/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err == nil || !strings.Contains(err.Error(), "身份") {
		t.Fatal("untrusted missing hold must be blocked")
	}
	if err := s.verifySafeReadOnlyProbes(); err == nil {
		t.Fatal("unknown quarantine was treated as safe")
	}
	_ = path
}
