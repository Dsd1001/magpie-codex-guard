package check

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// Modify fixture keys out-of-band just as the Magpie administrator would.
func editMockKeyScope(t *testing.T, path, id string, scope []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		var keyID string
		if err := json.Unmarshal(row["id"], &keyID); err != nil {
			t.Fatal(err)
		}
		if keyID != id {
			continue
		}
		found = true
		next, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}
		row["accounts"] = next
	}
	if !found {
		t.Fatal("missing mock key")
	}
	next, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, next, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestManualAccountPicksConvergeWithoutApproval(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	s.state.Route.ExpectedCodexCount = 99
	s.state.Route.Baselines = map[string][]string{"production": {"codex/deleted"}}
	s.state.Route.Expected = map[string][]string{"production": {"codex/not-current"}}
	for _, scope := range [][]string{
		{}, {"codex/aaa"}, {"codex/unknown", "codex/aaa"}, {"claude/keep", "codex/aaa"}, {"claude/keep"},
	} {
		editMockKeyScope(t, path, "production", scope)
		if _, err := s.ApplyRouting(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		got := decodeKeyStates(t, path)["production"]
		want := []string{"codex/bbb"}
		if slices.Contains(scope, "claude/keep") {
			want = append([]string{"claude/keep"}, want...)
		}
		if got.Off || !slices.Equal(got.Accounts, want) {
			t.Fatalf("incorrect synced accounts %v", got.Accounts)
		}
		if !s.VerifyLiveHold("aaa") {
			t.Fatal("held account was not excluded")
		}
	}
	delete(s.state.Holds, "aaa")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := decodeKeyStates(t, path)["production"].Accounts; !slices.Equal(got, []string{"claude/keep", "codex/aaa", "codex/bbb"}) {
		t.Fatal(got)
	}
}

func TestRepeatedSyncIsIdempotentAndPreservesRawFields(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	raw, _, err := loadKeyDocuments(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[1]["billing"] = json.RawMessage(`{"multiplier":1.25,"comment":"keep"}`)
	raw[1]["custom"] = json.RawMessage(`{"unknown":[1,2,3]}`)
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	stamp := s.state.Route.LastApplied
	first, _, _ := loadKeyDocuments(path)
	for i := 0; i < 3; i++ {
		if _, err := s.ApplyRouting(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || !stamp.Equal(s.state.Route.LastApplied) {
		t.Fatal("unchanged sync churned production data")
	}
	second, _, _ := loadKeyDocuments(path)
	for _, field := range []string{"secret", "name", "billing", "custom"} {
		if string(first[1][field]) != string(second[1][field]) {
			t.Fatal("changed unrelated field", field)
		}
	}
}

func TestInterruptedAccountJournalReplansLatestState(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	s.state.Route.Pending = true
	s.state.Route.Previous = map[string][]string{"production": {"codex/aaa", "codex/bbb"}}
	editMockKeyScope(t, path, "production", []string{"codex/aaa", "claude/admin-added"})
	action, err := s.RecoverRoutingJournal(context.Background())
	if err != nil || action != "reconciled" || s.state.Route.Pending {
		t.Fatalf("journal stuck: %s %v", action, err)
	}
	if got := decodeKeyStates(t, path)["production"].Accounts; !slices.Equal(got, []string{"claude/admin-added", "codex/bbb"}) {
		t.Fatal(got)
	}
}

func TestLiveQuarantineDiagnosticDetectsButDoesNotGateEdits(t *testing.T) {
	for _, scope := range [][]string{{}, {"claude/other"}, {"codex/aaa", "codex/bbb"}} {
		s, path := emergencyFixture(t)
		s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
		editMockKeyScope(t, path, "production", scope)
		if err := s.verifySafeReadOnlyProbes(); err == nil {
			s.Close()
			t.Fatal("unsafe live route passed diagnostics")
		}
		if _, err := s.ApplyRouting(context.Background(), false); err != nil {
			s.Close()
			t.Fatal(err)
		}
		if err := s.verifySafeReadOnlyProbes(); err != nil {
			s.Close()
			t.Fatal(err)
		}
		s.Close()
	}
}
