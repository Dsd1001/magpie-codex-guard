package check

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func updateGatewayFixture(t *testing.T, path string, update func([]map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	update(rows)
	b, err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func setGatewayModelFixture(t *testing.T, path, id string, models []string) {
	t.Helper()
	updateGatewayFixture(t, path, func(rows []map[string]any) {
		for _, row := range rows {
			if row["id"] == id {
				row["models"] = models
				return
			}
		}
		t.Fatalf("key %s not found", id)
	})
}

func TestCodexQuarantineOnlyChangesAccountPicksAndPreservesOtherProviders(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	providerDoc := `{"providers":[{"id":"codex"},{"id":"cybersol"},{"id":"gemini"}]}`
	if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(providerDoc), 0600); err != nil {
		t.Fatal(err)
	}
	setGatewayModelFixture(t, path, "production", []string{"codex/*", "cybersol/*"})
	setGatewayModelFixture(t, path, "restricted", []string{"cybersol/*"})
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off || !slices.Equal(keys["production"].Accounts, []string{"codex/bbb"}) ||
		!slices.Equal(keys["production"].Models, []string{"codex/*", "cybersol/*"}) {
		t.Fatalf("one held Codex account must change only account picks: %+v", keys["production"])
	}
	if keys["restricted"].Off || !slices.Equal(keys["restricted"].Models, []string{"cybersol/*"}) {
		t.Fatalf("cybersol-only key should stay enabled: %+v", keys["restricted"])
	}
	if !s.VerifyLiveHold("aaa") {
		t.Fatal("held account must not route through either key")
	}

	// Simulate an administrator adding an unrelated model permission. Guard
	// must adopt the live models without widening held Codex account picks.
	setGatewayModelFixture(t, path, "production", []string{"codex/*", "cybersol/*", "gemini/*"})
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatalf("unrelated provider edit blocked Codex quarantine: %v", err)
	}
	keys = decodeKeyStates(t, path)
	if !slices.Equal(keys["production"].Models, []string{"codex/*", "cybersol/*", "gemini/*"}) ||
		!slices.Equal(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatal("Guard clobbered administrator provider permissions")
	}
	if !slices.Equal(s.state.Route.ModelBaselines["production"], keys["production"].Models) {
		t.Fatal("Guard did not adopt current unowned model baseline")
	}

	// All Codex accounts are quarantined. Explicit unrelated providers must
	// remain usable; only the Codex model permission is removed temporarily.
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off || !slices.Equal(keys["production"].Models, []string{"cybersol/*", "gemini/*"}) {
		t.Fatalf("all Codex held should not turn off independent providers: %+v", keys["production"])
	}
	if keys["restricted"].Off || !slices.Equal(keys["restricted"].Models, []string{"cybersol/*"}) {
		t.Fatalf("already cybersol-only key changed: %+v", keys["restricted"])
	}
	if !s.VerifyLiveHold("aaa") || !s.VerifyLiveHold("bbb") {
		t.Fatal("held Codex accounts not excluded by model fallback")
	}
	if !slices.Equal(decodeKeyStates(t, path)["production"].Models, []string{"cybersol/*", "gemini/*"}) {
		t.Fatal("model fallback drift")
	}

	// Restore one Codex account. Guard must automatically restore the exact
	// administrator-selected model list, preserving cybersol and gemini.
	delete(s.state.Holds, "bbb")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off || !slices.Equal(keys["production"].Models, []string{"codex/*", "cybersol/*", "gemini/*"}) ||
		!slices.Equal(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatalf("recovery failed: %+v", keys["production"])
	}
	if !s.VerifyLiveHold("aaa") {
		t.Fatal("first held Codex account was accidentally restored")
	}

	delete(s.state.Holds, "aaa")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off || len(keys["production"].Accounts) != 0 || !slices.Equal(keys["production"].Models, []string{"codex/*", "cybersol/*", "gemini/*"}) {
		t.Fatalf("full recovery changed unrelated provider configuration: %+v", keys["production"])
	}
}

func TestCodexModelFallbackRejectsExternalAccessWidening(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(`{"providers":[{"id":"codex"},{"id":"cybersol"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	setGatewayModelFixture(t, path, "production", []string{"codex/*", "cybersol/*"})
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if decodeKeyStates(t, path)["production"].Off {
		t.Fatal("healthy external provider was disabled")
	}
	// Reintroducing codex/* is now an unsafe modification of Guard's active
	// temporary Codex model block, not an independent provider edit.
	setGatewayModelFixture(t, path, "production", []string{"codex/*", "cybersol/*"})
	if _, err := s.ApplyRouting(context.Background(), false); err == nil || !strings.Contains(err.Error(), "model scope changed") {
		t.Fatalf("model bypass was not detected: %v", err)
	}
}

func TestCodexAccountIsolationPreservesAbsentModelField(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]json.RawMessage
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		var id string
		_ = json.Unmarshal(row["id"], &id)
		if id == "production" {
			if _, ok := row["models"]; ok {
				t.Fatal("Codex account-only update invented a models field")
			}
		}
	}
}

func TestCodexModelFallbackRejectsRoutingGroupAliases(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(`{"providers":[{"id":"codex"},{"id":"cybersol"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	setGatewayModelFixture(t, path, "production", []string{"group/gpt-6.1-sol"})
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !decodeKeyStates(t, path)["production"].Off {
		t.Fatal("ambiguous model group must fail closed when all Codex accounts are held")
	}
}
