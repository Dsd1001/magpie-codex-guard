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

func testAutoGroups(t *testing.T, keyPath string) string {
	t.Helper()
	dir := filepath.Dir(keyPath)
	// Four production auto routes. The third contains an administrator-
	// disabled independent member whose Off must never be lost.
	groups := []map[string]any{
		{"id": "auto-gpt-6-1-sol", "name": "gpt-6.1-sol", "members": []string{"codex/gpt-6.1-sol", "cybersol/gpt-6.1-sol"}, "routing": "order", "rules": []any{}},
		{"id": "auto-gpt-6-astra", "name": "gpt-6-astra", "members": []string{"codex/gpt-6-astra", "cybersol/gpt-6-astra"}},
		{"id": "auto-gpt-6-sol", "name": "gpt-6-sol", "members": []string{"codex/gpt-6-sol", "cybersol/gpt-6.1-sol", "backup/gpt-6-sol"}, "off": []string{"backup/gpt-6-sol"}},
		{"id": "auto-gpt-6-1-terra", "name": "gpt-6.1-terra", "members": []string{"codex/gpt-6.1-terra", "cybersol/gpt-6.1-terra"}},
		{"id": "my-other-group", "name": "My user routing", "members": []string{"other/m", "backup/m"}, "off": []string{"backup/m"}, "routing": "order"},
	}
	doc := map[string]any{"providers": []map[string]string{{"id": "cybersol", "key": "TEST_UPSTREAM_KEY_DO_NOT_USE"}, {"id": "backup"}}, "groups": groups, "groupOrder": []string{"my-other-group"}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	setGatewayModelFixture(t, keyPath, "production", []string{"codex/*", "cybersol/*"})
	return path
}

func testOffMap(t *testing.T, path string) map[string][]string {
	t.Helper()
	_, groups, err := readGroupOffDocument(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	records, err := groupOffRecords(groups)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for id, v := range records {
		out[id] = v.Off
	}
	return out
}

func editGroupOffFixture(t *testing.T, path, groupID string, off []string) {
	t.Helper()
	doc, groups, err := readGroupOffDocument(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		var id string
		_ = json.Unmarshal(group["id"], &id)
		if id == groupID {
			b, _ := json.Marshal(off)
			group["off"] = b
		}
	}
	gs, _ := json.Marshal(groups)
	doc["groups"] = gs
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAutoRoutingGroupsFullQuarantineAndRecovery(t *testing.T) {
	s, keyPath := emergencyFixture(t)
	defer s.Close()
	path := testAutoGroups(t, keyPath)
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(s.state.Route.GroupOffExpected) != 0 {
		t.Fatal("partial quarantine changed group routing")
	}

	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, keyPath)
	if keys["production"].Off || !slices.Equal(keys["production"].Models, []string{"cybersol/*"}) || keys["probe"].Off {
		t.Fatalf("all-isolated permission fallback failed: %+v", keys)
	}
	off := testOffMap(t, path)
	for id, model := range map[string]string{
		"auto-gpt-6-1-sol":   "codex/gpt-6.1-sol",
		"auto-gpt-6-astra":   "codex/gpt-6-astra",
		"auto-gpt-6-sol":     "codex/gpt-6-sol",
		"auto-gpt-6-1-terra": "codex/gpt-6.1-terra",
	} {
		if !slices.Contains(off[id], model) {
			t.Fatalf("%s must disable Codex member; got %v", id, off[id])
		}
	}
	if !slices.Equal(off["auto-gpt-6-sol"], []string{"backup/gpt-6-sol", "codex/gpt-6-sol"}) ||
		!slices.Equal(off["my-other-group"], []string{"backup/m"}) {
		t.Fatalf("user-owned group settings were overwritten: %+v", off)
	}
	if !s.VerifyLiveHold("aaa") || !s.VerifyLiveHold("bbb") {
		t.Fatal("full quarantine no longer excludes isolated Codex accounts")
	}

	// Repeating an unchanged full-isolation reconciliation must not churn.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("unchanged routing groups were rewritten")
	}

	delete(s.state.Holds, "bbb")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	off = testOffMap(t, path)
	for id, values := range off {
		if id == "auto-gpt-6-sol" && !slices.Equal(values, []string{"backup/gpt-6-sol"}) {
			t.Fatalf("admin Off lost in restored group %s: %v", id, values)
		}
		if strings.HasPrefix(id, "auto-") && id != "auto-gpt-6-sol" && len(values) != 0 {
			t.Fatalf("Codex member still Off after recovery in %s: %v", id, values)
		}
	}
	keys = decodeKeyStates(t, keyPath)
	if keys["production"].Off || !slices.Contains(keys["production"].Models, "codex/*") ||
		!slices.Equal(keys["production"].Accounts, []string{"codex/bbb"}) ||
		len(s.state.Route.GroupOffExpected) != 0 {
		t.Fatal("healthy account not restored or group Off tracking not cleared")
	}

	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol", Risk: "isolated"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, keyPath)
	if keys["production"].Off || !slices.Contains(keys["production"].Models, "codex/*") ||
		len(s.state.Route.GroupOffExpected) > 0 || len(s.state.Holds) > 0 {
		t.Fatal("manual reset did not restore baseline permissions")
	}
	if got := testOffMap(t, path)["auto-gpt-6-sol"]; !slices.Equal(got, []string{"backup/gpt-6-sol"}) {
		t.Fatalf("manual reset erased admin Off: %v", got)
	}
}

func TestAutoRoutingGroupsExternalDriftFailsClosed(t *testing.T) {
	s, keyPath := emergencyFixture(t)
	defer s.Close()
	path := testAutoGroups(t, keyPath)
	for _, id := range []string{"aaa", "bbb"} {
		s.state.Holds[id] = QuarantineHold{Account: id, Model: "codex/gpt-6.1-sol"}
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	editGroupOffFixture(t, path, "auto-gpt-6-1-sol", []string{"codex/gpt-6.1-sol", "cybersol/gpt-6.1-sol"})
	before, _ := os.ReadFile(path)
	if _, err := s.ApplyRouting(context.Background(), false); err == nil || !strings.Contains(err.Error(), "changed outside") {
		t.Fatalf("external Off drift was not refused: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("external routing group edit was overwritten")
	}
	if !slices.Equal(decodeKeyStates(t, keyPath)["production"].Models, []string{"cybersol/*"}) {
		t.Fatal("external group drift widened production key")
	}
}

func TestInterruptedGroupOffJournalCompletesAfterKeyRestriction(t *testing.T) {
	s, keyPath := emergencyFixture(t)
	defer s.Close()
	path := testAutoGroups(t, keyPath)
	for _, id := range []string{"aaa", "bbb"} {
		s.state.Holds[id] = QuarantineHold{Account: id, Model: "codex/gpt-6.1-sol"}
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// Simulate power loss between the Key-file update and providers.json
	// update. The exact Key after image is present but groups remain before.
	route := &s.state.Route
	route.Pending = true
	route.GroupOffPrevious = map[string][]string{}
	route.GroupOffTarget = map[string][]string{}
	route.GroupOffPendingMembers = map[string][]string{}
	for id, values := range route.GroupOffExpected {
		route.GroupOffTarget[id] = slices.Clone(values)
		route.GroupOffPrevious[id] = slices.Clone(route.GroupOffBaselines[id])
		_, groups, _ := readGroupOffDocument(filepath.Dir(path))
		records, _ := groupOffRecords(groups)
		route.GroupOffPendingMembers[id] = slices.Clone(records[id].Members)
		editGroupOffFixture(t, path, id, route.GroupOffBaselines[id])
	}
	route.GroupOffNextBaselines = clonedScopes(route.GroupOffBaselines)
	route.GroupOffNextExpected = clonedScopes(route.GroupOffExpected)
	route.GroupOffNextMembers = clonedScopes(route.GroupOffMembers)
	route.Previous = map[string][]string{}
	route.PreviousOff = map[string]bool{}
	route.ModelPrevious = map[string][]string{}
	for _, key := range decodeKeyStates(t, keyPath) {
		route.Previous[key.ID] = slices.Clone(key.Accounts)
		route.PreviousOff[key.ID] = key.Off
		route.ModelPrevious[key.ID] = slices.Clone(key.Models)
	}
	route.PendingQuarantine = []string{"aaa", "bbb"}
	if err := s.store.Save(s.state); err != nil {
		t.Fatal(err)
	}
	action, err := s.RecoverRoutingJournal(context.Background())
	if err != nil || action != "completed" {
		t.Fatalf("journal recovery failed: %s %v", action, err)
	}
	if s.state.Route.Pending || !slices.Contains(testOffMap(t, path)["auto-gpt-6-1-sol"], "codex/gpt-6.1-sol") {
		t.Fatal("journal completion did not restore safe group-off state")
	}
}

func TestGroupOffRefusesInterveningProviderEdit(t *testing.T) {
	s, keyPath := emergencyFixture(t)
	defer s.Close()
	path := testAutoGroups(t, keyPath)
	codex, _, _, err := readRouterInputs(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planRoutingGroupOff(filepath.Dir(path), s.state.Route, codex, []string{"aaa", "bbb"}, false)
	if err != nil || !plan.changed {
		t.Fatalf("missing isolation group plan: %v", err)
	}
	// An administrator edits a completely unrelated field after planning.
	doc, _, err := readGroupOffDocument(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	doc["adminNote"] = json.RawMessage(`"keep-me"`)
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeGroupOffDocument(filepath.Dir(path), plan); err == nil || !strings.Contains(err.Error(), "changed during") {
		t.Fatalf("provider edit unexpectedly overwritten: %v", err)
	}
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "keep-me") {
		t.Fatal("admin field lost")
	}
}

func TestManualGroupIsSkippedWithoutExposingIsolatedCodex(t *testing.T) {
	s, keyPath := emergencyFixture(t)
	defer s.Close()
	path := testAutoGroups(t, keyPath)
	doc, groups, err := readGroupOffDocument(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		var id string
		_ = json.Unmarshal(g["id"], &id)
		if id == "auto-gpt-6-1-sol" {
			g["routing"] = json.RawMessage(`"manual"`)
		}
	}
	encoded, _ := json.Marshal(groups)
	doc["groups"] = encoded
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"aaa", "bbb"} {
		s.state.Holds[id] = QuarantineHold{Account: id, Model: "codex/gpt-6.1-sol"}
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatalf("manual group should be skipped rather than block Key restrictions: %v", err)
	}
	if got := testOffMap(t, path)["auto-gpt-6-1-sol"]; len(got) != 0 {
		t.Fatalf("manual group Off was incorrectly modified: %v", got)
	}
	if key := decodeKeyStates(t, keyPath)["production"]; key.Off || !slices.Equal(key.Models, []string{"cybersol/*"}) {
		t.Fatalf("full isolation failed closed on manual group: %+v", key)
	}
}
