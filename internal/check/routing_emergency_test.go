package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func emergencyFixture(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "logins.json"), []byte(`[
  {"id":"aaa","agent":"codex","user":"a@example.com"},
  {"id":"bbb","agent":"codex","user":"b@example.com"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "caller-keys.json")
	b := []byte(`[
  {"id":"probe","name":"Probe","secret":"PROBE_SECRET_LONG_ENOUGH","accounts":[],"off":false},
  {"id":"production","name":"Business","secret":"PRODUCTION_SECRET_LONG_ENOUGH","accounts":[],"off":false},
  {"id":"restricted","name":"Restricted","secret":"RESTRICTED_SECRET_LONG_ENOUGH","accounts":["codex/aaa"],"off":false},
  {"id":"alreadyoff","name":"Already off","secret":"ANOTHER_SECRET_LONG_ENOUGH","accounts":[],"off":true}
 ]`)
	if err := os.WriteFile(keysPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(t.TempDir(), filepath.Join(t.TempDir(), "middleware.js"))
	if err != nil {
		t.Fatal(err)
	}
	s.state.Config = Config{GatewayURL: "http://127.0.0.1:3333", GatewayKey: "PROBE_SECRET_LONG_ENOUGH", DailyLimit: 100}
	s.state.Route = RoutingState{ProbeKeyID: "probe", AutoApply: true, ExpectedCodexCount: 2}
	s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")] = &AccountTarget{Account: "aaa", Model: "codex/gpt-6.1-sol", Enabled: true}
	s.state.AccountTargets[accountTargetID("bbb", "codex/gpt-6.1-sol")] = &AccountTarget{Account: "bbb", Model: "codex/gpt-6.1-sol", Enabled: true}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	return s, keysPath
}
func decodeKeyStates(t *testing.T, path string) map[string]privateGatewayKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ks []privateGatewayKey
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatal(err)
	}
	out := map[string]privateGatewayKey{}
	for _, k := range ks {
		out[k.ID] = k
	}
	return out
}
func TestFailClosedDisablesKeysWhenNoHealthyCodex(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "low"}
	plan, err := s.ApplyRouting(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Quarantined) != 1 {
		t.Fatal(plan.Quarantined)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off {
		t.Fatal("unrestricted key should remain enabled while healthy bbb exists")
	}
	if !reflect.DeepEqual(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatalf("scope: %v", keys["production"].Accounts)
	}
	if !keys["restricted"].Off {
		t.Fatal("restricted key with no healthy Codex must be disabled")
	}
	if keys["probe"].Off {
		t.Fatal("probe key was disabled")
	}
	if !keys["alreadyoff"].Off {
		t.Fatal("existing disabled key was enabled")
	}
	if keys["restricted"].Accounts[0] != "codex/aaa" {
		t.Fatal("do not erase original scope on disabled key")
	}

	// Now everyone is isolated. Every production Key must become OFF even
	// if its baseline accounts list was empty.
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Risk: "high"}
	plan, err = s.ApplyRouting(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Quarantined) != 2 {
		t.Fatal(plan.Quarantined)
	}
	keys = decodeKeyStates(t, path)
	for _, id := range []string{"production", "restricted", "alreadyoff"} {
		if !keys[id].Off {
			t.Fatalf("production key %s is still enabled while all accounts are held", id)
		}
	}
	if keys["probe"].Off {
		t.Fatal("probe key must remain operational")
	}
	if !s.state.Route.Quarantined["aaa"] || !s.state.Route.Quarantined["bbb"] {
		t.Fatal("quarantine journal not committed")
	}

	// Resolve one hold: restore enabled status for a key with a healthy
	// Codex account while continuing to exclude the other one.
	delete(s.state.Holds, "bbb")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off {
		t.Fatal("business key not reenabled after recovery")
	}
	if !reflect.DeepEqual(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatalf("unhealthy account got routed %v", keys["production"].Accounts)
	}
	if !keys["restricted"].Off {
		t.Fatal("scoped key should remain disabled, only aaa eligible originally")
	}
	if !keys["alreadyoff"].Off {
		t.Fatal("originally disabled key got incorrectly enabled")
	}

	delete(s.state.Holds, "aaa")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off || len(keys["production"].Accounts) > 0 {
		t.Fatal("production baseline not restored")
	}
	if keys["restricted"].Off || !reflect.DeepEqual(keys["restricted"].Accounts, []string{"codex/aaa"}) {
		t.Fatal("restricted baseline not restored")
	}
	if !keys["alreadyoff"].Off {
		t.Fatal("preexisting off status changed during recovery")
	}
	if keys["probe"].Off {
		t.Fatal("probe key changed")
	}
}
func TestExternalOffEditRefusesOverwrite(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "low"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off {
		t.Fatal("initial production should be on")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	if err := json.Unmarshal(raw, &docs); err != nil {
		t.Fatal(err)
	}
	for i := range docs {
		if docs[i]["id"] == "production" {
			docs[i]["off"] = true
		}
	}
	edited, _ := json.Marshal(docs)
	if err := os.WriteFile(path, edited, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err == nil {
		t.Fatal("externally edited status MUST conflict")
	}

}
func TestManualRestoreClearsEmergencyDisabledKeys(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "low"}
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off || keys["restricted"].Off {
		t.Fatal("restore failed to turn production keys back on")
	}
	if !keys["alreadyoff"].Off {
		t.Fatal("restore illegally enabled a previously disabled key")
	}
	if len(s.state.Holds) != 0 || s.state.Route.AutoApply {
		t.Fatalf("restore did not disable controller: %d holds", len(s.state.Holds))
	}
}

// A failed fingerprint HTTP response must NOT become a high-risk identity
// mismatch; the account is still isolated for six hours due to three
// objective failures. All four requests are charged to the daily budget.
func TestFingerprintRequestFailureIsLowRisk(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	var calls atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Magpie-Account") != "a@example.com" {
			t.Errorf("unpinned call: %s", r.Header.Get("X-Magpie-Account"))
		}
		calls.Add(1)
		var payload struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if len(payload.Messages) > 0 && strings.Contains(payload.Messages[0].Content, "1 到 355") {
			http.Error(w, "quota", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"50 inches"},"finish_reason":"stop"}],"usage":{"total_tokens":80}}`))
	}))
	defer gateway.Close()
	s.state.Config.GatewayURL = gateway.URL
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", "milk", false); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	hold, ok := s.state.Holds["aaa"]
	if !ok || hold.Risk != "low" || hold.Fingerprint.Verdict != "indeterminate" {
		t.Fatalf("incomplete samples should be low-risk: %+v", hold)
	}
	if got := time.Until(hold.NextCheckAt); got < 5*time.Hour || got > 7*time.Hour {
		t.Fatalf("first retry should be 6h: %s", got)
	}
	if hold.Fingerprint.Version != "test-bank-v1" {
		t.Fatalf("fingerprint version was lost: %+v", hold.Fingerprint)
	}
	if calls.Load() != 4 {
		t.Fatalf("expected 3 objective and 1 rejected fingerprint request, got %d", calls.Load())
	}
	day := time.Now().UTC().Format("2006-01-02")
	if s.state.Spent[day] != 4 {
		t.Fatalf("daily budget incorrectly charged %d", s.state.Spent[day])
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off || !reflect.DeepEqual(keys["production"].Accounts, []string{"codex/bbb"}) {
		t.Fatalf("failed fingerprint unexpectedly released quarantine: %+v", keys["production"])
	}
}
