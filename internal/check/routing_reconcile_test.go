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

func TestAdminNarrowingRebasesWithoutWritingAndNeverRestoresRemovedAccount(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	// Add a Free login that is not monitored and explicitly permitted before
	// it is removed by the administrator.
	extra := []map[string]string{
		{"id": "aaa", "agent": "codex", "user": "a@example.com"},
		{"id": "bbb", "agent": "codex", "user": "b@example.com"},
		{"id": "ccc", "agent": "codex", "user": "free@example.com"},
	}
	data, _ := json.Marshal(extra)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "logins.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s.state.Route.ExpectedCodexCount = 3
	editMockKeyScope(t, path, "production", []string{"codex/aaa", "codex/bbb", "codex/ccc"})
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := decodeKeyStates(t, path)["production"].Accounts; !reflect.DeepEqual(got, []string{"codex/bbb", "codex/ccc"}) {
		t.Fatal(got)
	}
	editMockKeyScope(t, path, "production", []string{"codex/bbb"})
	before, _ := os.ReadFile(path)
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("admin scope was rewritten")
	}
	if !reflect.DeepEqual(s.state.Route.Baselines["production"], []string{"codex/aaa", "codex/bbb"}) {
		t.Fatal(s.state.Route.Baselines["production"])
	}
	if !reflect.DeepEqual(s.state.Route.Expected["production"], []string{"codex/bbb"}) {
		t.Fatal(s.state.Route.Expected["production"])
	}
	if !s.state.Route.Quarantined["aaa"] || len(s.state.Holds) != 1 {
		t.Fatal("existing isolation removed")
	}
	audit := s.state.Route.Audit
	if len(audit) == 0 || audit[len(audit)-1].Action != "admin-scope-narrowing-accepted" {
		t.Fatalf("audit=%v", audit)
	}
	delete(s.state.Holds, "aaa")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := decodeKeyStates(t, path)["production"].Accounts
	if !reflect.DeepEqual(got, []string{"codex/aaa", "codex/bbb"}) {
		t.Fatalf("Free account was resurrected: %v", got)
	}
}

func TestScopeAdditionNeverAutoAdoptedButHealthyProbeAllowed(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "high", Model: "codex/gpt-6.1-sol", NextCheckAt: time.Now().Add(48 * time.Hour)}
	s.state.Route.ScheduleEnabled = true
	var calls atomic.Int32
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer PROBE_SECRET_LONG_ENOUGH" ||
			r.Header.Get("X-Magpie-Account") != "b@example.com" {
			t.Error("call was not using the independent detection key and account")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": "50 inches"}, "finish_reason": "stop"}},
			"usage":   map[string]int{"total_tokens": 20},
		})
	}))
	defer gw.Close()
	s.state.Config.GatewayURL = gw.URL
	a := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	a.NextCheckAt = time.Now().Add(48 * time.Hour)
	b := s.state.AccountTargets[accountTargetID("bbb", "codex/gpt-6.1-sol")]
	b.State = "passed"
	b.NextCheckAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// Unknown account is an addition, not a safe admin deletion.
	editMockKeyScope(t, path, "production", []string{"codex/bbb", "codex/extra"})
	before, _ := os.ReadFile(path)
	if _, err := s.ApplyRouting(context.Background(), false); err == nil {
		t.Fatal("scope widening was accepted")
	}
	if err := s.verifySafeReadOnlyProbes(); err != nil {
		t.Fatalf("held account excluded: %v", err)
	}
	s.schedulerTick(time.Now())
	s.wg.Wait()
	if calls.Load() != 0 {
		t.Fatalf("new checks must stop when routing cannot isolate an unavailable account: %d", calls.Load())
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("gateway scope was overwritten")
	}
	if !reflect.DeepEqual(s.state.Route.Expected["production"], []string{"codex/bbb"}) {
		t.Fatal("scope widened in database")
	}
	// No third failure is permitted while the write-capable controller is
	// blocked, so no potentially unisolated NEW hold can arise.
	b.State = "suspect"
	b.ConsecutiveFails = 2
	b.NextCheckAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	s.schedulerTick(time.Now().Add(3 * time.Minute))
	s.wg.Wait()
	if calls.Load() != 0 {
		t.Fatal("an unheld account was checked without isolation guarantee")
	}
	if _, hold := s.state.Holds["bbb"]; hold {
		t.Fatal("new unisolated hold created")
	}
}

func TestUnsafeLiveScopesBlockFallback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope []string
	}{
		{"empty_means_allow_all", []string{}},
		{"other_provider_unscoped_codex", []string{"claude/x"}},
		{"quarantined_account_present", []string{"codex/aaa", "codex/bbb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := emergencyFixture(t)
			defer s.Close()
			s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "high", Model: "codex/gpt-6.1-sol"}
			if _, err := s.ApplyRouting(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			editMockKeyScope(t, path, "production", tc.scope)
			if err := s.verifySafeReadOnlyProbes(); err == nil {
				t.Fatal("unsafe route was called safe")
			}
			before, _ := os.ReadFile(path)
			s.schedulerTick(time.Now())
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("controller overwrote admin edit")
			}
			if !strings.Contains(s.state.Route.LastError, "隔离账号") &&
				!strings.Contains(s.state.Route.LastError, "白名单") &&
				!strings.Contains(s.state.Route.LastError, "Codex") {
				t.Fatalf("unsafe route did not surface error: %s", s.state.Route.LastError)
			}
		})
	}
}
