package check

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

type fakeFingerprint struct {
	verdict string
	call    atomic.Int32
}

func (f *fakeFingerprint) Evaluate(_ []fingerprint.Output, _ string) FingerprintReport {
	f.call.Add(1)
	return FingerprintReport{Verdict: f.verdict, Version: "test-bank-v1", UsedOutputs: 3, Prediction: "claude-opus-5"}
}
func TestObjectiveFingerprintIsolationAndRecoveryIntegration(t *testing.T) {
	magpie := t.TempDir()
	t.Setenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR", magpie)
	acctJSON := `[{"id":"aaa","agent":"codex","user":"a@example.com"},{"id":"bbb","agent":"codex","user":"b@example.com"}]`
	if err := os.WriteFile(filepath.Join(magpie, "logins.json"), []byte(acctJSON), 0600); err != nil {
		t.Fatal(err)
	}
	secret := "A_DEDICATED_PROBE_KEY_AAAAAAAAAAAAA"
	initial := `[{"id":"probe","name":"Probe","secret":"` + secret + `","accounts":[],"off":false},{"id":"prod","name":"Production","secret":"PRODUCTION_KEY_AAAAAAAAAAAAAAA","accounts":[],"off":false}]`
	keysPath := filepath.Join(magpie, "caller-keys.json")
	if err := os.WriteFile(keysPath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	var okAnswers atomic.Bool
	var total atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("X-Magpie-Account") != "a@example.com" {
			t.Errorf("incorrect pinned account or endpoint: %s %s", r.URL.Path, r.Header.Get("X-Magpie-Account"))
			http.Error(w, "wrong route", 500)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("wrong probe key")
		}
		total.Add(1)
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		// Every objective retry and every fingerprint sample must use
		// the native Magpie model ID, never a private quality-probe alias.
		if body.Model != "codex/gpt-6.1-sol" {
			t.Errorf("invalid native Codex route: %q", body.Model)
			http.Error(w, "unrecognized model", http.StatusNotFound)
			return
		}
		answer := "50 inches"
		if okAnswers.Load() {
			answer = "46.24 inches"
		}
		if len(body.Messages) > 0 && strings.Contains(body.Messages[0].Content, "1 到 355") {
			values := []string{}
			for i := 0; i < 315; i++ {
				if i%2 == 0 {
					values = append(values, "350")
				} else {
					values = append(values, "3")
				}
			}
			answer = strings.Join(values, ",")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": answer}, "finish_reason": "stop"}},
			"usage":   map[string]int{"total_tokens": 450},
		})
	}))
	defer srv.Close()
	data := t.TempDir()
	gate := filepath.Join(data, "gate.js")
	s, err := New(data, gate)
	if err != nil {
		t.Fatal(err)
	}
	s.state.Config = Config{GatewayURL: srv.URL, GatewayKey: secret, DailyLimit: 100}
	s.state.Route = RoutingState{ProbeKeyID: "probe", AutoApply: true, ExpectedCodexCount: 2, ScheduleEnabled: true}
	model := "codex/gpt-6.1-sol"
	id := accountTargetID("aaa", model)
	s.state.AccountTargets[id] = &AccountTarget{Account: "aaa", Model: model, Enabled: true, State: "unverified"}
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.TriggerAccount("aaa", model, "milk", false); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if calls := fake.call.Load(); calls != 1 {
		t.Fatalf("fingerprint called %d times, want once", calls)
	}
	if got := total.Load(); got != 6 {
		t.Fatalf("expected 3+3 upstream requests, got %d", got)
	}
	hold, exists := s.state.Holds["aaa"]
	if !exists || hold.Risk != "high" {
		t.Fatalf("missing high-risk hold: %+v", hold)
	}
	if time.Until(hold.NextCheckAt) < 47*time.Hour {
		t.Fatalf("high-risk schedule %s", hold.NextCheckAt)
	}
	assertKeyScopes := func(expected []string) {
		t.Helper()
		b, err := os.ReadFile(keysPath)
		if err != nil {
			t.Fatal(err)
		}
		var data []struct {
			ID       string   `json:"id"`
			Accounts []string `json:"accounts"`
		}
		if err := json.Unmarshal(b, &data); err != nil {
			t.Fatal(err)
		}
		for _, k := range data {
			if k.ID == "probe" && len(k.Accounts) != 0 {
				t.Fatalf("probe key scope changed: %v", k.Accounts)
			}
			if k.ID == "prod" {
				got := fmt.Sprint(k.Accounts)
				if got != fmt.Sprint(expected) {
					t.Fatalf("prod scope %s expected %s", got, fmt.Sprint(expected))
				}
			}
		}
	}
	assertKeyScopes([]string{"codex/bbb"})
	if !s.state.Route.Quarantined["aaa"] {
		t.Fatal("production routing did not record applied quarantine")
	}
	if err := s.CloseForTest(); err != nil {
		t.Fatal(err)
	}
	s, err = New(data, gate)
	if err != nil {
		t.Fatal(err)
	}
	s.state.Config = Config{GatewayURL: srv.URL, GatewayKey: secret, DailyLimit: 100}
	reloaded, exists := s.state.Holds["aaa"]
	if !exists || !reloaded.NextCheckAt.Equal(hold.NextCheckAt) {
		t.Fatal("lost persisted hold across restart")
	}
	okAnswers.Store(true)
	for i := 0; i < 2; i++ {
		if err := s.TriggerAccount("aaa", model, "milk", false); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if _, exists := s.state.Holds["aaa"]; exists {
		t.Fatal("two good objective answers did not release hold")
	}
	assertKeyScopes(nil)
	if s.state.Route.Quarantined["aaa"] {
		t.Fatal("production routing not restored")
	}
	if got := total.Load(); got != 8 {
		t.Fatalf("unexpected number of upstream calls: %d", got)
	}
	s.Close()
}
func (s *Service) CloseForTest() error {
	s.Close()
	return nil
}
func TestDashboardAuthentication(t *testing.T) {
	s, err := New(t.TempDir(), filepath.Join(t.TempDir(), "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	access := NewGuardAccess("server_secret", "http://127.0.0.1:23456")
	handler := s.ManagementHandler(access)
	for _, tc := range []struct {
		path     string
		expected int
	}{
		{"/health", 204}, {"/api/state", 401}, {"/", 401},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest("GET", tc.path, nil))
		if rr.Code != tc.expected {
			t.Fatalf("%s status %d, want %d", tc.path, rr.Code, tc.expected)
		}
	}
}
