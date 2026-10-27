package check

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fingerprintBankFixture(t *testing.T) (*Service, *atomic.Int32, func()) {
	t.Helper()
	magpie := t.TempDir()
	t.Setenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR", magpie)
	if err := os.WriteFile(filepath.Join(magpie, "logins.json"), []byte(
		"[{\"id\":\"aaa\",\"agent\":\"codex\",\"user\":\"a@example.com\"}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(magpie, "caller-keys.json"), []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.URL.Path != "/v1/chat/completions" ||
			r.Header.Get("X-Magpie-Account") != "a@example.com" ||
			r.Header.Get("Authorization") != "Bearer isolated-probe-key" {
			t.Errorf("request was not pinned to dedicated Codex probe: %s", r.URL.Path)
		}
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "codex/gpt-6.1-sol" {
			t.Errorf("bad fingerprint model: %q", body.Model)
		}
		if len(body.Messages) != 1 || !strings.Contains(body.Messages[0].Content, "1 到 355") {
			t.Error("expected an actual random integer fingerprint challenge")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":11}}`))
	}))
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	s.state.Config = Config{GatewayURL: server.URL, GatewayKey: "isolated-probe-key", DailyLimit: 60}
	s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")] = &AccountTarget{
		Account: "aaa", Model: "codex/gpt-6.1-sol", Enabled: true, State: "passed",
		ConsecutiveFails: 0, NextCheckAt: time.Now().Add(50 * time.Minute),
	}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return s, count, func() { s.Close() }
}

func TestFingerprintPromptListedButNeverObjectiveRubric(t *testing.T) {
	s, _, close := fingerprintBankFixture(t)
	defer close()
	all := s.PromptCatalog()
	found := false
	for _, p := range all {
		if p.ID == FingerprintPromptID {
			found = true
			if p.Kind != "fingerprint" || p.Automatic {
				t.Fatalf("wrong fingerprint catalog type: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("fingerprint missing from question bank")
	}
	if err := s.ConfigureAutoPrompts([]string{FingerprintPromptID}, true); err == nil {
		t.Fatal("fingerprint wrongly entered objective failure rubric")
	}
	if got := s.AutoPromptSettings().FingerprintMode; got != FingerprintOff {
		t.Fatalf("default must disable standalone fingerprint jobs: %q", got)
	}
}

func TestManualFingerprintUsesThreeSamplesWithoutTouchingHolds(t *testing.T) {
	s, count, close := fingerprintBankFixture(t)
	defer close()
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	t0 := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	t0.ConsecutiveFails = 2
	t0.State = "suspect"
	t0.NextCheckAt = time.Now().Add(2 * time.Minute)
	next := t0.NextCheckAt
	hold := QuarantineHold{
		Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "high",
		Since: time.Now().Add(-time.Hour), NextCheckAt: time.Now().Add(48 * time.Hour),
	}
	s.state.Holds["aaa"] = hold
	s.state.AutoPromptPolicy = AutoPromptPolicy{Configured: true, Rotate: true, PromptIDs: []string{"milk"}, FingerprintMode: FingerprintOff}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, true); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if count.Load() != 3 || fake.call.Load() != 1 {
		t.Fatalf("sample count=%d eval=%d", count.Load(), fake.call.Load())
	}
	t1 := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if t1.ConsecutiveFails != 2 || t1.State != "suspect" || !t1.NextCheckAt.Equal(next) {
		t.Fatalf("manual fingerprint touched objective state: %+v", t1)
	}
	if got := s.state.Holds["aaa"]; got.Risk != hold.Risk || !got.NextCheckAt.Equal(hold.NextCheckAt) {
		t.Fatalf("manual fingerprint touched quarantine: %+v", got)
	}
	last := s.state.AccountResults[len(s.state.AccountResults)-1]
	if last.Prompt != FingerprintPromptID || last.Verdict != "mismatch" || last.Fingerprint == nil {
		t.Fatalf("manual result missing: %+v", last)
	}
	if s.state.Route.AutoApply {
		t.Fatal("manual detection changed routing")
	}
}

func TestStandaloneFingerprintJobsAreRetiredAndManualIsSafe(t *testing.T) {
	s, count, close := fingerprintBankFixture(t)
	defer close()
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	if err := s.TriggerFingerprint("aaa", "codex/gpt-6.1-sol", false); err == nil {
		t.Fatal("standalone periodic fingerprint was allowed")
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintPeriodic); err == nil {
		t.Fatal("legacy periodic mode was accepted")
	}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintOnFailure); err == nil {
		t.Fatal("legacy post-failure mode was accepted")
	}
	if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, true); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if count.Load() != 3 {
		t.Fatalf("manual fingerprint should use 3 upstream samples, got %d", count.Load())
	}
	if len(s.state.Holds) != 0 {
		t.Fatal("manual fingerprint created isolation")
	}
}

func TestFingerprintReferenceCatalogAndExpectedModelValidation(t *testing.T) {
	s, _, close := fingerprintBankFixture(t)
	defer close()
	// Gateway Key is not necessary to list public local model fingerprints,
	// and the local model catalog does not send any upstream request.
	access := NewGuardAccess("control", "http://127.0.0.1:3333")
	request := httptest.NewRequest("GET", "http://127.0.0.1:3333/api/fingerprint-models", nil)
	request.Header.Set("Authorization", "Bearer control")
	response := httptest.NewRecorder()
	s.ManagementHandler(access).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reference catalog HTTP %d: %s", response.Code, response.Body.String())
	}
	var models []FingerprintModelOption
	if err := json.Unmarshal(response.Body.Bytes(), &models); err != nil {
		t.Fatal(err)
	}
	if len(models) < 20 {
		t.Fatalf("reference model catalog unexpectedly short: %d", len(models))
	}
	model := ""
	for _, m := range models {
		if m.ID == "gpt-6-astra" {
			model = m.ID
			break
		}
	}
	if model == "" {
		t.Fatal("known pinned reference model is missing")
	}
	if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", model); err != nil {
		t.Fatal(err)
	}
	if err := s.configureTargetFingerprint("aaa", "codex/gpt-6.1-sol", "attacker/some-unrecognized-model"); err == nil {
		t.Fatal("invalid model outside of pinned reference bank was accepted")
	}
	target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if target.FingerprintExpected != model {
		t.Fatal("valid reference model overwritten")
	}
	// Explicitly verify original route settings never changed.
	if s.state.Route.AutoApply {
		t.Fatal("setting fingerprint expected modified routing")
	}
}

func TestFingerprintModeAPIAndErrorContainment(t *testing.T) {
	s, _, close := fingerprintBankFixture(t)
	defer close()
	access := NewGuardAccess("control", "http://127.0.0.1:3333")
	handler := s.ManagementHandler(access)
	for _, testCase := range []struct {
		mode string
		want int
	}{
		{"objective_rotation", 200},
		{"periodic_24h", 400},
		{"unrecognized-value", 400},
		{"off", 200},
	} {
		body, err := json.Marshal(map[string]any{
			"prompt_ids": []string{"milk"}, "rotate": true, "fingerprint_mode": testCase.mode,
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "http://127.0.0.1:3333/api/auto-prompts", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer control")
		request.Header.Set("Origin", "http://127.0.0.1:3333")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != testCase.want {
			t.Fatalf("mode %q response %d expected %d: %s", testCase.mode, response.Code, testCase.want, response.Body.String())
		}
	}
	if mode := s.AutoPromptSettings().FingerprintMode; mode != FingerprintOff {
		t.Fatalf("API fingerprint mode not persisted: %q", mode)
	}
}
