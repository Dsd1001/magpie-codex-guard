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
	if got := s.AutoPromptSettings().FingerprintMode; got != FingerprintOnFailure {
		t.Fatalf("migration should preserve original after-failures mode: %q", got)
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

func TestPeriodicFingerprintNeedsOptInAndPersists24HourTiming(t *testing.T) {
	s, count, close := fingerprintBankFixture(t)
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.TriggerFingerprint("aaa", "codex/gpt-6.1-sol", false); err == nil {
		t.Fatal("periodic trigger was allowed before opt-in")
	}
	before := *s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintPeriodic); err != nil {
		t.Fatal(err)
	}
	t1 := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if t1.ConsecutiveFails != before.ConsecutiveFails || t1.State != before.State ||
		time.Until(t1.NextFingerprintAt) < 23*time.Hour {
		t.Fatalf("enabling periodic fingerprint reset objective or scheduled immediately: %+v", t1)
	}
	// Due in the past but objective is NOT due yet.
	t1.NextFingerprintAt = time.Now().Add(-time.Minute)
	s.state.Route.ScheduleEnabled = true
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleOneAccount(time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if count.Load() != 3 || fake.call.Load() != 1 {
		t.Fatalf("periodic samples=%d eval=%d", count.Load(), fake.call.Load())
	}
	t1 = s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if t1.State != "passed" || t1.ConsecutiveFails != 0 || time.Until(t1.NextFingerprintAt) < 23*time.Hour {
		t.Fatalf("periodic fingerprint mutated objective or rescheduled badly: %+v", t1)
	}
	if len(s.state.Holds) != 0 || s.state.Route.AutoApply {
		t.Fatal("periodic fingerprint affected quarantine")
	}
	last := s.state.AccountResults[len(s.state.AccountResults)-1]
	if last.PromptName != "周期性模型指纹检测" || last.Verdict != "mismatch" {
		t.Fatalf("periodic result: %+v", last)
	}
	dir := s.dir
	next := t1.NextFingerprintAt
	s.Close()
	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	saved := reopened.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	if !next.Equal(saved.NextFingerprintAt) || reopened.AutoPromptSettings().FingerprintMode != FingerprintPeriodic {
		t.Fatal("fingerprint timer or policy did not survive restart")
	}
	reopened.Close()
	// Close original fixture's external test server without closing s twice.
	_ = close
}

func TestTurningOffFingerprintStillClassifiesObjectiveHoldLow(t *testing.T) {
	s, count, close := fingerprintBankFixture(t)
	defer close()
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	if err := s.ConfigureDetectionPrompts([]string{"milk"}, true, FingerprintOff); err != nil {
		t.Fatal(err)
	}
	fake := s.fingerprint.(*fakeFingerprint)
	if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err == nil {
		t.Fatal("fingerprint accepted as an auto objective")
	}
	// 3 objective failures still create a low-risk hold, but do not send
	// three more fingerprint probes when auto fingerprint is explicitly off.
	s.mu.Lock()
	t1 := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
	t1.ConsecutiveFails = 2
	t1.State = "suspect"
	s.mu.Unlock()
	s.mu.Lock()
	hold := startHold(*t1, time.Now())
	s.state.Holds["aaa"] = hold
	s.mu.Unlock()
	s.collectFingerprint(s.ctx, "aaa", "codex/gpt-6.1-sol")
	if count.Load() != 0 || fake.call.Load() != 1 {
		t.Fatalf("disabled mode still sampled: %d", count.Load())
	}
	got := s.state.Holds["aaa"]
	if got.Risk != "low" || got.Fingerprint.Verdict != "indeterminate" {
		t.Fatalf("disabled automatic fingerprint did not handle safe fallback: %+v", got)
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
		{"periodic_24h", 200},
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
