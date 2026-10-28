package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func apiFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	s, path := emergencyFixture(t)
	dir := filepath.Dir(path)
	doc := `{"providers":[{"id":"codex","key":""},{"id":"pipio","key":"isolated-test-upstream-key","models":["gpt-6.1-sol"]},{"id":"cybersol","key":"other-isolated-test-key","models":["gpt-6.1-sol"]}]}`
	if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("isolated-test-upstream-key"))
	kid := hex.EncodeToString(sum[:5])
	enrolled, _ := json.Marshal([]APIEnrollment{{Provider: "pipio", KeyID: kid, Name: "Pipio"}})
	if err := os.WriteFile(filepath.Join(dir, "api-upstreams.json"), enrolled, 0600); err != nil {
		t.Fatal(err)
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accounts {
		if a.Provider == "pipio" {
			return s, path, a.ID
		}
	}
	t.Fatal("API identity missing")
	return nil, "", ""
}

func TestAPIProbePinMatchesMagpieTraceNamespace(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	for _, tc := range []struct {
		name, keys, want string
	}{
		{"single", `[]`, "pipio"},
		{"disabled extra", `[{"key":"another-key","off":true}]`, "pipio"},
		{"duplicate", `[{"key":"isolated-test-upstream-key"}]`, "pipio"},
		{"multiple", `[{"key":"another-key"}]`, "hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"providers":[{"id":"pipio","key":"isolated-test-upstream-key","keys":` + tc.keys + `}]}`
			if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			accounts, err := discoverAPIAccounts(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.want
			if want == "hash" {
				sum := sha256.Sum256([]byte("isolated-test-upstream-key"))
				want = "pipio#" + hex.EncodeToString(sum[:5])
			}
			if len(accounts) != 1 || accounts[0].Pin != want || accounts[0].ID != id {
				t.Fatalf("unexpected API identity/pin: %+v", accounts)
			}
		})
	}
}

func TestAPIOnlyDiscoveryModelsAndIsolation(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	if err := os.Remove(filepath.Join(dir, "logins.json")); err != nil {
		t.Fatal(err)
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil || len(accounts) != 1 || accounts[0].ID != id {
		t.Fatalf("API-only discovery: %+v, %v", accounts, err)
	}
	t.Setenv("PATH", t.TempDir()) // no Magpie CLI and no Codex login
	models, err := AvailableCodexModels(context.Background(), Config{})
	if err != nil || len(models) != 1 || models[0].ID != "pipio/gpt-6.1-sol" {
		t.Fatalf("API-only model catalog: %+v, %v", models, err)
	}
	s.state.Route.ExpectedCodexCount = 0
	s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyLiveHold(id) {
		t.Fatal("API-only isolation not verified")
	}
}

func TestAPIIsolationHonorsFiniteModelScopesAndDisabledKeys(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	var rows []map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["id"] == "production" {
			row["models"] = []string{"pipio/gpt-6.1-sol"}
		}
	}
	rows = append(rows, map[string]any{"id": "disabled", "secret": "disabled-test-key", "off": true, "models": []string{"group/all"}})
	b, _ = json.Marshal(rows)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if !keys["production"].Off || !slices.Equal(keys["production"].Models, []string{"pipio/gpt-6.1-sol"}) {
		t.Fatal("last permitted API model must disable the key, not create an unrestricted scope")
	}
	if !keys["disabled"].Off || !slices.Equal(keys["disabled"].Models, []string{"group/all"}) {
		t.Fatal("administrator-disabled key was changed")
	}
	delete(s.state.Holds, id)
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	keys = decodeKeyStates(t, path)
	if keys["production"].Off || !slices.Equal(keys["production"].Models, []string{"pipio/gpt-6.1-sol"}) || !keys["disabled"].Off {
		t.Fatal("recovery failed to restore finite permission and enabled baselines")
	}
}

func TestAPIUpstreamFingerprintIsolationRecoveryAndPersistence(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		pin := "pipio"
		if payload.Model != "pipio/gpt-6.1-sol" || r.Header.Get("X-Magpie-Account") != pin {
			t.Errorf("probe was not fixed to API upstream: %q %q", payload.Model, r.Header.Get("X-Magpie-Account"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"123, 221, 9"},"finish_reason":"stop"}],"usage":{"total_tokens":10}}`))
	}))
	defer server.Close()
	s.state.Config.GatewayURL = server.URL
	s.state.Config.DailyLimit = 100
	if err := s.SetAccountTarget(id, "pipio/gpt-6.1-sol", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountTarget(id, "codex/gpt-6.1-sol", true); err == nil {
		t.Fatal("API account accepted another provider's model")
	}
	if err := s.configureTargetFingerprint(id, "pipio/gpt-6.1-sol", "gpt-6-astra"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDetectionPrompts(nil, true, FingerprintObjective); err != nil {
		t.Fatal(err)
	}
	fake := &fakeFingerprint{verdict: "mismatch"}
	s.fingerprint = fake
	if err := s.TriggerAutomaticFingerprint(id, "pipio/gpt-6.1-sol"); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(s.state.Holds) != 0 || len(decodeKeyStates(t, path)["production"].Models) != 0 {
		t.Fatal("first API mismatch changed production scope")
	}
	for n := 0; n < 2; n++ {
		if err := s.TriggerAutomaticFingerprint(id, "pipio/gpt-6.1-sol"); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if calls != 9 || s.state.Holds[id].Risk != "isolated" {
		t.Fatalf("three fingerprint mismatch rounds must quarantine after 9 samples: %d %+v", calls, s.state.Holds[id])
	}
	keys := decodeKeyStates(t, path)
	if !slices.Equal(keys["production"].Models, []string{"codex/*", "cybersol/*"}) || keys["production"].Off {
		t.Fatalf("wrong production model isolation: %+v", keys["production"])
	}
	if len(keys["probe"].Models) != 0 || keys["probe"].Off {
		t.Fatal("probe lost isolated API recovery access")
	}
	if !s.VerifyLiveHold(id) {
		t.Fatal("live API quarantine was not verified")
	}
	reopened, err := New(s.dir, s.gate)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Holds[id].Risk != "isolated" {
		t.Fatal("restart lost API hold")
	}
	reopened.Close()
	fake.verdict = "match"
	for i := 0; i < 2; i++ {
		if err := s.TriggerAutomaticFingerprint(id, "pipio/gpt-6.1-sol"); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	if _, ok := s.state.Holds[id]; ok {
		t.Fatal("two recovery passes did not release hold")
	}
	if len(decodeKeyStates(t, path)["production"].Models) != 0 {
		t.Fatal("recovery did not restore original unrestricted model scope")
	}
	target := s.state.AccountTargets[accountTargetID(id, "pipio/gpt-6.1-sol")]
	if target.NextCheckAt.Sub(target.CheckedAt) != 30*time.Minute {
		t.Fatal("API normal interval differs from 30 minutes")
	}
}

func TestAPIUnavailableAndScopeConflicts(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 429) }))
	defer server.Close()
	s.state.Config.GatewayURL = server.URL
	_ = s.SetAccountTarget(id, "pipio/gpt-6.1-sol", true)
	_ = s.configureTargetFingerprint(id, "pipio/gpt-6.1-sol", "gpt-6-astra")
	_ = s.ConfigureDetectionPrompts(nil, true, FingerprintObjective)
	if err := s.TriggerAutomaticFingerprint(id, "pipio/gpt-6.1-sol"); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(s.state.Holds) != 0 || s.state.AccountTargets[accountTargetID(id, "pipio/gpt-6.1-sol")].ConsecutiveFails != 0 {
		t.Fatal("HTTP 429 must retry without isolation or recording an incorrect answer")
	}
	s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	b, _ := os.ReadFile(path)
	_ = json.Unmarshal(b, &rows)
	for _, r := range rows {
		if r["id"] == "production" {
			r["models"] = []string{"pipio/*"}
		}
	}
	b, _ = json.Marshal(rows)
	_ = os.WriteFile(path, b, 0600)
	if _, err := s.ApplyRouting(context.Background(), false); err == nil {
		t.Fatal("out-of-band model scope edit was overwritten")
	}
	if s.VerifyLiveHold(id) {
		t.Fatal("API hold verified despite production access")
	}
	if _, _, err := apiModelScope([]string{"group/all"}, map[string]bool{"pipio": true}, []string{"codex", "pipio"}); err == nil {
		t.Fatal("ambiguous group permission accepted for API isolation")
	}
}

func TestAPIModelScopeJournalRecovery(t *testing.T) {
	for _, mode := range []string{"before", "after", "external"} {
		t.Run(mode, func(t *testing.T) {
			s, path, id := apiFixture(t)
			defer s.Close()
			_, before, err := loadKeyDocuments(path)
			if err != nil {
				t.Fatal(err)
			}
			s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
			if _, err := s.ApplyRouting(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			route := &s.state.Route
			route.Pending = true
			route.Previous = map[string][]string{}
			route.PreviousOff = map[string]bool{}
			route.ModelPrevious = map[string][]string{}
			route.PendingQuarantine = []string{id}
			for _, key := range before {
				route.Previous[key.ID] = slices.Clone(key.Accounts)
				route.PreviousOff[key.ID] = key.Off
				route.ModelPrevious[key.ID] = slices.Clone(key.Models)
			}
			if mode != "after" {
				var rows []map[string]any
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(b, &rows); err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if mode == "before" {
						row["models"] = route.ModelPrevious[row["id"].(string)]
					}
					if mode == "external" && row["id"] == "production" {
						row["models"] = []string{"cybersol/gpt-6.1-sol"}
					}
				}
				b, _ = json.Marshal(rows)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			fileBefore, _ := os.ReadFile(path)
			action, err := s.RecoverRoutingJournal(context.Background())
			fileAfter, _ := os.ReadFile(path)
			if string(fileBefore) != string(fileAfter) {
				t.Fatal("journal recovery modified live permissions")
			}
			if mode == "external" {
				if err == nil || !s.state.Route.Pending {
					t.Fatal("external model-scope edit must leave recovery blocked")
				}
				return
			}
			if err != nil || s.state.Route.Pending {
				t.Fatalf("journal recovery: %s %v", action, err)
			}
			if mode == "before" && (action != "aborted" || s.state.Route.AutoApply || len(s.state.Route.ModelExpected["production"]) != 0) {
				t.Fatal("uncommitted model scope was accepted")
			}
			if mode == "after" && (action != "completed" || !s.VerifyLiveHold(id)) {
				t.Fatal("committed model scope was not recovered")
			}
		})
	}
}
