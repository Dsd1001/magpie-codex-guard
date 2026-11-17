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

func TestAPIOnlyDiscoveryCannotBeQuarantinedByLegacyHolds(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	dir := filepath.Dir(path)
	if err := os.Remove(filepath.Join(dir, "logins.json")); err != nil {
		t.Fatal(err)
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil || len(accounts) != 1 || accounts[0].ID != id {
		t.Fatalf("API discovery: %v %v", accounts, err)
	}
	t.Setenv("PATH", t.TempDir())
	models, err := AvailableCodexModels(context.Background(), Config{})
	if err != nil || len(models) != 1 || models[0].ID != "pipio/gpt-6.1-sol" {
		t.Fatalf("API manual catalog: %v %v", models, err)
	}
	setGatewayModelFixture(t, path, "production", []string{"pipio/gpt-6.1-sol"})
	s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
	before := decodeKeyStates(t, path)["production"]
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after := decodeKeyStates(t, path)["production"]
	if after.Off != before.Off || !slices.Equal(after.Models, before.Models) || !slices.Equal(after.Accounts, before.Accounts) {
		t.Fatal("legacy API hold changed API-only key")
	}
	if s.VerifyLiveHold(id) {
		t.Fatal("plugin claimed ownership of non-Codex isolation")
	}
}

func TestNonCodexKeysAndDisabledKeysNeverChange(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	setGatewayModelFixture(t, path, "production", []string{"pipio/gpt-6.1-sol"})
	setGatewayModelFixture(t, path, "alreadyoff", []string{"group/all"})
	s.state.Holds[id] = QuarantineHold{Account: id, Model: "pipio/gpt-6.1-sol", Risk: "high"}
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	s.state.Holds["bbb"] = QuarantineHold{Account: "bbb", Model: "codex/gpt-6.1-sol"}
	before := decodeKeyStates(t, path)
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after := decodeKeyStates(t, path)
	for _, key := range []string{"production", "alreadyoff", "probe"} {
		if after[key].Off != before[key].Off || !slices.Equal(after[key].Models, before[key].Models) || !slices.Equal(after[key].Accounts, before[key].Accounts) {
			t.Fatal("unmanaged key changed", key)
		}
	}
}

func TestLegacyAPITargetSupportsManualDiagnosisButNoAutomaticIsolation(t *testing.T) {
	s, path, id := apiFixture(t)
	defer s.Close()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Magpie-Account") != "pipio" || r.Header.Get("Authorization") != "Bearer PROBE_SECRET_LONG_ENOUGH" {
			t.Error("incorrect manual probe pin or credential")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":11}}`))
	}))
	defer server.Close()
	s.state.Config.GatewayURL = server.URL
	model := "pipio/gpt-6.1-sol"
	target := &AccountTarget{Account: id, Model: model, Enabled: true, State: "unverified", FingerprintExpected: "gpt-6-astra"}
	s.state.AccountTargets[accountTargetID(id, model)] = target
	s.fingerprint = &fakeFingerprint{verdict: "mismatch"}
	if err := s.TriggerAccount(id, model, FingerprintPromptID, false); err == nil {
		t.Fatal("non-Codex automatic isolation unexpectedly enabled")
	}
	if calls != 0 || target.State != "unverified" {
		t.Fatal("rejected automatic probe changed state")
	}
	before, _ := os.ReadFile(path)
	if err := s.TriggerAccount(id, model, FingerprintPromptID, true); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	after, _ := os.ReadFile(path)
	if calls != 3 || len(s.state.Holds) != 0 || target.State != "unverified" || string(before) != string(after) {
		t.Fatal("manual diagnosis affected routing or isolation")
	}
}

func TestTemporaryCodexRestrictionsPreserveAdministratorProviderEdits(t *testing.T) {
	s, path, _ := apiFixture(t)
	defer s.Close()
	setGatewayModelFixture(t, path, "production", []string{"codex/*", "pipio/*", "cybersol/*"})
	for _, id := range []string{"aaa", "bbb"} {
		s.state.Holds[id] = QuarantineHold{Account: id, Model: "codex/gpt-6.1-sol"}
	}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	setGatewayModelFixture(t, path, "production", []string{"pipio/gpt-6.1-sol"})
	s.state.Route.Pending = true // restart after an interrupted previous sync
	if _, err := s.RecoverRoutingJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := decodeKeyStates(t, path)["production"]
	if got.Off || !slices.Equal(got.Models, []string{"pipio/gpt-6.1-sol"}) {
		t.Fatal("independent-provider edits lost during pending recovery")
	}
	delete(s.state.Holds, "bbb")
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got = decodeKeyStates(t, path)["production"]
	if got.Off || !slices.Contains(got.Models, "codex/*") || !slices.Contains(got.Models, "pipio/gpt-6.1-sol") || slices.Contains(got.Models, "cybersol/*") {
		t.Fatal("Codex recovery overwrote newer unrelated provider permissions", got.Models)
	}
}
