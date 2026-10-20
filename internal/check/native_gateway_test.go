package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCodexProbeRoutesWithoutGatewayMiddleware(t *testing.T) {
	magpie := t.TempDir()
	t.Setenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR", magpie)
	if err := os.WriteFile(filepath.Join(magpie, "logins.json"), []byte(`[{"id":"acct-1","agent":"codex","user":"one@example.com"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" ||
			r.Header.Get("X-Magpie-Account") != "one@example.com" ||
			r.Header.Get("Authorization") != "Bearer dedicated-probe-test-key" {
			t.Errorf("missing dedicated key, native endpoint, or account pin")
			http.Error(w, "unauthorized", 401)
			return
		}
		body := struct {
			Model string `json:"model"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if body.Model != "codex/gpt-6.1-sol" {
			t.Errorf("non-native model: %q", body.Model)
			http.Error(w, "unknown model", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"46.24 inches"},"finish_reason":"stop"}],"usage":{"total_tokens":16}}`))
	}))
	defer gateway.Close()

	// A previously installed gateway middleware file must not be rewritten:
	// the new guard should never need a global request hook.
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate.middleware.js")
	original := []byte("export function onRequest(body) { return body; }\n")
	if err := os.WriteFile(gate, original, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Config = Config{GatewayURL: gateway.URL, GatewayKey: "dedicated-probe-test-key", DailyLimit: 10}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(original) {
		t.Fatal("guard rewrote unrelated Magpie middleware")
	}
	answer, tokens, err := CallAccount(context.Background(), s.state.Config, "codex/gpt-6.1-sol", "acct-1", "milk")
	if err != nil || answer != "46.24 inches" || tokens != 16 {
		t.Fatalf("native route failed: answer=%q tokens=%d error=%v", answer, tokens, err)
	}
}

func TestMagpieNotFoundDoesNotExposeRemoteErrorBody(t *testing.T) {
	magpie := t.TempDir()
	t.Setenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR", magpie)
	if err := os.WriteFile(filepath.Join(magpie, "logins.json"), []byte(`[{"id":"acct-1","agent":"codex","user":"one@example.com"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("sensitive upstream detail: secret-for-diagnostic-only"))
	}))
	defer gateway.Close()
	_, _, err := CallAccount(context.Background(), Config{GatewayURL: gateway.URL, GatewayKey: "test-dedicated"}, "codex/gpt-6.1-sol", "acct-1", "milk")
	if err == nil || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "secret-for-diagnostic-only") {
		t.Fatalf("unsafe or missing diagnostic for missing model: %v", err)
	}
}
