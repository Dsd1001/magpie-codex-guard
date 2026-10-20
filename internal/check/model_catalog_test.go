package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseMagpieCodexModels(t *testing.T) {
	content := `  Codex
  codex/gpt-6.1-sol                GPT 6.1 Sol  low/medium/high
  codex/gpt-6-astra               GPT 6 Astra  low/medium
  codex/gpt-6.1-sol               duplicate
  antigravity/claude              Claude
  codex/../../private             should never be a model ID
  codex/                           invalid
  codex/not\x1b[31m               fake ANSI
  https://example.com/foo         untrusted line
  codex/gpt-5.6-luna              Luna
`
	got := ParseMagpieCodexModels(content)
	want := []string{"codex/gpt-6.1-sol", "codex/gpt-6-astra", "codex/gpt-5.6-luna"}
	if len(got) != len(want) {
		t.Fatalf("got %#v; want 3 Codex models", got)
	}
	for i, item := range got {
		if item.ID != want[i] || item.Group != "codex" {
			t.Fatalf("model %d: got %#v, want %s", i, item, want[i])
		}
	}
}

func fakeMagpieExecutable(t *testing.T, stdout string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell fixture")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" != models ] || [ \"$2\" != codex ]; then exit 19; fi\nprintf '%s\\n' '" + stdout + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "magpie"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAvailableCodexModelsWithoutProbeKey(t *testing.T) {
	fakeMagpieExecutable(t, "  codex/gpt-6.1-sol  GPT 6.1 Sol")
	models, err := AvailableCodexModels(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "codex/gpt-6.1-sol" {
		t.Fatalf("unexpected CLI models: %#v", models)
	}
}

func TestCodexModelEndpointDoesNotRequireGatewayKey(t *testing.T) {
	fakeMagpieExecutable(t, "  codex/gpt-6.1-sol  GPT 6.1 Sol")
	dir := t.TempDir()
	svc, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	access := NewGuardAccess("admin-only", "http://127.0.0.1:3030")
	request := httptest.NewRequest("GET", "http://127.0.0.1:3030/api/models", nil)
	request.Header.Set("Authorization", "Bearer admin-only")
	recorder := httptest.NewRecorder()
	svc.ManagementHandler(access).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET models HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	var models []Model
	if err := json.Unmarshal(recorder.Body.Bytes(), &models); err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "codex/gpt-6.1-sol" {
		t.Fatalf("models: %#v", models)
	}
	// A model list must never expose Gateway Key values or login tokens.
	if strings.Contains(recorder.Body.String(), "admin-only") {
		t.Fatal("control credential leaked")
	}
}

func TestAvailableCodexModelsFallbackToConfiguredGateway(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH fixture")
	}
	t.Setenv("PATH", t.TempDir()) // no magpie executable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer test-probe-key" {
			t.Errorf("wrong model request")
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"codex/gpt-6-sol"},{"id":"other/model"}]}`))
	}))
	defer server.Close()
	models, err := AvailableCodexModels(context.Background(), Config{GatewayURL: server.URL, GatewayKey: "test-probe-key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "codex/gpt-6-sol" {
		t.Fatalf("fallback models: %#v", models)
	}
}

func TestModelsWithoutCLIOrGatewayExplainFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH fixture")
	}
	t.Setenv("PATH", t.TempDir())
	_, err := AvailableCodexModels(context.Background(), Config{})
	if err == nil || !strings.Contains(err.Error(), "Magpie") {
		t.Fatalf("missing actionable error: %v", err)
	}
}
