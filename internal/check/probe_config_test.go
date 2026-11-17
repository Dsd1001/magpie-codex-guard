package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGatewayDefaultEnvironmentAndLegacyCredentialMigration(t *testing.T) {
	t.Setenv("MAGPIE_CODEX_GUARD_GATEWAY_URL", "")
	dir := t.TempDir()
	s, err := New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.state.Config.GatewayURL != DefaultGatewayURL || s.state.Config.DailyLimit != 600 {
		t.Fatal("missing first-install defaults")
	}
	if err := s.Configure(Config{GatewayURL: "http://127.0.0.1:5555", GatewayKey: "must-never-save", DailyLimit: 700}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Hour)
	s.state.Route.ProbeKeyID = "saved-probe-id"
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "isolated", Since: time.Now().Add(-time.Hour), NextCheckAt: deadline}
	body, _ := json.Marshal(s.state)
	var legacy map[string]any
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["config"].(map[string]any)["gateway_key"] = "LEGACY_PLAINTEXT_MUST_BE_DISCARDED"
	body, _ = json.Marshal(legacy)
	if _, err := s.store.db.Exec("UPDATE state SET body=? WHERE id=1", body); err != nil {
		t.Fatal(err)
	}
	s.Close()
	t.Setenv("MAGPIE_CODEX_GUARD_GATEWAY_URL", "http://127.0.0.1:6666")
	s, err = New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.state.Config.GatewayURL != "http://127.0.0.1:5555" || s.state.Config.DailyLimit != 700 || s.state.Route.ProbeKeyID != "saved-probe-id" {
		t.Fatal("environment overrode saved configuration")
	}
	if !s.state.Holds["aaa"].NextCheckAt.Equal(deadline) || s.state.Config.GatewayKey != "" {
		t.Fatal("migration changed isolation or retained old credential")
	}
	if err := s.store.db.QueryRow("SELECT body FROM state WHERE id=1").Scan(&body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "gateway_key") || strings.Contains(string(body), "LEGACY_PLAINTEXT") || strings.Contains(string(body), "must-never-save") {
		t.Fatal("obsolete credential was persisted")
	}
	fresh, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.state.Config.GatewayURL != "http://127.0.0.1:6666" {
		t.Fatal("environment default ignored")
	}
}

func TestInvalidDedicatedKeyNeverUsesLegacyOrProductionCredential(t *testing.T) {
	for _, kind := range []string{"missing", "disabled", "empty", "wrong-model", "wrong-account"} {
		t.Run(kind, func(t *testing.T) {
			s, path := emergencyFixture(t)
			defer s.Close()
			s.state.Config.GatewayKey = "PRODUCTION_SECRET_LONG_ENOUGH"
			target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
			target.ConsecutiveFails, target.ConsecutiveUnavailable = 2, 2
			updateGatewayFixture(t, path, func(rows []map[string]any) {
				for _, row := range rows {
					if row["id"] != "probe" {
						continue
					}
					switch kind {
					case "missing":
						row["id"] = "deleted"
					case "disabled":
						row["off"] = true
					case "empty":
						row["secret"] = ""
					case "wrong-model":
						row["models"] = []string{"other/*"}
					case "wrong-account":
						row["accounts"] = []string{"codex/bbb"}
					}
				}
			})
			before, _ := os.ReadFile(path)
			err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", "milk", false)
			if err == nil || !isConnectionError(err) {
				t.Fatalf("missing explicit key configuration error: %v", err)
			}
			if target.ConsecutiveFails != 2 || target.ConsecutiveUnavailable != 2 || !target.RouteEligible || len(s.state.Holds) != 0 || s.accountProbeActive {
				t.Fatal("key error changed account decision")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("key error wrote production permissions")
			}
			public, _ := s.Snapshot()
			b, _ := json.Marshal(public)
			if strings.Contains(string(b), "SECRET_LONG") || strings.Contains(err.Error(), "SECRET_LONG") {
				t.Fatal("key credential leaked")
			}
		})
	}
}

func TestFingerprintRoundPinsKeyAndNextRoundUsesSwitchOrRotation(t *testing.T) {
	for _, manual := range []bool{false, true} {
		for _, rotate := range []bool{false, true} {
			name := "automatic-switch"
			if manual {
				name = "manual-switch"
			}
			if rotate {
				name += "-rotation"
			}
			t.Run(name, func(t *testing.T) {
				s, path := emergencyFixture(t)
				defer s.Close()
				s.state.Route.AutoApply = false
				s.fingerprint = &fakeFingerprint{verdict: "match"}
				started, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				var mu sync.Mutex
				var seen []string
				gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					seen = append(seen, r.Header.Get("Authorization"))
					first := len(seen) == 1
					mu.Unlock()
					if first {
						close(started)
						<-release
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"1,2,3"},"finish_reason":"stop"}],"usage":{"total_tokens":11}}`))
				}))
				defer gateway.Close()
				defer releaseOnce.Do(func() { close(release) })
				s.state.Config.GatewayURL = gateway.URL
				if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, manual); err != nil {
					t.Fatal(err)
				}
				awaitProbeSignal(t, started, "first sample did not start")
				wantNext := "Bearer PRODUCTION_SECRET_LONG_ENOUGH"
				if rotate {
					wantNext = "Bearer ROTATED_TEST_CREDENTIAL"
					updateGatewayFixture(t, path, func(rows []map[string]any) {
						for _, row := range rows {
							if row["id"] == "probe" {
								row["secret"] = "ROTATED_TEST_CREDENTIAL"
							}
						}
					})
				} else {
					if err := s.ConfigureController(context.Background(), "production", 0, false, false, ""); err != nil {
						t.Fatal(err)
					}
				}
				releaseOnce.Do(func() { close(release) })
				s.wg.Wait()
				if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, manual); err != nil {
					t.Fatal(err)
				}
				s.wg.Wait()
				mu.Lock()
				got := slices.Clone(seen)
				mu.Unlock()
				if len(got) != 6 {
					t.Fatalf("expected 6 samples, got %d", len(got))
				}
				for i, credential := range got {
					want := "Bearer PROBE_SECRET_LONG_ENOUGH"
					if i >= 3 {
						want = wantNext
					}
					if credential != want {
						t.Fatalf("sample %d mixed key credentials", i+1)
					}
				}
			})
		}
	}
}

func TestGatewayAuthenticationAndEndpointErrorsNeverAccumulateIsolationFailures(t *testing.T) {
	for _, status := range []int{401, 403, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s, _ := emergencyFixture(t)
			defer s.Close()
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "opaque gateway error", status) }))
			defer gateway.Close()
			s.state.Config.GatewayURL = gateway.URL
			target := s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")]
			target.ConsecutiveFails, target.ConsecutiveUnavailable = 2, 2
			for i := 0; i < 3; i++ {
				if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", FingerprintPromptID, false); err != nil {
					t.Fatal(err)
				}
				s.wg.Wait()
			}
			if len(s.state.Holds) != 0 || target.State != "connection_error" || target.ConsecutiveFails != 2 || target.ConsecutiveUnavailable != 2 || !target.RouteEligible {
				t.Fatalf("Gateway fault changed account decision: %+v", target)
			}
		})
	}
}

func TestUnreachableGatewayPreservesExistingHoldAndRecoveryProgress(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.state.Config.GatewayURL = gateway.URL
	gateway.Close()
	deadline := time.Now().Add(time.Hour)
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol", Risk: "isolated", NextCheckAt: deadline, ConfirmationPasses: 1}
	before := s.state.Holds["aaa"]
	if err := s.TriggerAccount("aaa", "codex/gpt-6.1-sol", "milk", false); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	after := s.state.Holds["aaa"]
	if after.ConfirmationPasses != before.ConfirmationPasses || !after.NextCheckAt.Equal(before.NextCheckAt) || s.state.AccountTargets[accountTargetID("aaa", "codex/gpt-6.1-sol")].State != "connection_error" {
		t.Fatal("connection refused changed isolation/recovery decision")
	}
}

func TestResetAndRestartDoNotImplicitlyRestoreProductionRouting(t *testing.T) {
	s, path := emergencyFixture(t)
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := s.ResetAccountStates(); err != nil {
		t.Fatal(err)
	}
	dir := s.dir
	s.Close()
	loaded, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	loaded.schedulerTick(time.Now())
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || !loaded.state.Route.AwaitingDetection {
		t.Fatal("restart changed production permissions after reset")
	}
	// A scheduler handoff selected before reset rechecks the reset marker
	// under the routing lock instead of modifying production afterwards.
	if _, err := loaded.applyAutomaticRouting(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("stale automatic routing handoff changed permissions after reset")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loaded.ApplyRouting(cancelled, false); err == nil {
		t.Fatal("cancelled routing write proceeded")
	}
	// Explicit sync is distinct from reset: pending accounts must now be excluded.
	if _, err := loaded.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !decodeKeyStates(t, path)["production"].Off {
		t.Fatal("manual sync treated pending accounts as healthy")
	}
}
