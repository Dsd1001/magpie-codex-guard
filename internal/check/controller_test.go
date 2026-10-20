package check

import (
	"context"
	"strings"
	"testing"
)

func TestConfigureControllerImmediatelyExcludesHeldAccount(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	// New installs start as observe-only until explicitly opted in.
	s.state.Route.AutoApply = false
	s.state.Route.ScheduleEnabled = false
	s.state.Route.ExpectedCodexCount = 0
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Risk: "low"}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	err := s.ConfigureController(context.Background(), "probe", 2, true, true, "ENABLE_ALL_PRODUCTION_KEYS")
	if err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	if keys["production"].Off {
		t.Fatal("normal production Key unexpectedly disabled")
	}
	if got := strings.Join(keys["production"].Accounts, ","); got != "codex/bbb" {
		t.Fatalf("production key did not exclude held aaa: %s", got)
	}
	if !keys["restricted"].Off {
		t.Fatal("restricted key must be disabled because it has no healthy accounts")
	}
	if keys["probe"].Off {
		t.Fatal("probe Key was disabled")
	}
	if !s.state.Route.AutoApply || !s.state.Route.ScheduleEnabled {
		t.Fatal("controller settings were not persisted")
	}
	if !s.state.Route.Quarantined["aaa"] {
		t.Fatal("controller returned before routing was synchronized")
	}

	// Disabling while a hold exists must not allow an inconsistent state.
	err = s.ConfigureController(context.Background(), "probe", 2, false, false, "")
	if err == nil {
		t.Fatal("disabling with live quarantines should require manual restore")
	}
	if !s.state.Route.AutoApply {
		t.Fatal("controller was unexpectedly disabled")
	}
}
func TestConfigureControllerValidationIsAtomic(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	s.state.Route.AutoApply = false
	s.state.Route.ScheduleEnabled = false
	s.state.Route.ExpectedCodexCount = 0
	s.state.Route.ProbeKeyID = ""
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		probe   string
		count   int
		confirm string
	}{
		{"probe", 2, "wrong_confirmation"},
		{"probe", 1, "ENABLE_ALL_PRODUCTION_KEYS"},
		{"missing", 2, "ENABLE_ALL_PRODUCTION_KEYS"},
	} {
		err := s.ConfigureController(context.Background(), tc.probe, tc.count, true, true, tc.confirm)
		if err == nil {
			t.Fatalf("should have rejected bad config %+v", tc)
		}
		if s.state.Route.AutoApply || s.state.Route.ScheduleEnabled ||
			s.state.Route.ExpectedCodexCount != 0 || s.state.Route.ProbeKeyID != "" {
			t.Fatalf("partial state mutation after error: %+v", s.state.Route)
		}
	}
}
