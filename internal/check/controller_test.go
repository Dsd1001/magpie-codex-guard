package check

import (
	"context"
	"os"
	"slices"
	"testing"
)

func TestConfigureControllerNeedsNoCountApprovalAndSyncsImmediately(t *testing.T) {
	s, path := emergencyFixture(t)
	defer s.Close()
	s.state.Route.AutoApply = false
	s.state.Holds["aaa"] = QuarantineHold{Account: "aaa", Model: "codex/gpt-6.1-sol"}
	if err := s.ConfigureController(context.Background(), "probe", 0, true, true, ""); err != nil {
		t.Fatal(err)
	}
	keys := decodeKeyStates(t, path)
	for _, id := range []string{"production", "restricted"} {
		if keys[id].Off || !slices.Equal(keys[id].Accounts, []string{"codex/bbb"}) {
			t.Fatal("not synced", id)
		}
	}
	if !s.state.Route.AutoApply || !s.state.Route.ScheduleEnabled || !s.state.Route.Quarantined["aaa"] {
		t.Fatal("settings not applied")
	}
	before, _ := os.ReadFile(path)
	if err := s.ConfigureController(context.Background(), "probe", 99, false, false, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || len(s.state.Holds) != 1 {
		t.Fatal("disabling automation must not release holds or modify permissions")
	}
}

func TestConfigureControllerInvalidKeyIsAtomic(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	s.state.Route.AutoApply = false
	s.state.Route.ScheduleEnabled = false
	s.state.Route.ProbeKeyID = ""
	for _, id := range []string{"", "missing", "alreadyoff", "bad/key"} {
		if err := s.ConfigureController(context.Background(), id, 0, true, true, ""); err == nil {
			t.Fatal("invalid key accepted", id)
		}
		if s.state.Route.AutoApply || s.state.Route.ScheduleEnabled || s.state.Route.ProbeKeyID != "" {
			t.Fatal("failed config partially committed")
		}
	}
}

func TestConfigureControllerCanSwitchKeysAfterManagementHistory(t *testing.T) {
	s, _ := emergencyFixture(t)
	defer s.Close()
	if _, err := s.ApplyRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureController(context.Background(), "production", 0, true, true, ""); err != nil {
		t.Fatal("history blocked key change", err)
	}
	if s.state.Route.ProbeKeyID != "production" {
		t.Fatal("key selection not updated")
	}
}
