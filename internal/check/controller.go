package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The count and confirmation arguments are accepted for old clients only.
// Enabling a controller is an ordinary setting, not a whitelist approval.
func (s *Service) ConfigureController(ctx context.Context, probeKeyID string, _ int, autoApply, scheduleEnabled bool, _ string) error {
	if probeKeyID == "" || len(probeKeyID) > 120 || strings.ContainsAny(probeKeyID, "\r\n/") {
		return errors.New("请选择专用检测 Key")
	}
	s.mu.Lock()
	old := s.state.Route
	s.state.Route.ProbeKeyID = probeKeyID
	if _, err := s.resolveProbeConfigLocked("", ""); err != nil {
		s.state.Route = old
		s.mu.Unlock()
		return err
	}
	for _, target := range s.state.AccountTargets {
		if target == nil || !target.Enabled || target.Missing || modelProvider(target.Model) != "codex" {
			continue
		}
		if _, err := s.resolveProbeConfigLocked(target.Account, target.Model); err != nil {
			s.state.Route = old
			s.mu.Unlock()
			return err
		}
	}
	s.state.Route.ExpectedCodexCount = 0
	s.state.Route.AutoSyncAccounts = true
	s.state.Route.AutoApply = autoApply
	s.state.Route.ScheduleEnabled = scheduleEnabled
	if err := s.store.Save(s.state); err != nil {
		s.state.Route = old
		s.mu.Unlock()
		return err
	}
	if scheduleEnabled {
		s.autoChecksPaused = false
	}
	s.mu.Unlock()
	// Disabling automatic management leaves existing permissions untouched.
	if autoApply {
		if _, err := s.ApplyRouting(ctx, false); err != nil {
			s.noteSchedulerError(fmt.Errorf("设置已保存，生产路由同步稍后重试：%w", err))
			return err
		}
	}
	select {
	case s.scheduleWake <- struct{}{}:
	default:
	}
	return nil
}
