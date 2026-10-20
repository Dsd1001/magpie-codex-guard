package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ConfigureController atomically stores the desired monitoring policy, then
// reconciles Magpie's production keys before reporting success. In particular,
// never leave an active quarantine controller silently disabled because one
// of several /api/config substeps failed. The caller may retry after a
// transient filesystem lock; an error is not proof that routing has changed.
func (s *Service) ConfigureController(ctx context.Context, probeKeyID string, expectedCount int, autoApply, scheduleEnabled bool, confirm string) error {
	if probeKeyID == "" || len(probeKeyID) > 120 || strings.ContainsAny(probeKeyID, "\r\n/") {
		return errors.New("请选择独立检测 Gateway Key")
	}
	if expectedCount < 0 || expectedCount > 100 {
		return errors.New("预期账号数须在 0 到 100 之间")
	}
	if autoApply {
		if expectedCount < 2 {
			return errors.New("自动隔离至少需要两个 Codex 账号")
		}
		if confirm != "ENABLE_ALL_PRODUCTION_KEYS" {
			return errors.New("必须输入明确的自动隔离授权短语")
		}
	}
	dir, err := MagpieDir()
	if err != nil {
		return err
	}
	accounts, _, keys, err := readRouterInputs(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.state.Route
	if old.Pending {
		s.mu.Unlock()
		return errors.New("路由事务尚未确认，请先检查和恢复")
	}
	if old.ProbeKeyID != "" && old.ProbeKeyID != probeKeyID && len(old.Baselines) > 0 {
		s.mu.Unlock()
		return errors.New("已有生产 Key 管理记录时不得直接更换检测专用 Key")
	}
	if old.AutoApply && !autoApply && (len(s.state.Holds) > 0 || len(old.Quarantined) > 0) {
		s.mu.Unlock()
		return errors.New("仍有隔离状态，不能直接关闭控制器；请先执行紧急恢复并确认路由")
	}
	s.state.Route.ProbeKeyID = probeKeyID
	s.state.Route.ExpectedCodexCount = expectedCount
	s.state.Route.AutoApply = autoApply
	s.state.Route.ScheduleEnabled = scheduleEnabled
	if autoApply {
		if err = verifyProbeKey(s.state, keys); err == nil {
			_, _, _, err = makeRoutingPreview(s.state, keys, accounts)
		}
		if err != nil {
			s.state.Route = old
			s.mu.Unlock()
			return err
		}
	}
	if err = s.store.Save(s.state); err != nil {
		s.state.Route = old
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if autoApply {
		if _, err = s.ApplyRouting(ctx, false); err != nil {
			s.noteSchedulerError(fmt.Errorf("策略已保存，但生产路由尚未同步：%w", err))
			return fmt.Errorf("路由未成功同步；请检查后重试：%w", err)
		}
	}
	return nil
}
