package check

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

func clonedScopes(input map[string][]string) map[string][]string {
	out := make(map[string][]string, len(input))
	for id, scope := range input {
		out[id] = slices.Clone(scope)
	}
	return out
}

// Read-only diagnostics, not a prerequisite for detection or reconciliation.
// Inspect the actual production permissions; the last write journal alone is
// not proof that an account is still excluded after an administrator edit.
func verifyHeldAccountsExcluded(state State, keys []privateGatewayKey, codex []CodexAccount) error {
	held := liveCodexHolds(state, codex)
	for _, key := range keys {
		if key.ID == state.Route.ProbeKeyID || key.Off || !modelScopesMayUseCodex(key.Models) {
			continue
		}
		for _, account := range held {
			if keyAllowsAccount(key.Accounts, "codex", account) {
				return errors.New("隔离账号仍在生产路由中，等待按最新检测状态同步")
			}
		}
	}
	return nil
}

func (s *Service) verifySafeReadOnlyProbes() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := MagpieDir()
	if err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held, err := lock.TryLockContext(ctx, 20*time.Millisecond)
	if err != nil || !held {
		return errors.New("无法读取正在更新的路由配置")
	}
	defer lock.Unlock()
	codex, _, keys, err := readRouterInputs(dir)
	if err != nil {
		return err
	}
	return verifyHeldAccountsExcluded(s.state, keys, codex)
}

func (s *Service) VerifyLiveHold(account string) bool {
	if err := s.verifySafeReadOnlyProbes(); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hold, held := s.state.Holds[account]
	return held && (hold.Model == "" || strings.HasPrefix(hold.Model, "codex/")) && !s.state.Route.Pending
}
