package check

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// hasManagedRoutes is deliberately conservative. Stored routing baselines are
// evidence that Magpie keys may still have Guard-owned restrictions, even when
// AutoApply is off or the plugin's probe key has since been removed.
func hasManagedRoutes(route RoutingState) bool {
	return route.Pending ||
		len(route.Quarantined) > 0 ||
		len(route.Baselines) > 0 || len(route.Expected) > 0 ||
		len(route.BaselineOff) > 0 || len(route.ExpectedOff) > 0 ||
		len(route.ModelBaselines) > 0 || len(route.ModelExpected) > 0
}

// makeResetRoutingPreview restores only Guard-managed fields to their recorded
// baseline. Unlike a normal quarantine preview, reset does not depend on a
// live probe key, a reference model, or an unchanged number of Codex logins.
// External edits to any tracked field are conflicts, never silently erased.
// Newly created/unmanaged keys are left exactly as they are.
func makeResetRoutingPreview(state State, keys []privateGatewayKey, codex []CodexAccount) (RoutingPreview, map[string][]string, map[string]bool, error) {
	route := state.Route
	if route.Pending {
		return RoutingPreview{}, nil, nil, errors.New("路由事务尚未完成，请先核对并恢复待处理事务")
	}
	preview := RoutingPreview{
		Mode: "observe_only", ProbeKeyID: route.ProbeKeyID,
		AccountCount: len(codex), Keys: make([]PlannedKeyScope, 0, len(keys)),
	}
	baselines := make(map[string][]string, len(keys))
	offBaselines := make(map[string]bool, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if key.ID == "" || seen[key.ID] {
			return RoutingPreview{}, nil, nil, errors.New("Gateway Key 存在空 ID 或重复 ID，拒绝重置")
		}
		seen[key.ID] = true

		accounts := slices.Clone(key.Accounts)
		if expected, tracked := route.Expected[key.ID]; tracked {
			base, exists := route.Baselines[key.ID]
			if !exists {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少原始账号白名单，拒绝重置", key.ID)
			}
			if !slices.Equal(key.Accounts, expected) {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 白名单已被外部修改，需人工核对后重置", key.ID)
			}
			accounts = slices.Clone(base)
		} else if _, hasBaseline := route.Baselines[key.ID]; hasBaseline {
			return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少路由写入记录，拒绝重置", key.ID)
		}

		off := key.Off
		if expected, tracked := route.ExpectedOff[key.ID]; tracked {
			base, exists := route.BaselineOff[key.ID]
			if !exists {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少原始启用状态，拒绝重置", key.ID)
			}
			if key.Off != expected {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 启用状态已被外部修改，需人工核对后重置", key.ID)
			}
			off = base
		} else if _, hasBaseline := route.BaselineOff[key.ID]; hasBaseline {
			return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少启用状态写入记录，拒绝重置", key.ID)
		}

		models := slices.Clone(key.Models)
		if expected, tracked := route.ModelExpected[key.ID]; tracked {
			base, exists := route.ModelBaselines[key.ID]
			if !exists {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少原始模型白名单，拒绝重置", key.ID)
			}
			if !slices.Equal(key.Models, expected) {
				return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 模型白名单已被外部修改，需人工核对后重置", key.ID)
			}
			models = slices.Clone(base)
		} else if _, hasBaseline := route.ModelBaselines[key.ID]; hasBaseline {
			return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 缺少模型写入记录，拒绝重置", key.ID)
		}

		preview.Keys = append(preview.Keys, PlannedKeyScope{
			KeyID: key.ID, Before: slices.Clone(key.Accounts), After: slices.Clone(accounts),
			OffBefore: key.Off, OffAfter: off, IsProbe: key.ID == route.ProbeKeyID,
			ModelsBefore: slices.Clone(key.Models), ModelsAfter: slices.Clone(models),
			ModelsBaseline: slices.Clone(models),
			Changed: !slices.Equal(key.Accounts, accounts) ||
				key.Off != off || !slices.Equal(key.Models, models),
		})
		baselines[key.ID] = accounts
		offBaselines[key.ID] = off
	}
	return preview, baselines, offBaselines, nil
}

// resetAllAccountMonitoringState runs only after a successful, verified route
// restoration (or if the journal proves no route was ever managed). The
// account roster, explicit settings, overrides, usage and historical results
// remain intact. Scheduling and automatic routing are switched off so an
// immediately due probe cannot recreate every hold after reset.
func resetAllAccountMonitoringState(state *State) {
	state.Holds = make(map[string]QuarantineHold)
	for _, t := range state.AccountTargets {
		if t == nil {
			continue
		}
		t.State = "unverified"
		t.Reason = ""
		t.CheckedAt = time.Time{}
		t.NextCheckAt = time.Time{}
		t.ConsecutiveFails = 0
		t.ConsecutiveUnavailable = 0
		t.UnavailablePrompt = ""
		t.ConsecutivePasses = 0
		t.LastAutoPrompt = ""
		t.PromptRotation = 0
		t.LastFingerprintAt = time.Time{}
		t.NextFingerprintAt = time.Time{}
		t.FingerprintVersion = ""
	}
	route := &state.Route
	route.AutoApply = false
	route.ScheduleEnabled = false
	route.Quarantined = nil
	route.Pending = false
	route.PendingRestore = false
	route.Previous = nil
	route.PreviousOff = nil
	route.ModelPrevious = nil
	route.PendingQuarantine = nil
	route.Baselines = nil
	route.Expected = nil
	route.ModelBaselines = nil
	route.ModelExpected = nil
	route.BaselineOff = nil
	route.ExpectedOff = nil
	route.LastError = ""
}
