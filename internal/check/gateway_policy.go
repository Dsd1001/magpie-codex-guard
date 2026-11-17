package check

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// GatewayKeyScope is a REDACTED representation of Magpie's caller-keys.json.
// Never load the Secret field into this structure or send it to the web UI.
type GatewayKeyScope struct {
	ID       string   `json:"id"`
	Accounts []string `json:"accounts,omitempty"`
	Off      bool     `json:"off,omitempty"`
}

type PlannedKeyScope struct {
	CodexBlocked   bool     `json:"codex_blocked,omitempty"`
	KeyID          string   `json:"key_id"`
	Before         []string `json:"before"`
	After          []string `json:"after"`
	Changed        bool     `json:"changed"`
	IsProbe        bool     `json:"is_probe"`
	OffBefore      bool     `json:"off_before"`
	OffAfter       bool     `json:"off_after"`
	ModelsBefore   []string `json:"models_before,omitempty"`
	ModelsAfter    []string `json:"models_after,omitempty"`
	ModelsBaseline []string `json:"-"`
}

// PlanCodexQuarantine replaces only Codex account picks, using the live roster
// and latest durable decisions. Other provider picks and disabled keys remain
// untouched. With no eligible Codex account, OFF is the conservative fallback;
// attachAPIModelScopes can retain non-Codex traffic through a safe model scope.
func PlanCodexQuarantine(keys []GatewayKeyScope, probeKeyID string, knownCodex, excludedCodex []string) ([]PlannedKeyScope, error) {
	if strings.TrimSpace(probeKeyID) == "" {
		return nil, errors.New("请选择专用检测 Key")
	}
	known := map[string]string{}
	for _, id := range knownCodex {
		if err := ValidateAccount(id); err != nil {
			return nil, fmt.Errorf("账号 ID 无效：%w", err)
		}
		normalized := strings.ToLower(id)
		if strings.Contains(id, "/") || known[normalized] != "" {
			return nil, errors.New("账号 ID 格式无效或重复")
		}
		known[normalized] = id
	}
	excluded := map[string]bool{}
	for _, id := range excludedCodex {
		if known[strings.ToLower(id)] == "" {
			return nil, errors.New("隔离账号不在当前账号列表中")
		}
		excluded[strings.ToLower(id)] = true
	}
	var healthy []string
	for id, original := range known {
		if !excluded[id] {
			healthy = append(healthy, "codex/"+original)
		}
	}
	slices.Sort(healthy)
	seen, probeSeen := map[string]bool{}, false
	out := make([]PlannedKeyScope, 0, len(keys))
	for _, k := range keys {
		if k.ID == "" || seen[k.ID] {
			return nil, errors.New("Gateway Key ID 为空或重复")
		}
		seen[k.ID] = true
		plan := PlannedKeyScope{KeyID: k.ID, Before: slices.Clone(k.Accounts), After: slices.Clone(k.Accounts), OffBefore: k.Off, OffAfter: k.Off, IsProbe: k.ID == probeKeyID}
		if plan.IsProbe {
			probeSeen = true
		}
		if !plan.IsProbe && !k.Off {
			var after []string
			for _, ref := range k.Accounts {
				provider, _, ok := strings.Cut(ref, "/")
				if !ok || !strings.EqualFold(provider, "codex") {
					after = append(after, ref)
				}
			}
			after = append(after, healthy...)
			plan.After = after
			plan.CodexBlocked = len(healthy) == 0
			plan.OffAfter = plan.CodexBlocked
			plan.Changed = !slices.Equal(plan.Before, plan.After) || plan.OffAfter != k.Off
		}
		out = append(out, plan)
	}
	if !probeSeen {
		return nil, errors.New("所选专用检测 Key 不存在")
	}
	return out, nil
}
