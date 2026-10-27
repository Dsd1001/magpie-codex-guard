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

// PlanCodexQuarantine calculates explicit account allowlists across ALL
// production gateway keys while exempting one dedicated probe key.
//
// knownCodex and excludedCodex are MAGPIE STABLE ACCOUNT IDS WITHOUT the
// "codex/" prefix. These must come from Magpie's AccountIDs() identity,
// not an email alias chosen by the operator.
//
// The input scopes must describe each key's permissions BEFORE the
// controller started to quarantine accounts (preserved baselines). The
// empty list means "allow everything" in Magpie. In particular, restoring
// the original empty list is correct when quarantine ends; writing an
// empty list to represent "exclude every account" would FAIL OPEN.
//
// A caller can use this pure function to preview a plan, audit it, and
// only then apply it through Magpie's administrative CLI. It does not
// touch Magpie's key store or the running gateway.
func PlanCodexQuarantine(keys []GatewayKeyScope, probeKeyID string, knownCodex, excludedCodex []string) ([]PlannedKeyScope, error) {
	if strings.TrimSpace(probeKeyID) == "" {
		return nil, errors.New("必须指定独立检测 Gateway Key 的 ID")
	}
	known := map[string]string{}
	for _, id := range knownCodex {
		if err := ValidateAccount(id); err != nil {
			return nil, fmt.Errorf("账号 ID 无效：%w", err)
		}
		normalized := strings.ToLower(id)
		if strings.Contains(id, "/") {
			return nil, errors.New("账号 ID 不应包含 provider 前缀")
		}
		if _, exists := known[normalized]; exists {
			return nil, errors.New("发现重复的账号 ID")
		}
		known[normalized] = id
	}
	excluded := map[string]bool{}
	for _, id := range excludedCodex {
		n := strings.ToLower(id)
		if _, exists := known[n]; !exists {
			return nil, fmt.Errorf("未知或不再存在的待隔离账号 %q", id)
		}
		excluded[n] = true
	}
	seenKeys := map[string]bool{}
	probeSeen := false
	out := make([]PlannedKeyScope, 0, len(keys))
	for _, k := range keys {
		if k.ID == "" || seenKeys[k.ID] {
			return nil, errors.New("Gateway Key ID 为空或重复")
		}
		seenKeys[k.ID] = true
		probe := k.ID == probeKeyID
		if probe {
			probeSeen = true
		}
		before := slices.Clone(k.Accounts)
		after := slices.Clone(k.Accounts)
		// A Gateway Key that the administrator already disabled must never
		// have its allowlist rewritten. Off keys have no production traffic,
		// and their original scope is retained for any explicit future review.
		if !probe && k.Off {
			out = append(out, PlannedKeyScope{
				KeyID: k.ID, Before: before, After: after, Changed: false,
				IsProbe: false, OffBefore: true, OffAfter: true,
			})
			continue
		}
		blocked := false
		if !probe && len(excluded) > 0 {
			hadCodex := false
			var permitted []string
			for _, ref := range before {
				prefix, id, ok := strings.Cut(ref, "/")
				if !ok {
					return nil, fmt.Errorf("Key %s 原始白名单包含无效条目", k.ID)
				}
				if !strings.EqualFold(prefix, "codex") {
					permitted = append(permitted, ref)
					continue
				}
				hadCodex = true
				if !excluded[strings.ToLower(id)] {
					permitted = append(permitted, ref)
				}
			}
			if !hadCodex {
				// Magpie treats a provider NOT named in an account allowlist as
				// unrestricted. Always name every healthy Codex account.
				ids := slices.SortedFunc(func(yield func(string) bool) {
					for _, id := range known {
						if !excluded[strings.ToLower(id)] && !yield(id) {
							return
						}
					}
				}, strings.Compare)
				for _, id := range ids {
					permitted = append(permitted, "codex/"+id)
				}
			}
			canUseCodex := slices.ContainsFunc(permitted, func(v string) bool {
				return strings.HasPrefix(strings.ToLower(v), "codex/")
			})
			if !canUseCodex {
				// There is no valid Codex account to name. Magpie's empty list
				// means ALLOW ALL, unknown sentinel ids fail its CleanAccounts,
				// and a list naming only other providers ALSO allows all Codex.
				// Temporarily turn this production Key OFF, including unrelated
				// provider traffic, until a Codex account is healthy again.
				// Keep original account allowlist untouched for exact recovery.
				blocked = true
			} else {
				after = permitted
			}
		}
		offAfter := k.Off || blocked
		out = append(out, PlannedKeyScope{
			KeyID: k.ID, Before: before, After: after,
			Changed: !slices.Equal(before, after) || k.Off != offAfter,
			IsProbe: probe, OffBefore: k.Off, OffAfter: offAfter,
		})
	}
	if !probeSeen {
		return nil, errors.New("找不到检测专用 Key：拒绝更新任何生产 Key")
	}
	return out, nil
}
