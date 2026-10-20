package check

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// CodexAccount is public account metadata only. Login credentials
// contained in Magpie's logins.json are never persisted or returned.
type CodexAccount struct {
	ID   string `json:"id"`
	User string `json:"user"`
}

// MagpieDir mirrors Magpie's non-portable ~/.config/magpie directory.
func MagpieDir() (string, error) {
	if p := os.Getenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR"); p != "" {
		if !filepath.IsAbs(p) {
			return "", errors.New("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR 必须是绝对路径")
		}
		return filepath.Clean(p), nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) {
			return "", errors.New("XDG_CONFIG_HOME 必须是绝对路径")
		}
		return filepath.Join(xdg, "magpie"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "magpie"), nil
}

// DiscoverCodexAccounts reads metadata from the same local Magpie instance.
// Importantly, logins.json includes auth tokens; NEVER print its contents,
// serialize it into logs, or return its raw bytes through HTTP.
func DiscoverCodexAccounts(dir string) ([]CodexAccount, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("Magpie 配置目录不是绝对路径")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "logins.json"))
	if err != nil {
		return nil, fmt.Errorf("无法读取本机 Magpie 账号信息：%w", err)
	}
	if len(raw) > 8*1024*1024 {
		return nil, errors.New("Magpie 账号信息超出安全上限")
	}
	var accounts []struct {
		ID     string `json:"id"`
		Agent  string `json:"agent"`
		User   string `json:"user"`
		Hidden string `json:"hidden,omitempty"`
	}
	if err := json.Unmarshal(raw, &accounts); err != nil {
		return nil, errors.New("Magpie 账号文件格式不正确")
	}
	ids := map[string]bool{}
	out := []CodexAccount{}
	for _, a := range accounts {
		if a.Agent != "codex" || a.Hidden != "" {
			continue
		}
		if err := ValidateAccount(a.User); err != nil {
			return nil, errors.New("Codex 账号标识无效")
		}
		id := a.ID
		if id == "" {
			sum := sha256.Sum256([]byte("magpie login\ncodex\n" + strings.ToLower(strings.TrimSpace(a.User))))
			id = hex.EncodeToString(sum[:8]) // matches Magpie v0.1.1207 loginID
		}
		if err := ValidateAccount(id); err != nil || strings.Contains(id, "/") {
			return nil, errors.New("Codex 账号稳定 ID 无效")
		}
		if ids[strings.ToLower(id)] {
			return nil, errors.New("Codex 账号出现重复的稳定 ID")
		}
		ids[strings.ToLower(id)] = true
		out = append(out, CodexAccount{ID: id, User: a.User})
	}
	if len(out) == 0 {
		return nil, errors.New("本机 Magpie 的 logins.json 没有可识别的 Codex 账号；拒绝推测可用账号")
	}
	slices.SortFunc(out, func(a, b CodexAccount) int {
		return strings.Compare(strings.ToLower(a.User), strings.ToLower(b.User))
	})
	return out, nil
}

// ResolveAccountID accepts a stable ID or the visible Magpie account name,
// returning the immutable ID used by Gateway Key allowlists.
func ResolveAccountID(accounts []CodexAccount, ref string) (string, error) {
	for _, a := range accounts {
		if strings.EqualFold(ref, a.ID) || strings.EqualFold(ref, a.User) {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("无法在 Magpie 已保存账号中找到 %q", ref)
}

// ResolveProbeLoginUser converts a stable Magpie account ID to the
// account's CURRENT login name for X-Magpie-Account.
//
// Magpie v0.1.1207 accepts the account login name or a routing trace ID
// in that HTTP header; the stable IDs in caller-keys.json are a separate
// namespace and are NOT valid account pins. Do not pass the ID through.
func ResolveProbeLoginUser(ref string) (string, error) {
	if err := ValidateAccount(ref); err != nil {
		return "", err
	}
	dir, err := MagpieDir()
	if err != nil {
		return "", err
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return "", err
	}
	for _, a := range accounts {
		if strings.EqualFold(ref, a.ID) || strings.EqualFold(ref, a.User) {
			return a.User, nil
		}
	}
	return "", fmt.Errorf("无法找到检测账号 %q 的当前登录名，已取消本轮请求以避免检测其他账号", ref)
}
