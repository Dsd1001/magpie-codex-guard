package check

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const DefaultGatewayURL = "http://127.0.0.1:3425"

// The environment changes only the default, never a saved custom URL.
func defaultGatewayURL() string {
	if value := strings.TrimSpace(os.Getenv("MAGPIE_CODEX_GUARD_GATEWAY_URL")); value != "" {
		return value
	}
	return DefaultGatewayURL
}

type probeConnectionError struct{ message string }

func (e *probeConnectionError) Error() string { return e.message }
func connectionError(message string) error    { return &probeConnectionError{message: message} }
func isConnectionError(err error) bool {
	var target *probeConnectionError
	return errors.As(err, &target)
}

func probeKeyByID(keys []privateGatewayKey, id string) (privateGatewayKey, error) {
	if id == "" {
		return privateGatewayKey{}, connectionError("请选择专用检测 Key")
	}
	var found *privateGatewayKey
	for i := range keys {
		if keys[i].ID != id {
			continue
		}
		if found != nil {
			return privateGatewayKey{}, connectionError("专用检测 Key ID 重复，请检查 Magpie 配置")
		}
		found = &keys[i]
	}
	if found == nil {
		return privateGatewayKey{}, connectionError("专用检测 Key 不存在，请重新选择")
	}
	if found.Off {
		return privateGatewayKey{}, connectionError("专用检测 Key 已被禁用")
	}
	if strings.TrimSpace(found.Secret) == "" {
		return privateGatewayKey{}, connectionError("专用检测 Key 没有有效凭证")
	}
	return *found, nil
}

func keyAllowsModel(models []string, model string) bool {
	if len(models) == 0 {
		return true
	}
	for _, scope := range models {
		if scope == "*" || scope == model {
			return true
		}
		if matched, _ := path.Match(scope, model); matched {
			return true
		}
	}
	return false
}

func keyAllowsAccount(accounts []string, provider, account string) bool {
	named := false
	for _, ref := range accounts {
		p, id, ok := strings.Cut(ref, "/")
		if !ok || !strings.EqualFold(p, provider) {
			continue
		}
		named = true
		if strings.EqualFold(id, account) {
			return true
		}
	}
	// Magpie scopes account picks per provider. An absent provider is unrestricted.
	return !named
}

// Caller holds s.mu. The secret exists only in the returned round snapshot;
// it is never copied to persistent state, a browser response, or an error.
func (s *Service) resolveProbeConfigLocked(account, model string) (Config, error) {
	cfg := s.state.Config
	cfg.GatewayKey = ""
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = defaultGatewayURL()
	}
	if err := ValidateGateway(cfg.GatewayURL); err != nil {
		return cfg, connectionError(err.Error())
	}
	dir, err := MagpieDir()
	if err != nil {
		return cfg, connectionError("无法定位 Magpie 检测 Key 配置")
	}
	_, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
	if err != nil {
		return cfg, connectionError("无法读取 Magpie 检测 Key 配置：" + err.Error())
	}
	key, err := probeKeyByID(keys, s.state.Route.ProbeKeyID)
	if err != nil {
		return cfg, err
	}
	if model != "" && !keyAllowsModel(key.Models, model) {
		return cfg, connectionError("专用检测 Key 没有检测模型权限：" + model)
	}
	if account != "" && !keyAllowsAccount(key.Accounts, modelProvider(model), account) {
		return cfg, connectionError("专用检测 Key 无权检测该账号，请在 Magpie 中开放检测账号权限")
	}
	cfg.GatewayKey = key.Secret
	cfg.ProbeKeyID = key.ID
	return cfg, nil
}

type probeConfigContextKey struct{}

func withProbeConfig(ctx context.Context, cfg Config) context.Context {
	return context.WithValue(ctx, probeConfigContextKey{}, cfg)
}

// A round keeps its original key even when another key is selected or rotated.
// The next round resolves the current secret from caller-keys.json again.
func (s *Service) reserveRequest(round ...context.Context) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cfg Config
	if len(round) > 0 {
		if err := round[0].Err(); err != nil {
			return cfg, err
		}
		cfg, _ = round[0].Value(probeConfigContextKey{}).(Config)
	}
	if cfg.GatewayKey == "" {
		var err error
		cfg, err = s.resolveProbeConfigLocked("", "")
		if err != nil {
			return cfg, err
		}
	}
	if err := s.reserveBudgetLocked(cfg.DailyLimit); err != nil {
		return cfg, connectionError(err.Error())
	}
	return cfg, nil
}

// A failed local connection is not evidence about a Codex login. Upstream
// request timeouts retain the existing unavailable/retry policy.
func classifyProbeTransportError(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return connectionError("无法连接检测 Gateway，请检查 URL、端口和容器网络")
	}
	return err
}

// On ambiguous 401/403/404 responses, distinguish the Gateway credentials or
// endpoint from a real upstream account failure. /models does not call an LLM
// or consume an upstream sampling budget. Never copy an error response body.
func classifyProbeHTTPError(ctx context.Context, cfg Config, model string, status int) error {
	if status == 403 {
		return connectionError("检测 Gateway 拒绝访问（HTTP 403），请检查专用 Key 权限")
	}
	if (status == 401 || status == 404) && cfg.ProbeKeyID != "" {
		dir, err := MagpieDir()
		if err != nil {
			return connectionError("无法验证专用检测 Key 配置")
		}
		_, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
		if err != nil {
			return connectionError("无法读取专用检测 Key 配置")
		}
		key, err := probeKeyByID(keys, cfg.ProbeKeyID)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(key.Secret), []byte(cfg.GatewayKey)) != 1 {
			return connectionError("检测 Key 凭证已轮换，本轮作废，下一轮使用新凭证")
		}
		if !keyAllowsModel(key.Models, model) {
			return connectionError("专用检测 Key 的模型权限已变更")
		}
		models, err := Models(ctx, cfg)
		if err != nil {
			return connectionError(fmt.Sprintf("检测 Gateway 连接或鉴权失败（HTTP %d），请检查 URL 和专用 Key", status))
		}
		found := false
		for _, candidate := range models {
			found = found || candidate.ID == model
		}
		if !found {
			return connectionError("检测模型未在 Gateway 模型列表中提供，请检查模型配置")
		}
	}
	return &gatewayHTTPStatusError{status: status}
}
