package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func ValidateGateway(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("请输入有效的 Magpie HTTP(S) Gateway URL")
	}
	return nil
}

// Fixed account routing uses the same Magpie header as the old working
// account plugin; absent/unavailable logins must fail instead of falling
// back to an arbitrary other account.
var probeClient = &http.Client{
	Timeout:       180 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("禁止检测请求重定向") },
}

type Model struct {
	ID    string `json:"id"`
	Group string `json:"group"`
}

func gatewayV1(raw string) string {
	base := strings.TrimRight(raw, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	return base
}
func Models(ctx context.Context, c Config) ([]Model, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ValidateGateway(c.GatewayURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayV1(c.GatewayURL)+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GatewayKey)
	resp, err := probeClient.Do(req)
	if err != nil {
		return nil, errors.New("无法获取 Magpie 模型列表")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Magpie 模型列表 HTTP %d", resp.StatusCode)
	}
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&data); err != nil {
		return nil, errors.New("模型列表响应无效")
	}
	out := []Model{}
	for _, m := range data.Data {
		if strings.HasPrefix(m.ID, "codex/") {
			out = append(out, Model{ID: m.ID, Group: "codex"})
		}
	}
	return out, nil
}
func CallAccount(ctx context.Context, c Config, model, account, prompt string) (string, int, error) {
	pinUser, err := ResolveProbeLoginUser(account)
	if err != nil {
		return "", 0, err
	}
	payload := map[string]any{
		"model": model, "stream": false, "max_tokens": 8192,
		"messages": []any{map[string]string{"role": "user", "content": prompt}},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayV1(c.GatewayURL)+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GatewayKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Magpie-Account", pinUser)
	resp, err := probeClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", 0, errors.New("Magpie HTTP 404：模型路由不存在，或指定账号无法服务该模型；请检查 Codex 模型与账号权限")
		}
		return "", 0, fmt.Errorf("Magpie HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil {
		return "", 0, err
	}
	if len(raw) > 4*1024*1024 {
		return "", 0, errors.New("上游回复过大")
	}
	var data struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Total int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", 0, errors.New("无法解析上游模型回复")
	}
	if len(data.Choices) != 1 {
		return "", 0, errors.New("上游回复缺少唯一候选答案")
	}
	result := data.Choices[0]
	if result.Finish != "stop" {
		return result.Message.Content, data.Usage.Total, errors.New("上游回答未正常结束或被截断")
	}
	if strings.TrimSpace(result.Message.Content) == "" {
		return "", data.Usage.Total, errors.New("上游回答为空")
	}
	return result.Message.Content, data.Usage.Total, nil
}
