package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// This is the same read-only catalog users see with 'magpie models codex'.
// Never read or expose credential-bearing Magpie login/provider JSON just to
// populate a dropdown. Probe credentials remain necessary for actual probes.
var codexModelID = regexp.MustCompile(`^codex/[A-Za-z0-9][A-Za-z0-9._-]*$`)

type limitedCatalogOutput struct {
	bytes.Buffer
}

func (w *limitedCatalogOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 256*1024 {
		return 0, errors.New("Magpie 模型列表输出过大")
	}
	return w.Buffer.Write(p)
}

// ParseMagpieCodexModels recognizes the first column of Magpie's human CLI
// output. Other provider models and all diagnostic/URL text are discarded.
func ParseMagpieCodexModels(output string) []Model {
	seen := make(map[string]bool)
	out := make([]Model, 0, 16)
	for _, line := range strings.Split(output, "\n") {
		columns := strings.Fields(line)
		if len(columns) == 0 {
			continue
		}
		id := columns[0]
		if !codexModelID.MatchString(id) || len(id) > 512 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Model{ID: id, Group: "codex"})
		if len(out) == 128 {
			break
		}
	}
	return out
}

func magpieModelsFromCLI(ctx context.Context, executable string) ([]Model, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "models", "codex")
	// When an explicit Magpie configuration directory is supplied, only
	// redirect the CLI if that directory follows Magpie's XDG layout.
	if dir := os.Getenv("MAGPIE_ACCOUNT_QUALITY_MAGPIE_DIR"); dir != "" && filepath.Base(dir) == "magpie" {
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "XDG_CONFIG_HOME=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, "XDG_CONFIG_HOME="+filepath.Dir(dir))
	}
	var stdout limitedCatalogOutput
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, errors.New("Magpie 本机模型目录查询失败")
	}
	models := ParseMagpieCodexModels(stdout.String())
	if len(models) == 0 {
		return nil, errors.New("Magpie 本机没有可供选择的 Codex 模型")
	}
	return models, nil
}

// AvailableCodexModels lists models without needing a Gateway Key.
// The optional configured Gateway can still serve as a fallback for hosts
// without the Magpie CLI, never as a prerequisite for the dropdown.
func AvailableCodexModels(ctx context.Context, c Config) ([]Model, error) {
	local, localErr := magpieModelsFromCLI(ctx, "magpie")
	if localErr == nil {
		return local, nil
	}
	if c.GatewayURL != "" && c.GatewayKey != "" {
		remote, err := Models(ctx, c)
		if err == nil && len(remote) > 0 {
			return remote, nil
		}
		if err != nil {
			return nil, fmt.Errorf("无法从本机 Magpie 加载模型，检测网关也无法列出模型：%w", err)
		}
	}
	return nil, fmt.Errorf("%w；如 Magpie CLI 不在运行环境中，请配置检测连接后重试", localErr)
}
