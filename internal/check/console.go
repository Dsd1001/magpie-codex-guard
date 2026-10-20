package check

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Access owns management credentials separately from the model gateway key.
type Access struct {
	mu       sync.Mutex
	control  string
	local    string
	tickets  map[string]time.Time
	sessions map[string]time.Time
	origins  map[string]bool
}

func NewAccess(control, localOrigin string) *Access {
	return &Access{control: control, local: localOrigin, tickets: map[string]time.Time{}, sessions: map[string]time.Time{}, origins: map[string]bool{localOrigin: true}}
}
func (a *Access) Ticket() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.tickets {
		if now.After(v) {
			delete(a.tickets, k)
		}
	}
	t := Secret()
	a.tickets[t] = now.Add(10 * time.Minute)
	return t
}
func (a *Access) Exchange(ticket string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.tickets[ticket]
	delete(a.tickets, ticket)
	if !ok || time.Now().After(until) {
		return "", false
	}
	s := Secret()
	a.sessions[s] = time.Now().Add(30 * time.Minute)
	return s, true
}
func (a *Access) Session(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(a.sessions, token)
		return false
	}
	return true
}
func (a *Access) Origin(origin string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.origins[origin]
}
func (a *Access) SetRemote(origin string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.origins {
		if strings.HasPrefix(k, "https://") {
			delete(a.origins, k)
		}
	}
	if origin != "" {
		a.origins[origin] = true
	}
	a.tickets = map[string]time.Time{}
	a.sessions = map[string]time.Time{}
}

type Console struct {
	mu                 sync.Mutex
	access             *Access
	local, dir, binary string
	cmd                *exec.Cmd
	cancel             context.CancelFunc
	remote             string
	timer              *time.Timer
}

func NewConsole(access *Access, local, dir, binary string) *Console {
	return &Console{access: access, local: local, dir: dir, binary: binary}
}

var quickURL = regexp.MustCompile(`https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com(?:\s|$)`)

func (c *Console) Open(ctx context.Context, remote bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !remote {
		return c.local + "/open/" + c.access.Ticket(), nil
	}
	if c.remote != "" {
		return c.remote + "/open/" + c.access.Ticket(), nil
	}
	binary := c.binary
	if binary == "" {
		binary = "cloudflared"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", errors.New("未找到 cloudflared，请安装官方客户端或设置 cloudflaredPath")
	}
	dir, err := os.MkdirTemp(c.dir, "tunnel-")
	if err != nil {
		return "", err
	}
	defer func() {
		if c.cmd == nil {
			os.RemoveAll(dir)
		}
	}()
	config := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		return "", err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(lifetime, resolved, "tunnel", "--config", config, "--no-autoupdate", "--url", c.local, "--protocol", "http2", "--edge-ip-version", "4", "--metrics", "127.0.0.1:0")
	cmd.Dir = dir
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TUNNEL_") && !strings.HasPrefix(entry, "CLOUDFLARED_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	pipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return "", err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		return "", err
	}
	lines := make(chan string, 64)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
		done <- cmd.Wait()
		os.RemoveAll(dir)
	}()
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	origin := ""
	registered := false
	for {
		select {
		case line := <-lines:
			if match := quickURL.FindString(line); match != "" {
				origin = strings.TrimSpace(match)
			}
			registered = registered || strings.Contains(line, "Registered tunnel connection")
			if origin != "" && registered {
				u, e := url.Parse(origin)
				if e != nil || u.Scheme != "https" || u.Port() != "" {
					cancel()
					return "", errors.New("无效临时域名")
				}
				c.cmd = cmd
				c.cancel = cancel
				c.remote = origin
				c.access.SetRemote(origin)
				c.timer = time.AfterFunc(30*time.Minute, c.Close)
				go func() {
					<-done
					c.mu.Lock()
					defer c.mu.Unlock()
					if c.cmd == cmd {
						c.resetLocked()
					}
				}()
				return origin + "/open/" + c.access.Ticket(), nil
			}
		case err := <-done:
			cancel()
			return "", fmt.Errorf("Cloudflare 临时通道启动失败：%v", err)
		case <-ctx.Done():
			cancel()
			return "", ctx.Err()
		case <-deadline.C:
			cancel()
			return "", errors.New("Cloudflare 临时通道启动超时")
		}
	}
}
func (c *Console) resetLocked() {
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.cmd = nil
	c.remote = ""
	c.cancel = nil
	c.access.SetRemote("")
}
func (c *Console) Close()                  { c.mu.Lock(); defer c.mu.Unlock(); c.resetLocked() }
func (c *Console) SetBinary(binary string) { c.mu.Lock(); defer c.mu.Unlock(); c.binary = binary }

// Preserve the guard-specific API expected by existing integration tests.
type GuardAccess = Access

func NewGuardAccess(control, localOrigin string) *GuardAccess { return NewAccess(control, localOrigin) }
