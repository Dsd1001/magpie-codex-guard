package check

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQuickTunnelLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "cloudflared")
	script := "#!/bin/sh\nprintf 'https://fixture-console.trycloudflare.com\\nRegistered tunnel connection\\n' >&2\nexec sleep 300\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	a := NewAccess("control", "http://127.0.0.1:1234")
	c := NewConsole(a, "http://127.0.0.1:1234", dir, binary)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	link, err := c.Open(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "https://fixture-console.trycloudflare.com/open/") {
		t.Fatal(link)
	}
	ticket := strings.Split(link, "/open/")[1]
	session, ok := a.Exchange(ticket)
	if !ok {
		t.Fatal("remote ticket failed")
	}
	second, err := c.Open(ctx, true)
	if err != nil || second == link {
		t.Fatal("reopening reused ticket")
	}
	c.Close()
	if a.Session(session) {
		t.Fatal("remote close kept session")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		count := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "tunnel-") {
				count++
			}
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("temporary tunnel configuration not removed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestQuickTunnelFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "cloudflared")
	os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0700)
	a := NewAccess("control", "http://127.0.0.1:1234")
	c := NewConsole(a, "http://127.0.0.1:1234", dir, binary)
	if _, err := c.Open(context.Background(), true); err == nil {
		t.Fatal("failed tunnel accepted")
	}
	c.Close()
	if a.Origin("https://fixture-console.trycloudflare.com") {
		t.Fatal("failed tunnel registered origin")
	}
}
