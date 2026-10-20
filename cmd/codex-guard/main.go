package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/check"
	"github.com/gofrs/flock"
)

func main() {
	data := flag.String("data", "data", "private state dir")
	gate := flag.String("gate", "plugin/gate.middleware.js", "probe middleware path")
	listen := flag.String("listen", "127.0.0.1:0", "loopback listener")
	owned := flag.Bool("owned", false, "stop when parent stdin closes")
	flag.Parse()
	if err := run(*data, *gate, *listen, *owned); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(data, gate, listen string, owned bool) error {
	if err := os.MkdirAll(data, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(data, "service.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("检测后台已经运行，拒绝重复管理同一账号目录")
	}
	defer lock.Unlock()
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("检测控制台仅允许监听本地环回地址")
	}
	abs, err := filepath.Abs(gate)
	if err != nil {
		return err
	}
	service, err := check.New(data, abs)
	if err != nil {
		return err
	}
	defer service.Close()
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	origin := "http://" + ln.Addr().String()
	token := check.Secret()
	access := check.NewGuardAccess(token, origin)
	httpserver := &http.Server{
		Handler:           service.ManagementHandler(access),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
	}
	// One-time control token travels only over the plugin child stdout pipe.
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"url": origin + "/open/" + access.Ticket(), "origin": origin, "control": token,
	}); err != nil {
		return err
	}
	service.StartAccountScheduler()
	done := make(chan error, 1)
	go func() { done <- httpserver.Serve(ln) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(stop)
	closed := make(chan struct{})
	if owned {
		go func() { io.Copy(io.Discard, os.Stdin); close(closed) }()
	}
	select {
	case err = <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-stop:
	case <-closed:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpserver.Shutdown(ctx)
}
