package check

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

// The management control token never leaves the plugin's private child pipe.
func (a *Access) validControl(id string) bool {
	return subtle.ConstantTimeCompare([]byte(id), []byte(a.control)) == 1
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "请求格式错误", 400)
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "请求正文不能包含额外数据", 400)
		return false
	}
	return true
}
func apiError(w http.ResponseWriter, err error, code int) {
	if err == nil {
		err = errors.New("未知错误")
	}
	http.Error(w, err.Error(), code)
}
func (s *Service) ManagementHandler(access *GuardAccess, consoles ...*Console) http.Handler {
	var console *Console
	if len(consoles) > 0 {
		console = consoles[0]
	}
	mux := http.NewServeMux()
	// Reuse the original plugin's Go-owned tunnel lifecycle and ticket API.
	mux.HandleFunc("POST /api/console", func(w http.ResponseWriter, r *http.Request) {
		if console == nil {
			http.Error(w, "管理控制台未启用", http.StatusServiceUnavailable)
			return
		}
		var input struct {
			Remote bool   `json:"remote"`
			Binary string `json:"binary"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Binary != "" {
			console.SetBinary(input.Binary)
		}
		link, err := console.Open(r.Context(), input.Remote)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"url": link})
	})
	mux.HandleFunc("POST /api/console/close", func(w http.ResponseWriter, r *http.Request) {
		if console != nil {
			// Let the tunnel deliver the response before terminating transport.
			time.AfterFunc(300*time.Millisecond, console.Close)
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	root, _ := fs.Sub(web, "web")
	mux.Handle("GET /assets/", http.FileServer(http.FS(root)))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := web.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		state, health := s.Snapshot()
		s.mu.Lock()
		gatewayReady := s.state.Config.GatewayURL != "" && s.state.Config.GatewayKey != ""
		s.mu.Unlock()
		dir, err := MagpieDir()
		accounts := []CodexAccount{}
		discoveryError := ""
		if err == nil {
			accounts, err = DiscoverCodexAccounts(dir)
		}
		if err != nil {
			discoveryError = err.Error()
		}
		keys, kerr := GatewayKeyLabels()
		if kerr != nil {
			keys = []GatewayKeyLabel{}
		}
		writeJSON(w, map[string]any{"state": state, "health": health, "gateway_configured": gatewayReady, "accounts": accounts, "discovery_error": discoveryError, "keys": keys, "prompts": s.PromptCatalog(), "routing_error": func() string {
			if kerr != nil {
				return kerr.Error()
			}
			return ""
		}()})
	})
	mux.HandleFunc("GET /api/models", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		cfg := s.state.Config
		s.mu.Unlock()
		models, err := AvailableCodexModels(r.Context(), cfg)
		if err != nil {
			apiError(w, err, http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, models)
	})
	mux.HandleFunc("GET /api/fingerprint-models", func(w http.ResponseWriter, r *http.Request) {
		models, err := FingerprintModelCatalog()
		if err != nil {
			apiError(w, err, 503)
			return
		}
		writeJSON(w, models)
	})
	mux.HandleFunc("POST /api/config", func(w http.ResponseWriter, r *http.Request) {
		var input Config
		if !decode(w, r, &input) {
			return
		}
		if err := s.Configure(input); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/timing", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Policy     TimingPolicy `json:"policy"`
			Account    string       `json:"account"`
			Model      string       `json:"model"`
			Inherit    bool         `json:"inherit"`
			Reschedule bool         `json:"reschedule"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.ConfigureTimingPolicy(input.Policy, input.Account, input.Model, input.Inherit, input.Reschedule); err != nil {
			apiError(w, err, http.StatusConflict)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/account-target", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Account, Model string
			Enabled        bool
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.SetAccountTarget(input.Account, input.Model, input.Enabled); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("DELETE /api/account-target", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Account, Model string }
		if !decode(w, r, &input) {
			return
		}
		if err := s.DeleteAccountTarget(input.Account, input.Model); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/account-targets/discover", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Model, Confirm string }
		if !decode(w, r, &input) {
			return
		}
		if input.Confirm != "ADD_ALL_CODEX_ACCOUNTS" {
			http.Error(w, "请确认批量添加账号", 400)
			return
		}
		count, err := s.DiscoverAccountTargets(input.Model)
		if err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]any{"count": count})
	})
	mux.HandleFunc("POST /api/account-targets/sync", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Confirm != "SYNC_LIVE_CODEX_TARGETS" {
			apiError(w, errors.New("确认短语错误"), 400)
			return
		}
		result, err := s.SyncLiveAccountTargets()
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("POST /api/account-targets/auto-sync", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool   `json:"enabled"`
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.ConfigureAccountAutoSync(input.Enabled, input.Confirm); err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, map[string]bool{"enabled": input.Enabled})
	})
	mux.HandleFunc("POST /api/account-test", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Account, Model, Prompt string }
		if !decode(w, r, &input) {
			return
		}
		if input.Prompt == "" {
			input.Prompt = "milk"
		}
		if err := s.TriggerAccount(input.Account, input.Model, input.Prompt, true); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/fingerprint-expected", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Account, Model, Expected string }
		if !decode(w, r, &input) {
			return
		}
		if err := s.configureTargetFingerprint(input.Account, input.Model, input.Expected); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/auto-prompts", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			PromptIDs       []string `json:"prompt_ids"`
			Rotate          bool     `json:"rotate"`
			FingerprintMode string   `json:"fingerprint_mode"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.ConfigureDetectionPrompts(input.PromptIDs, input.Rotate, input.FingerprintMode); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, s.AutoPromptSettings())
	})
	mux.HandleFunc("POST /api/custom-prompts", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name, Text, Guidance string
			Automatic            bool
			ExpectedAnswers      []string `json:"expected_answers"`
		}
		if !decode(w, r, &input) {
			return
		}
		p, err := s.AddCustomPrompt(input.Name, input.Text, input.Guidance, input.Automatic, input.ExpectedAnswers)
		if err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("PUT /api/custom-prompts/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name, Text, Guidance string
			Automatic            bool
			ExpectedAnswers      []string `json:"expected_answers"`
		}
		if !decode(w, r, &input) {
			return
		}
		err := s.UpdateCustomPrompt(r.PathValue("id"), input.Name, input.Text, input.Guidance, input.Automatic, input.ExpectedAnswers)
		if err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("DELETE /api/custom-prompts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DeleteCustomPrompt(r.PathValue("id")); err != nil {
			apiError(w, err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		plan, err := s.RoutingPreview()
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, plan)
	})
	mux.HandleFunc("POST /api/routing/config", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ProbeKeyID      string `json:"probe_key_id"`
			AutoApply       bool   `json:"auto_apply"`
			ScheduleEnabled bool   `json:"schedule_enabled"`
			ExpectedCount   int    `json:"expected_count"`
			Confirm         string `json:"confirm"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.ConfigureController(r.Context(), input.ProbeKeyID, input.ExpectedCount, input.AutoApply, input.ScheduleEnabled, input.Confirm); err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/routing/apply", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Confirm string }
		if !decode(w, r, &input) {
			return
		}
		if input.Confirm != "APPLY_QUARANTINE" {
			http.Error(w, "确认短语错误", 400)
			return
		}
		plan, err := s.ApplyRouting(r.Context(), false)
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, plan)
	})
	mux.HandleFunc("POST /api/routing/adopt-current", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &input) {
			return
		}
		preview, err := s.ApproveCurrentScopes(r.Context(), input.Confirm)
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, preview)
	})
	mux.HandleFunc("POST /api/routing/restore", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Confirm string }
		if !decode(w, r, &input) {
			return
		}
		if input.Confirm != "RESTORE_ALL_PRODUCTION_KEYS" {
			http.Error(w, "确认短语错误", 400)
			return
		}
		plan, err := s.ApplyRouting(r.Context(), true)
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, plan)
	})
	mux.HandleFunc("POST /api/routing/recover", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Confirm string }
		if !decode(w, r, &input) {
			return
		}
		if input.Confirm != "RECOVER_PENDING_JOURNAL" {
			http.Error(w, "确认短语错误", 400)
			return
		}
		result, err := s.RecoverRoutingJournal(r.Context())
		if err != nil {
			apiError(w, err, 409)
			return
		}
		writeJSON(w, map[string]string{"status": result})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; base-uri 'none'")
		if r.Method == "GET" && r.URL.Path == "/health" {
			w.Header().Set("X-Codex-Guard", "ready")
			w.WriteHeader(204)
			return
		}
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		control := access.validControl(supplied)
		if r.Method == "POST" && r.URL.Path == "/api/open" {
			if !control {
				http.Error(w, "仅允许插件签发管理链接", 403)
				return
			}
			var link string
			if console != nil {
				var err error
				link, err = console.Open(r.Context(), false)
				if err != nil {
					http.Error(w, err.Error(), 503)
					return
				}
			} else {
				link = access.local + "/open/" + access.Ticket()
			}
			writeJSON(w, map[string]string{"url": link})
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/open/") {
			if !access.Origin("http://"+r.Host) && !access.Origin("https://"+r.Host) {
				http.Error(w, "管理 Host 不匹配", 403)
				return
			}
			session, ok := access.Exchange(strings.TrimPrefix(r.URL.Path, "/open/"))
			if !ok {
				http.Error(w, "管理链接已失效", 401)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "guard_session", Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: access.Origin("https://"+r.Host) || r.TLS != nil, MaxAge: 1800})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		session := ""
		if cookie, err := r.Cookie("guard_session"); err == nil {
			session = cookie.Value
		}
		if !control && !access.Session(session) {
			http.Error(w, "请从 Magpie 插件入口打开一次性管理链接", 401)
			return
		}
		if r.Method != "GET" {
			origin := r.Header.Get("Origin")
			if origin != "" && !access.Origin(origin) {
				http.Error(w, "Origin 不匹配", 403)
				return
			}
		}
		// Only the Magpie plugin control token can mint tunnels/tickets.
		// An authenticated administrator may close their own temporary tunnel.
		if r.URL.Path == "/api/console" && !control {
			http.Error(w, "仅插件可开启控制台", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
