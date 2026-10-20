package check

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func consoleFixture(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestCopiedConsoleTicketExpiryAndRemoteReset(t *testing.T) {
	a := NewAccess("control", "http://127.0.0.1:5555")
	ticket := a.Ticket()
	session, ok := a.Exchange(ticket)
	if !ok || !a.Session(session) {
		t.Fatal("ticket exchange failed")
	}
	if _, ok := a.Exchange(ticket); ok {
		t.Fatal("ticket reused")
	}
	expired := a.Ticket()
	a.mu.Lock()
	a.tickets[expired] = time.Now().Add(-time.Second)
	a.mu.Unlock()
	if _, ok := a.Exchange(expired); ok {
		t.Fatal("expired ticket was accepted")
	}
	a.SetRemote("https://temporary-test.trycloudflare.com")
	if a.Session(session) {
		t.Fatal("session survived a tunnel change")
	}
}

func TestCopiedConsoleBrowserLoginAndOrigin(t *testing.T) {
	s := consoleFixture(t)
	a := NewAccess("control", "http://127.0.0.1:5555")
	a.SetRemote("https://temporary-test.trycloudflare.com")
	h := s.ManagementHandler(a)
	origin := "https://temporary-test.trycloudflare.com"
	ticket := a.Ticket()
	r := httptest.NewRequest("GET", origin+"/open/"+ticket, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].SameSite != http.SameSiteLaxMode ||
		!cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("browser cookie attributes incorrect: %#v", cookies)
	}
	r = httptest.NewRequest("GET", origin+"/", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("home with cookie: %d", w.Code)
	}
	r = httptest.NewRequest("GET", origin+"/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous homepage was served")
	}
	r = httptest.NewRequest("GET", origin+"/open/"+ticket, nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("ticket reused")
	}
	r = httptest.NewRequest("POST", origin+"/api/console", bytes.NewBufferString("{}"))
	r.AddCookie(cookies[0])
	r.Header.Set("Origin", origin)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("browser could create a tunnel")
	}
	r = httptest.NewRequest("POST", origin+"/api/auto-prompts", bytes.NewBufferString("{}"))
	r.AddCookie(cookies[0])
	r.Header.Set("Origin", "https://attacker.invalid")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("CSRF was permitted")
	}
	r = httptest.NewRequest("GET", "https://attacker.invalid/open/"+a.Ticket(), nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("unregistered host was accepted")
	}
}

func TestPluginConsoleLocalOpenRequiresControl(t *testing.T) {
	s := consoleFixture(t)
	local := "http://127.0.0.1:5555"
	a := NewAccess("control", local)
	console := NewConsole(a, local, t.TempDir(), "")
	defer console.Close()
	h := s.ManagementHandler(a, console)
	r := httptest.NewRequest("POST", local+"/api/console", bytes.NewBufferString(`{"remote":false}`))
	r.Header.Set("Origin", local)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer control")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("local console: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(local+"/open/")) {
		t.Fatal("no local open ticket")
	}
	r = httptest.NewRequest("POST", local+"/api/console", bytes.NewBufferString(`{"remote":false}`))
	r.Header.Set("Origin", local)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("unauthorized local link")
	}
}
