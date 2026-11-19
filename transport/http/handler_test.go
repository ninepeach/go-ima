package imahttp_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ima "github.com/ninepeach/go-ima"
	"github.com/ninepeach/go-ima/auth"
	"github.com/ninepeach/go-ima/internal/testdb"
	imapg "github.com/ninepeach/go-ima/storage/postgres"
	imahttp "github.com/ninepeach/go-ima/transport/http"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := imapg.New(testdb.New(t, false))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := auth.NewHasher(auth.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	svc, err := ima.New(ima.Options{Repositories: store.Repositories(), Hasher: h})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(imahttp.New(svc, imahttp.Options{}))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s: missing Cache-Control: no-store", method, path)
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: non-JSON body %q", method, path, raw)
		}
	}
	return resp.StatusCode, out
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestEndToEnd(t *testing.T) {
	srv := newServer(t)
	reg := `{"email":"kim@example.com","password":"correct horse battery","display_name":"Kim"}`
	if code, _ := call(t, srv, "POST", "/v1/register", "", reg); code != http.StatusAccepted {
		t.Fatalf("register: %d", code)
	}
	if code, _ := call(t, srv, "POST", "/v1/register", "", reg); code != http.StatusAccepted {
		t.Fatalf("duplicate register must look identical: %d", code)
	}
	code, body := call(t, srv, "POST", "/v1/login", "", `{"email":"kim@example.com","password":"wrong wrong wrong"}`)
	if code != http.StatusUnauthorized || errCode(body) != "invalid_credentials" {
		t.Fatalf("bad login: %d %v", code, body)
	}
	code, body = call(t, srv, "POST", "/v1/login", "", `{"email":"kim@example.com","password":"correct horse battery","device_name":"Phone"}`)
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}
	access, refresh := body["access_token"].(string), body["refresh_token"].(string)
	if body["device_token"] == "" || body["token_type"] != "Bearer" {
		t.Fatalf("login body: %v", body)
	}
	if code, body = call(t, srv, "GET", "/v1/me", access, ""); code != http.StatusOK || body["email"] != "kim@example.com" {
		t.Fatalf("me: %d %v", code, body)
	}
	code, body = call(t, srv, "GET", "/v1/sessions", access, "")
	if list, _ := body["sessions"].([]any); code != http.StatusOK || len(list) != 1 {
		t.Fatalf("sessions: %d %v", code, body)
	}
	code, body = call(t, srv, "POST", "/v1/token/refresh", "", `{"refresh_token":"`+refresh+`"}`)
	if code != http.StatusOK {
		t.Fatalf("refresh: %d %v", code, body)
	}
	access = body["access_token"].(string)
	if code, _ := call(t, srv, "POST", "/v1/logout", access, ""); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	if code, body := call(t, srv, "GET", "/v1/me", access, ""); code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
		t.Fatalf("after logout: %d %v", code, body)
	}
}

func TestRequestValidation(t *testing.T) {
	srv := newServer(t)
	for _, c := range []struct {
		method, path, token, body string
		code                      int
		errCode                   string
	}{
		{"POST", "/v1/login", "", `{`, 400, "invalid_request"},
		{"POST", "/v1/login", "", `{"email":"a@b.c","password":"x","admin":true}`, 400, "invalid_request"},
		{"POST", "/v1/login", "", `{"email":"a@b.c"} {"email":"x"}`, 400, "invalid_request"},
		{"POST", "/v1/register", "", `{"email":"bad","password":"correct horse battery"}`, 400, "invalid_request"},
		{"GET", "/v1/me", "", "", 401, "unauthenticated"},
		{"GET", "/v1/me", "ima_at_forged", "", 401, "unauthenticated"},
		{"GET", "/v1/nope", "", "", 404, "not_found"},
		{"POST", "/v1/login", "", strings.Repeat(" ", 70<<10) + "{}", 400, "invalid_request"},
	} {
		code, body := call(t, srv, c.method, c.path, c.token, c.body)
		if code != c.code || errCode(body) != c.errCode {
			t.Errorf("%s %s %.40q: got %d %v", c.method, c.path, c.body, code, body)
		}
	}
}
