package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountLoginProxyRefreshLogout(t *testing.T) {
	var origin string
	var challenge string
	var redirectURI string
	var tokenCalls atomic.Int32
	var refreshCalls atomic.Int32
	var revokeCalls atomic.Int32
	var mcpCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(oauthMetadata{Issuer: origin, AuthorizationEndpoint: origin + "/oauth/authorize", TokenEndpoint: origin + "/oauth/token", RegistrationEndpoint: origin + "/oauth/register", RevocationEndpoint: origin + "/oauth/revoke"})
		case "/oauth/register":
			var input struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || len(input.RedirectURIs) != 1 {
				t.Errorf("invalid registration: %v, %+v", err, input)
			}
			redirectURI = input.RedirectURIs[0]
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"client_id":"test-client"}`)
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("client_id") != "test-client" || r.Form.Get("resource") != origin+"/mcp" {
				t.Errorf("invalid token request: %v", r.Form)
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("redirect_uri") != redirectURI || r.Form.Get("code") != "test-code" {
					t.Errorf("invalid authorization code request: %v", r.Form)
				}
				challengeSum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(challengeSum[:]) != challenge {
					t.Error("PKCE verifier does not match challenge")
				}
				tokenCalls.Add(1)
				fmt.Fprint(w, `{"access_token":"access-one","refresh_token":"refresh-one","token_type":"Bearer","scope":"hostwatch:read","expires_in":3600}`)
			case "refresh_token":
				if r.Form.Get("refresh_token") != "refresh-one" {
					t.Errorf("wrong refresh token: %v", r.Form)
				}
				refreshCalls.Add(1)
				fmt.Fprint(w, `{"access_token":"access-two","refresh_token":"refresh-two","token_type":"Bearer","scope":"hostwatch:read","expires_in":3600}`)
			default:
				t.Errorf("unexpected grant type: %s", r.Form.Get("grant_type"))
			}
		case "/oauth/revoke":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("client_id") != "test-client" {
				t.Errorf("wrong revocation client: %v", r.Form)
			}
			revokeCalls.Add(1)
			fmt.Fprint(w, `{}`)
		case "/mcp":
			mcpCalls.Add(1)
			if r.Header.Get("Authorization") == "Bearer access-one" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer access-two" {
				t.Errorf("unexpected bearer: %q", r.Header.Get("Authorization"))
			}
			var request requestEnvelope
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"search"}]}}`, request.ID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	client, err := NewClient(origin, filepath.Join(t.TempDir(), "session", "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	client.OpenBrowser = func(raw string) error {
		authURL, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if authURL.Query().Get("scope") != "hostwatch:read" || authURL.Query().Get("client_id") != "test-client" || authURL.Query().Get("code_challenge_method") != "S256" {
			t.Errorf("invalid authorization URL: %s", raw)
		}
		challenge = authURL.Query().Get("code_challenge")
		if authURL.Query().Get("redirect_uri") != redirectURI {
			t.Error("registered redirect differs from authorization redirect")
		}
		callback, _ := url.Parse(redirectURI)
		query := callback.Query()
		query.Set("code", "test-code")
		query.Set("state", "incorrect")
		callback.RawQuery = query.Encode()
		res, err := http.Get(callback.String())
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("wrong state was accepted: %d", res.StatusCode)
		}
		query.Set("state", authURL.Query().Get("state"))
		query.Set("iss", origin)
		callback.RawQuery = query.Encode()
		res, err = http.Get(callback.String())
		if err != nil {
			return err
		}
		res.Body.Close()
		return nil
	}
	var loginOutput bytes.Buffer
	if err := client.Login(context.Background(), false, false, strings.NewReader(""), &loginOutput); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 || !strings.Contains(loginOutput.String(), "Connected to your Hostwatch account") {
		t.Fatalf("login was not completed: %s", loginOutput.String())
	}
	info, err := os.Stat(client.SessionFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("session permissions: %v, %v", info, err)
	}
	var output bytes.Buffer
	if err := client.ServeStdio(context.Background(), strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"name":"search"`) || mcpCalls.Load() != 2 || refreshCalls.Load() != 1 {
		t.Fatalf("MCP forward or refresh failed: %s; calls=%d refreshes=%d", output.String(), mcpCalls.Load(), refreshCalls.Load())
	}
	session, err := client.Load()
	if err != nil || session.RefreshToken != "refresh-two" {
		t.Fatalf("rotated token not stored: %+v, %v", session, err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if revokeCalls.Load() != 2 {
		t.Fatalf("expected two token revocations, got %d", revokeCalls.Load())
	}
	if _, err := os.Stat(client.SessionFile); !os.IsNotExist(err) {
		t.Fatalf("session remains after logout: %v", err)
	}
}

func TestSessionRejectsUnsafePermissionsAndOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	client, err := NewClient("https://gethostwatch.com", path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Session{Origin: "https://other.example", ClientID: "client", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Load(); err == nil {
		t.Fatal("accepted session from another origin")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Load(); err == nil {
		t.Fatal("accepted group/world-readable session")
	}
	if _, err := NewClient("http://gethostwatch.com", path); err == nil {
		t.Fatal("accepted non-loopback HTTP origin")
	}
}

func TestReadSSE(t *testing.T) {
	messages, err := readSSE(strings.NewReader("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1}\n\n"))
	if err != nil || len(messages) != 1 || !json.Valid(messages[0]) {
		t.Fatalf("unexpected SSE response: %q, %v", messages, err)
	}
	if _, err := readSSE(strings.NewReader("data: not-json\n\n")); err == nil {
		t.Fatal("accepted invalid SSE JSON")
	}
}
