package bridge

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultOrigin = "https://gethostwatch.com"

type Session struct {
	Origin       string    `json:"origin"`
	ClientID     string    `json:"clientId"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type oauthMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

type Client struct {
	Origin      string
	SessionFile string
	HTTP        *http.Client
	OpenBrowser func(string) error
}

func DefaultSessionFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hostwatch-mcp", "session.json"), nil
}

func NewClient(origin, sessionFile string) (*Client, error) {
	if origin == "" {
		origin = defaultOrigin
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("HOSTWATCH_ORIGIN must be a bare HTTPS origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, errors.New("HOSTWATCH_ORIGIN must use HTTPS (HTTP is allowed only on loopback)")
	}
	if sessionFile == "" {
		sessionFile, err = DefaultSessionFile()
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		Origin:      strings.TrimSuffix(u.String(), "/"),
		SessionFile: sessionFile,
		HTTP:        &http.Client{Timeout: 70 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		OpenBrowser: openBrowser,
	}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func randomURLString() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func (c *Client) getMetadata(ctx context.Context) (oauthMetadata, error) {
	var metadata oauthMetadata
	if err := c.jsonRequest(ctx, http.MethodGet, c.Origin+"/.well-known/oauth-authorization-server", nil, &metadata); err != nil {
		return metadata, err
	}
	if metadata.Issuer != c.Origin {
		return metadata, errors.New("Hostwatch OAuth issuer does not match the configured origin")
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.RegistrationEndpoint, metadata.RevocationEndpoint} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme+"://"+u.Host != c.Origin || u.User != nil {
			return metadata, errors.New("Hostwatch OAuth endpoint does not match the configured origin")
		}
	}
	return metadata, nil
}

func (c *Client) jsonRequest(ctx context.Context, method, endpoint string, body io.Reader, target any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil && method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Hostwatch HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(target)
}

func (c *Client) formRequest(ctx context.Context, endpoint string, form url.Values, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Hostwatch OAuth HTTP %d", res.StatusCode)
	}
	if target == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(target)
}

func validateToken(t tokenResponse) error {
	if t.AccessToken == "" || t.RefreshToken == "" || !strings.EqualFold(t.TokenType, "Bearer") || t.ExpiresIn <= 0 {
		return errors.New("Hostwatch returned an incomplete OAuth token response")
	}
	return nil
}

func (c *Client) Login(ctx context.Context, write, noBrowser bool, input io.Reader, output io.Writer) error {
	metadata, err := c.getMetadata(ctx)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	callbackNonce, err := randomURLString()
	if err != nil {
		return err
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback/%s", listener.Addr().(*net.TCPAddr).Port, callbackNonce)
	registration, err := json.Marshal(map[string]any{"client_name": "Hostwatch Go MCP", "redirect_uris": []string{redirectURI}, "token_endpoint_auth_method": "none"})
	if err != nil {
		return err
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := c.jsonRequest(ctx, http.MethodPost, metadata.RegistrationEndpoint, strings.NewReader(string(registration)), &registered); err != nil {
		return err
	}
	if registered.ClientID == "" {
		return errors.New("Hostwatch did not return an OAuth client ID")
	}
	verifier, err := randomURLString()
	if err != nil {
		return err
	}
	state, err := randomURLString()
	if err != nil {
		return err
	}
	challenge := sha256.Sum256([]byte(verifier))
	scope := "hostwatch:read"
	if write {
		scope += " hostwatch:write"
	}
	authURL, _ := url.Parse(metadata.AuthorizationEndpoint)
	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", registered.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	query.Set("state", state)
	query.Set("scope", scope)
	query.Set("resource", c.Origin+"/mcp")
	authURL.RawQuery = query.Encode()
	callback := make(chan url.Values, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback/"+callbackNonce || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state)) != 1 {
			http.Error(w, "OAuth state does not match", http.StatusBadRequest)
			return
		}
		select {
		case callback <- r.URL.Query():
		default:
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "Hostwatch authorization received. Return to the terminal.\n")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())
	fmt.Fprintln(output, "Open this Hostwatch authorization URL and choose QR or direct sign-in:")
	fmt.Fprintln(output, authURL.String())
	if !noBrowser {
		if err := c.OpenBrowser(authURL.String()); err != nil {
			fmt.Fprintln(output, "Browser did not open automatically; open the URL above manually.")
		}
	}
	var values url.Values
	if noBrowser {
		fmt.Fprintln(output, "Paste the full callback URL after approving the connection:")
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		pasted, err := url.Parse(strings.TrimSpace(line))
		if err != nil || pasted.String() == "" || pasted.Scheme+"://"+pasted.Host+pasted.Path != redirectURI {
			return errors.New("callback URL does not match this sign-in request")
		}
		values = pasted.Query()
	} else {
		select {
		case values = <-callback:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Minute):
			return errors.New("Hostwatch sign-in timed out")
		}
	}
	if subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state)) != 1 || values.Get("state") == "" {
		return errors.New("OAuth state does not match")
	}
	if values.Get("iss") != "" && values.Get("iss") != c.Origin {
		return errors.New("OAuth issuer does not match")
	}
	if values.Get("error") != "" {
		return fmt.Errorf("Hostwatch authorization denied: %s", values.Get("error"))
	}
	code := values.Get("code")
	if code == "" {
		return errors.New("Hostwatch did not return an authorization code")
	}
	var tokens tokenResponse
	if err := c.formRequest(ctx, metadata.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {registered.ClientID},
		"redirect_uri":  {redirectURI},
		"code":          {code},
		"code_verifier": {verifier},
		"resource":      {c.Origin + "/mcp"},
	}, &tokens); err != nil {
		return err
	}
	if err := validateToken(tokens); err != nil {
		return err
	}
	if err := c.save(Session{Origin: c.Origin, ClientID: registered.ClientID, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, Scope: tokens.Scope, ExpiresAt: time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)}); err != nil {
		return err
	}
	fmt.Fprintln(output, "Connected to your Hostwatch account. MCP access is ready.")
	return nil
}

func openBrowser(target string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{target}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		command, args = "xdg-open", []string{target}
	}
	return exec.Command(command, args...).Start()
}
