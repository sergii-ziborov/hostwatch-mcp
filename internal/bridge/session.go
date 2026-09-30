package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func (c *Client) Load() (Session, error) {
	var session Session
	info, err := os.Lstat(c.SessionFile)
	if errors.Is(err, os.ErrNotExist) {
		return session, errors.New("not connected; run hostwatch-mcp login")
	}
	if err != nil {
		return session, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return session, errors.New("Hostwatch session file must be a regular owner-only file (0600)")
	}
	file, err := os.Open(c.SessionFile)
	if err != nil {
		return session, err
	}
	defer file.Close()
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&session); err != nil {
		return session, err
	}
	if session.Origin != c.Origin || session.ClientID == "" || session.AccessToken == "" || session.RefreshToken == "" {
		return Session{}, errors.New("Hostwatch session is incomplete or belongs to another origin; run login")
	}
	return session, nil
}

func (c *Client) save(session Session) error {
	dir := filepath.Dir(c.SessionFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("Hostwatch session directory must be owner-only (0700)")
	}
	if info, err = os.Lstat(c.SessionFile); err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
			return errors.New("Hostwatch session file must be a regular owner-only file (0600)")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(session); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), c.SessionFile)
}

func (c *Client) Refresh(ctx context.Context, session Session) (Session, error) {
	metadata, err := c.getMetadata(ctx)
	if err != nil {
		return Session{}, err
	}
	var tokens tokenResponse
	if err := c.formRequest(ctx, metadata.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {session.ClientID},
		"refresh_token": {session.RefreshToken},
		"resource":      {c.Origin + "/mcp"},
	}, &tokens); err != nil {
		// Another local MCP client may have rotated the shared refresh token first.
		// Its newly saved session is still valid for this request.
		if current, loadErr := c.Load(); loadErr == nil && current.ClientID == session.ClientID && current.RefreshToken != session.RefreshToken && time.Until(current.ExpiresAt) >= time.Minute {
			return current, nil
		}
		return Session{}, fmt.Errorf("Hostwatch session expired; run login: %w", err)
	}
	if err := validateToken(tokens); err != nil {
		return Session{}, err
	}
	session.AccessToken = tokens.AccessToken
	session.RefreshToken = tokens.RefreshToken
	session.Scope = tokens.Scope
	session.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	if err := c.save(session); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (c *Client) ActiveSession(ctx context.Context) (Session, error) {
	session, err := c.Load()
	if err != nil {
		return session, err
	}
	if time.Until(session.ExpiresAt) < time.Minute {
		return c.Refresh(ctx, session)
	}
	return session, nil
}

func (c *Client) Logout(ctx context.Context) error {
	session, err := c.Load()
	if err != nil {
		return err
	}
	metadata, err := c.getMetadata(ctx)
	if err != nil {
		return err
	}
	for _, token := range []string{session.RefreshToken, session.AccessToken} {
		if err := c.formRequest(ctx, metadata.RevocationEndpoint, url.Values{"client_id": {session.ClientID}, "token": {token}}, nil); err != nil {
			return fmt.Errorf("remote revocation failed; local session retained: %w", err)
		}
	}
	return os.Remove(c.SessionFile)
}
