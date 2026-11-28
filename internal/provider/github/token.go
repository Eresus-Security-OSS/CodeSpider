package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies short-lived access tokens for API and git operations.
type TokenSource interface {
	Token(context.Context) (string, error)
}

// AppTokenSource obtains and refreshes GitHub App installation tokens.
type AppTokenSource struct {
	apiURL         string
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	client         *http.Client
	mu             sync.Mutex
	token          string
	expires        time.Time
	now            func() time.Time
}

func NewAppTokenSource(apiURL string, appID, installationID int64, privateKeyPath string) (*AppTokenSource, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("GitHub App private key is not PEM encoded")
	}
	var key *rsa.PrivateKey
	if parsed, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		key = parsed
	} else {
		parsedKey, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse GitHub App private key: %w", e)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("GitHub App private key must be RSA")
		}
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("GitHub App RSA key must be at least 2048 bits")
	}
	return &AppTokenSource{apiURL: strings.TrimRight(apiURL, "/"), appID: appID, installationID: installationID, key: key, client: &http.Client{Timeout: 30 * time.Second}, now: time.Now}, nil
}

func (s *AppTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Add(5*time.Minute).Before(s.expires) {
		return s.token, nil
	}
	jwt, err := s.jwt()
	if err != nil {
		return "", err
	}
	body := strings.NewReader(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiURL, s.installationID), body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	const max = 1 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return "", err
	}
	if len(data) > max {
		return "", fmt.Errorf("GitHub App token response exceeds %d bytes", max)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GitHub App token request: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	if result.Token == "" || result.ExpiresAt.IsZero() || !result.ExpiresAt.After(s.now()) {
		return "", fmt.Errorf("GitHub returned an invalid or expired installation token")
	}
	s.token, s.expires = result.Token, result.ExpiresAt
	return s.token, nil
}

func (s *AppTokenSource) jwt() (string, error) {
	now := s.now().Unix()
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]int64{"iat": now - 60, "exp": now + 540, "iss": s.appID})
	unsigned := header + "." + enc(payload)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + enc(sig), nil
}
