package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAppTokenSourceRefreshesAndCachesInstallationToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/77/access_tokens" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			t.Errorf("invalid JWT %q", r.Header.Get("Authorization"))
		}
		calls.Add(1)
		fmt.Fprintf(w, `{"token":"installation-%d","expires_at":%q}`, calls.Load(), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer server.Close()
	source, err := NewAppTokenSource(server.URL, 12, 77, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	source.client = server.Client()
	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != "installation-1" || second != first || calls.Load() != 1 {
		t.Fatalf("cached token mismatch: %q %q calls=%d", first, second, calls.Load())
	}
	source.mu.Lock()
	source.expires = source.now().Add(4 * time.Minute)
	source.mu.Unlock()
	third, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third != "installation-2" || calls.Load() != 2 {
		t.Fatalf("token was not refreshed: %q calls=%d", third, calls.Load())
	}
}
