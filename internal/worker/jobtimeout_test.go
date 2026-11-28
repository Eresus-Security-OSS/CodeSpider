package worker

import (
	"testing"
	"time"
)

func TestPoolJobTimeoutDefaultsAndOverrides(t *testing.T) {
	if got := NewPool(Config{}).jobTimeout; got != 5*time.Minute {
		t.Fatalf("zero JobTimeout must keep the 5 minute default, got %s", got)
	}
	if got := NewPool(Config{JobTimeout: -time.Second}).jobTimeout; got != 5*time.Minute {
		t.Fatalf("negative JobTimeout must fall back to the default, got %s", got)
	}
	if got := NewPool(Config{JobTimeout: 15 * time.Minute}).jobTimeout; got != 15*time.Minute {
		t.Fatalf("configured JobTimeout must be used, got %s", got)
	}
}
