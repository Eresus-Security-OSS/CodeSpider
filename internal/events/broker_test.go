package events

import (
	"context"
	"testing"
	"time"
)

func TestBrokerPublishRecentAndSubscribe(t *testing.T) {
	b := NewBroker(3)
	b.Publish(Event{Type: "run_started", PRKey: "acme/api#1", Message: "started"})
	b.Publish(Event{Type: "step", PRKey: "acme/api#1", Message: "step 1"})
	b.Publish(Event{Type: "tool_call", PRKey: "acme/api#1", Tool: "get_pr_diff", Message: "called"})
	b.Publish(Event{Type: "run_finished", PRKey: "acme/api#1", Message: "done"})

	recent := b.Recent()
	if len(recent) != 3 {
		t.Fatalf("expected history capped at 3, got %d", len(recent))
	}
	if recent[0].Type != "step" || recent[2].Type != "run_finished" {
		t.Fatalf("unexpected history order: %+v", recent)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := b.Subscribe(ctx)

	b.Publish(Event{Type: "blue_team", PRKey: "acme/api#1", Message: "verified"})
	select {
	case ev := <-ch:
		if ev.Type != "blue_team" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	cancel()
	// Channel should close on context cancellation
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to close after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscriber close")
	}
}
