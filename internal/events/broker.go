// Package events provides a thread-safe pub/sub broker for real-time agent activity streaming.
package events

import (
	"context"
	"sync"
	"time"
)

// Event represents a single live observability event emitted during agent execution or daemon lifecycle.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	PRKey     string    `json:"pr_key,omitempty"`
	Type      string    `json:"type"` // run_started, step, tool_call, blue_team, secret_alert, run_finished, config_reload
	Tool      string    `json:"tool,omitempty"`
	Message   string    `json:"message"`
}

// Broker maintains a bounded history ring buffer and broadcasts events to SSE subscribers.
type Broker struct {
	mu           sync.RWMutex
	historyLimit int
	history      []Event
	subscribers  map[chan Event]struct{}
	redactor     func(string) string
}

// NewBroker creates a new Broker retaining up to historyLimit recent events.
func NewBroker(historyLimit int) *Broker {
	if historyLimit <= 0 {
		historyLimit = 100
	}
	return &Broker{
		historyLimit: historyLimit,
		history:      make([]Event, 0, historyLimit),
		subscribers:  make(map[chan Event]struct{}),
	}
}

// WithRedactor configures an optional sanitization function applied to event messages before storage or broadcast.
func (b *Broker) WithRedactor(fn func(string) string) *Broker {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.redactor = fn
	b.mu.Unlock()
	return b
}

// Publish records an event and dispatches it non-blockingly to all active subscribers.
func (b *Broker) Publish(ev Event) {
	if b == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	b.mu.Lock()
	if b.redactor != nil {
		ev.Message = b.redactor(ev.Message)
	}
	if len(b.history) < b.historyLimit {
		b.history = append(b.history, ev)
	} else {
		copy(b.history, b.history[1:])
		b.history[len(b.history)-1] = ev
	}
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// Drop for slow consumers rather than blocking agent workers.
		}
	}
	b.mu.Unlock()
}

// Recent returns a copy of the buffered event history.
func (b *Broker) Recent() []Event {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Event, len(b.history))
	copy(out, b.history)
	return out
}

// Subscribe returns a channel that receives published events until ctx is canceled.
func (b *Broker) Subscribe(ctx context.Context) <-chan Event {
	ch := make(chan Event, 32)
	if b == nil {
		close(ch)
		return ch
	}

	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subscribers, ch)
		close(ch)
		b.mu.Unlock()
	}()
	return ch
}
