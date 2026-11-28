package worker

import "time"

// defaultJobTimeout is the wall-clock budget of one PR review job when none is configured.
const defaultJobTimeout = 5 * time.Minute

func jobTimeoutOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultJobTimeout
	}
	return d
}
