package store

import "testing"

func TestSetPausedPersistsAcrossReopenAndReportsChange(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := PRKey("acme", "api", 1)

	if changed, err := st.SetPaused(key, false); err != nil || changed {
		t.Fatalf("resuming an unpaused PR must be a no-op, changed=%v err=%v", changed, err)
	}
	if changed, err := st.SetPaused(key, true); err != nil || !changed {
		t.Fatalf("expected pause to change state, changed=%v err=%v", changed, err)
	}
	if changed, _ := st.SetPaused(key, true); changed {
		t.Fatal("pausing twice must report no change")
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.IsPaused(key) {
		t.Fatal("pause must survive a restart")
	}
	if changed, err := reopened.SetPaused(key, false); err != nil || !changed {
		t.Fatalf("expected resume to change state, changed=%v err=%v", changed, err)
	}
	reopened2, _ := Open(dir)
	if reopened2.IsPaused(key) {
		t.Fatal("resume must survive a restart")
	}

	var nilStore *Store
	if nilStore.IsPaused(key) {
		t.Fatal("nil store must report not paused")
	}
}
