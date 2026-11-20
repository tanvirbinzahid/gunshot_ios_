package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// importRAWJPEG stages a RAW+JPEG job (rendered first, RAW second) and seals it.
func importRAWJPEG(t *testing.T, e *Engine) (*Job, map[string]any) {
	t.Helper()
	r := Request{Account: "a@example.com", Quality: "original", Resources: []Resource{{Name: "IMG_0001.JPG", Size: 3}, {Name: "IMG_0001.DNG", Size: 5}}}
	v, err := e.begin(r, "googlephotos")
	if err != nil {
		t.Fatal(err)
	}
	j := e.find(v.(map[string]any)["id"].(string))
	if err = e.appendChunk(j, Request{Index: 0, Offset: 0, Data: []byte("jpg")}); err != nil {
		t.Fatal(err)
	}
	if err = e.appendChunk(j, Request{Index: 1, Offset: 0, Data: []byte("raw!!")}); err != nil {
		t.Fatal(err)
	}
	sealed, err := e.seal(j)
	if err != nil {
		t.Fatal(err)
	}
	return j, sealed.(map[string]any)
}

// #74: after the JPEG commits and the RAW upload fails, a retry must send only
// the RAW. The job completes with the JPEG key as its primary media key.
func TestRAWJPEGRetrySkipsCommittedComponent(t *testing.T) {
	var calls [][]string
	e := newEngine(t, func(_ context.Context, paths []string, _ string, _ string, cb func(Progress)) (string, error) {
		names := make([]string, len(paths))
		for i, p := range paths {
			names[i] = filepath.Base(p)
		}
		calls = append(calls, names)
		if len(calls) == 1 {
			// First attempt: JPEG committed remotely, RAW upload fails before commit.
			cb(Progress{State: "committing"})
			cb(Progress{State: "component_committed", Uploaded: 3, Component: 0, MediaKey: "jpeg-key"})
			cb(Progress{State: "preparing", Uploaded: 3})
			return "", errors.New("raw upload failed")
		}
		cb(Progress{State: "committing", Uploaded: 5})
		return "raw-key", nil
	})
	e.online, e.wifi = true, true
	j, _ := importRAWJPEG(t, e)
	e.Tick()
	waitIdle(t, e)
	if j.State != "pending" || len(j.ComponentKeys) != 2 || j.ComponentKeys[0] != "jpeg-key" || j.ComponentKeys[1] != "" {
		t.Fatalf("committed JPEG not recorded: %+v", j)
	}
	// The commit record must already be durable for crash safety.
	reopened, err := Open(e.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.find(j.ID); got.ComponentKeys[0] != "jpeg-key" {
		t.Fatalf("component key not persisted: %+v", got)
	}
	j.Next = 0
	e.Tick()
	waitIdle(t, e)
	if len(calls) != 2 || strings.Join(calls[1], ",") != "IMG_0001.DNG" {
		t.Fatalf("retry re-sent a committed photo: %v", calls)
	}
	if j.State != "completed" || j.MediaKey != "jpeg-key" || j.ComponentKeys[1] != "raw-key" || j.Uploaded != j.Total {
		t.Fatalf("wrong completion: %+v", j)
	}
	if strings.Join(calls[0], ",") != "IMG_0001.JPG,IMG_0001.DNG" {
		t.Fatalf("first attempt did not upload both: %v", calls)
	}
}

// A restart after both component commits were recorded is a completed job,
// not an unknown commit outcome.
func TestRAWJPEGRestartAfterAllComponentsCommitted(t *testing.T) {
	e := newEngine(t, nil)
	j, _ := importRAWJPEG(t, e)
	j.State = "committing"
	j.ComponentKeys = []string{"jpeg-key", "raw-key"}
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(e.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := next.find(j.ID)
	if got.State != "completed" || got.MediaKey != "jpeg-key" || next.state.CompletionRevision == 0 {
		t.Fatalf("committed pair not recovered: %+v", got)
	}
	// A partially committed pair interrupted mid-commit stays uncertain.
	e2 := newEngine(t, nil)
	k, _ := importRAWJPEG(t, e2)
	k.State = "committing"
	k.ComponentKeys = []string{"jpeg-key", ""}
	if err := e2.save(); err != nil {
		t.Fatal(err)
	}
	next2, err := Open(e2.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := next2.find(k.ID); got.State != "failed" || got.Error != "commit_outcome_unknown" {
		t.Fatalf("unsafe partial recovery: %+v", got)
	}
}

func TestPersistedComponentKeysValidated(t *testing.T) {
	e := newEngine(t, nil)
	j, _ := importRAWJPEG(t, e)
	j.ComponentKeys = []string{"only-one"}
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e.root, nil); err == nil {
		t.Fatal("accepted mismatched component keys")
	}
}

// #73: re-importing media whose job failed must not be pinned to the failure
// forever. The failed job is revived (keeping committed components) instead.
func TestReimportRevivesFailedJob(t *testing.T) {
	e := newEngine(t, nil)
	j, _ := importRAWJPEG(t, e)
	j.State = "failed"
	j.Error = "upload_failed_check_account_and_network"
	j.Attempts = 4
	j.ComponentKeys = []string{"jpeg-key", ""}
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	again, reply := importRAWJPEG(t, e)
	if reply["id"] != j.ID || reply["duplicate"] != true || again.State != "cancelled" {
		t.Fatalf("re-import not attached to the failed job: %v %+v", reply, again)
	}
	if j.State != "pending" || j.Attempts != 0 || j.Error != "" || j.ComponentKeys[0] != "jpeg-key" {
		t.Fatalf("failed job not revived intact: %+v", j)
	}
	for _, r := range j.Resources {
		if _, err := os.Stat(filepath.Join(e.jobDir(j.ID), r.Name)); err != nil {
			t.Fatal("revived job lost its staged media:", err)
		}
	}
	if _, err := os.Stat(e.jobDir(again.ID)); !os.IsNotExist(err) {
		t.Fatal("duplicate staging not removed")
	}
}

// A completed or active job remains the preferred duplicate target.
func TestReimportPrefersCompletedOverFailed(t *testing.T) {
	e := newEngine(t, nil)
	failed := importTest(t, e, "quota")
	failed.State = "failed"
	done := &Job{}
	*done = *failed
	done.ID = strings.Repeat("ab", 16)
	done.State = "completed"
	done.MediaKey = "key"
	e.state.Jobs = append(e.state.Jobs, done)
	e.jobsByID[done.ID] = done
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	v, err := e.begin(Request{Account: "a@example.com", Quality: "quota", Resources: []Resource{{Name: "photo.jpg", Size: 3}}}, "photos")
	if err != nil {
		t.Fatal(err)
	}
	j := e.find(v.(map[string]any)["id"].(string))
	if err = e.appendChunk(j, Request{Index: 0, Offset: 0, Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	reply, err := e.seal(j)
	if err != nil {
		t.Fatal(err)
	}
	if reply.(map[string]any)["id"] != done.ID || failed.State != "failed" {
		t.Fatalf("completed match not preferred: %v", reply)
	}
}
