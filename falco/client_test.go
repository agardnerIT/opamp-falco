package falco

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeFalco mimics falco's reload_control listener
// (userspace/falco/reload_control.cpp) with the generation model the real
// daemon uses: a reload increments `started`; completing it advances either
// `applied` or `rejected` to the new started generation. The POST response's
// started_generation is the baseline *before* the reload began.
type fakeFalco struct {
	sock string
	srv  *http.Server
	l    net.Listener

	rejectNext bool
	instance   string
	started    int64
	applied    int64
	rejected   int64
}

func newFakeFalco(t *testing.T) *fakeFalco {
	t.Helper()
	// macOS limits unix socket paths to ~104 bytes; t.TempDir() paths exceed
	// that, so use a short dir (the same constraint falco checks for).
	dir, err := os.MkdirTemp("", "fs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeFalco{
		sock:     filepath.Join(dir, "control.sock"),
		instance: "i1",
		started:  1,
		applied:  1,
	}
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = os.Chmod(f.sock, 0o660)
	f.l = l

	mux := http.NewServeMux()
	mux.HandleFunc("/reload", f.reload)
	f.srv = &http.Server{Handler: mux}
	go func() { _ = f.srv.Serve(l) }()
	t.Cleanup(func() {
		_ = f.srv.Close()
		os.Remove(f.sock)
	})
	return f
}

func (f *fakeFalco) reload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		fmt.Fprintf(w, `{"instance_id":%q,"started_generation":%d,"applied_generation":%d,"rejected_generation":%d,"ready":true}`,
			f.instance, f.started, f.applied, f.rejected)
	case http.MethodPost:
		// the real listener 400s a POST without an explicit Content-Length
		// header; mirror that so the test keeps the wire contract honest.
		if r.Header.Get("Content-Length") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		baseline := f.started
		f.started++
		if f.rejectNext {
			f.rejected = f.started
		} else {
			f.applied = f.started
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"instance_id":%q,"started_generation":%d}`, f.instance, baseline)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestReloadSocketWireContract(t *testing.T) {
	f := newFakeFalco(t)
	c := New("http://localhost:1", f.sock)
	ctx := context.Background()

	baseline, err := c.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if baseline.InstanceID != "i1" || baseline.StartedGeneration != 1 {
		t.Fatalf("baseline = %+v, want i1/1", baseline)
	}

	// A rejected reload: rejected advances, applied does not.
	f.rejectNext = true
	b, err := c.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out := c.Apply(ctx, b, 10*time.Millisecond, 2*time.Second)
	if out != Rejected {
		t.Fatalf("outcome = %v, want Rejected", out)
	}

	// An applied reload passes max(baseline, rejected).
	f.rejectNext = false
	b, err = c.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out = c.Apply(ctx, b, 10*time.Millisecond, 2*time.Second)
	if out != Applied {
		t.Fatalf("outcome = %v, want Applied", out)
	}
}

func TestApplyUnknownOnSocketLoss(t *testing.T) {
	f := newFakeFalco(t)
	sock := f.sock
	c := New("http://localhost:1", sock)
	// Remove the socket: every observation fails until the deadline.
	f.srv.Close()
	os.Remove(sock)
	out := c.Apply(context.Background(),
		ReloadBaseline{InstanceID: "i1", StartedGeneration: 1},
		10*time.Millisecond, 300*time.Millisecond)
	if out != Unknown {
		t.Fatalf("outcome = %v, want Unknown", out)
	}
}

func TestVersionsAndHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/versions", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`{"falco_version":"0.45.2","plugin_versions":{"container":"0.7.6"}}`))
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := New("http://"+l.Addr().String(), "")
	h, err := c.Healthz(context.Background())
	if err != nil || h != `{"status":"ok"}` {
		t.Fatalf("healthz = %q, err %v", h, err)
	}
	v, err := c.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.FalcoVersion != "0.45.2" || v.PluginVersions["container"] != "0.7.6" {
		t.Fatalf("versions decoded wrong: %+v", v)
	}
}

func TestCanReloadFalseWhenSocketMissing(t *testing.T) {
	c := New("http://localhost:1", filepath.Join(t.TempDir(), "absent.sock"))
	if c.CanReload(context.Background()) {
		t.Fatal("CanReload = true for a nonexistent socket")
	}
}
