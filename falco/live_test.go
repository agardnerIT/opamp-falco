package falco

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveFalco runs against a real Falco when FALCO_WEBSERVER is set:
//
//	FALCO_WEBSERVER=http://localhost:18765 go test -run TestLiveFalco ./internal/falco/
//
// It verifies the read paths (healthz/versions/reload status) against the
// product; the reload POST needs the Unix socket and is exercised by the
// opamp-server-py capture procedure (docs/falco-scope.md).
func TestLiveFalco(t *testing.T) {
	base := os.Getenv("FALCO_WEBSERVER")
	if base == "" {
		t.Skip("FALCO_WEBSERVER not set; live test skipped")
	}
	c := New(base, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h, err := c.Healthz(ctx)
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	t.Logf("healthz: %s", h)

	v, err := c.Versions(ctx)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if v.FalcoVersion == "" {
		t.Fatalf("versions: empty falco_version: %+v", v)
	}
	t.Logf("versions: falco %s (libs %s, plugins %v)", v.FalcoVersion, v.LibsVersion, v.PluginVersions)

	st, err := c.ReloadStatus(ctx)
	if err != nil {
		t.Fatalf("reload status: %v", err)
	}
	if st.InstanceID == "" || !st.Ready {
		t.Fatalf("reload status unexpected: %+v", st)
	}
	t.Logf("reload: instance=%s started=%d applied=%d rejected=%d ready=%v",
		st.InstanceID, st.StartedGeneration, st.AppliedGeneration, st.RejectedGeneration, st.Ready)
}
