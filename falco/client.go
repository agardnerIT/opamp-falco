// Package falco is the client for the control surfaces Falco itself exposes:
// the TCP webserver (GET /healthz, GET /versions, GET /reload) and the
// reload-control Unix socket (POST /reload).
//
// Nothing here touches Falco's internals; every call is a documented endpoint
// (Falco 0.45+). See falco.yaml in the falco repository, sections `webserver`
// and `reload_control`.
package falco

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Versions is the decoded body of GET /versions.
type Versions struct {
	FalcoVersion        string            `json:"falco_version"`
	LibsVersion         string            `json:"libs_version"`
	DefaultDriver       string            `json:"default_driver_version"`
	DriverAPIVersion    string            `json:"driver_api_version"`
	DriverSchemaVersion string            `json:"driver_schema_version"`
	EngineVersion       string            `json:"engine_version"`
	PluginAPIVersion    string            `json:"plugin_api_version"`
	PluginVersions      map[string]string `json:"plugin_versions"`
}

// ReloadStatus is the decoded body of GET /reload.
type ReloadStatus struct {
	InstanceID         string `json:"instance_id"`
	StartedGeneration  int64  `json:"started_generation"`
	AppliedGeneration  int64  `json:"applied_generation"`
	RejectedGeneration int64  `json:"rejected_generation"`
	Ready              bool   `json:"ready"`
}

// ReloadBaseline is the decoded body of a 202 response from POST /reload.
type ReloadBaseline struct {
	InstanceID        string `json:"instance_id"`
	StartedGeneration int64  `json:"started_generation"`
}

// ApplyOutcome is the verdict of one reload cycle.
type ApplyOutcome int

const (
	// Applied: falco reported ready with applied > max(baseline, rejected).
	Applied ApplyOutcome = iota
	// Rejected: falco rejected the config; the previous runtime kept running.
	Rejected
	// Unknown: the process restarted, the socket went away, or the deadline
	// passed. The reload may have happened; the caller must not claim success.
	Unknown
)

// Client talks to one Falco process.
type Client struct {
	// webserverURL is the base URL of Falco's TCP webserver, e.g.
	// http://localhost:8765. Used for GET /healthz, /versions and /reload.
	webserverURL string

	// controlSocket is the path of the reload-control Unix socket, e.g.
	// /run/falco/control.sock. Empty means POST /reload is unavailable
	// (reload_control disabled or not Linux); observation still works over TCP.
	controlSocket string

	http *http.Client
}

func New(webserverURL, controlSocket string) *Client {
	return &Client{
		webserverURL:  strings.TrimRight(webserverURL, "/"),
		controlSocket: controlSocket,
		http:          &http.Client{Timeout: 5 * time.Second},
	}
}

// CanReload reports whether POST /reload is available (a control socket is
// configured and reachable). Without it the sidecar can observe reloads but
// never cause them, so config delivery must be refused up front.
func (c *Client) CanReload(ctx context.Context) bool {
	if c.controlSocket == "" {
		return false
	}
	resp, err := c.postReload(ctx)
	if err != nil {
		return false
	}
	// A POST queues a reload for real; nothing here is a dry run. Falco's own
	// reload control re-reads files, so this probed reload is harmless: it
	// applies whatever is currently on disk. Close the body regardless.
	defer io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return true
}

// Healthz returns the body of GET /healthz (e.g. `{"status": "ok"}`).
func (c *Client) Healthz(ctx context.Context) (string, error) {
	resp, err := c.get(ctx, "/healthz")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return "", fmt.Errorf("healthz: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("healthz: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return strings.TrimSpace(string(body)), nil
}

// Versions returns the running Falco's component versions.
func (c *Client) Versions(ctx context.Context) (Versions, error) {
	resp, err := c.get(ctx, "/versions")
	if err != nil {
		return Versions{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Versions{}, fmt.Errorf("versions: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Versions{}, fmt.Errorf("versions: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var v Versions
	if err := json.Unmarshal(body, &v); err != nil {
		return Versions{}, fmt.Errorf("versions: decode: %w", err)
	}
	return v, nil
}

// ReloadStatus reports falco's reload state over TCP (or over the control
// socket when configured, which also works while the webserver is disabled).
func (c *Client) ReloadStatus(ctx context.Context) (ReloadStatus, error) {
	var (
		resp *http.Response
		err  error
	)
	if c.controlSocket != "" {
		resp, err = c.requestSocket(ctx, http.MethodGet, "/reload")
	} else {
		resp, err = c.get(ctx, "/reload")
	}
	if err != nil {
		return ReloadStatus{}, fmt.Errorf("reload status: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return ReloadStatus{}, fmt.Errorf("reload status: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ReloadStatus{}, fmt.Errorf("reload status: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var st ReloadStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return ReloadStatus{}, fmt.Errorf("reload status: decode %q: %w", string(body), err)
	}
	return st, nil
}

// Reload queues a reload and returns the baseline to poll against.
//
// Wire contract (falco reload_control.cpp): the request MUST be a POST with an
// explicitly zero-length body and no query string — httplib answers 400 to a
// POST without a Content-Length header, and 400 "do not accept a body or
// query" to anything else.
func (c *Client) Reload(ctx context.Context) (ReloadBaseline, error) {
	resp, err := c.postReload(ctx)
	if err != nil {
		return ReloadBaseline{}, fmt.Errorf("reload: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return ReloadBaseline{}, fmt.Errorf("reload: read body: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		return ReloadBaseline{}, fmt.Errorf("reload: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var b ReloadBaseline
	if err := json.Unmarshal(body, &b); err != nil {
		return ReloadBaseline{}, fmt.Errorf("reload: decode %q: %w", string(body), err)
	}
	return b, nil
}

// Apply writes nothing; it waits for one reload cycle to resolve and reports
// the outcome. Poll GET /reload until, on the same instance:
//
//   - ready && applied > max(baseline, rejected)  -> Applied
//   - rejected > baseline && applied <= baseline  -> Rejected
//   - instance_id changed or deadline reached    -> Unknown
func (c *Client) Apply(ctx context.Context, baseline ReloadBaseline, poll, deadline time.Duration) ApplyOutcome {
	if baseline.StartedGeneration < 0 {
		return Unknown
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	for {
		st, err := c.ReloadStatus(ctx)
		if err == nil {
			if st.InstanceID != "" && st.InstanceID != baseline.InstanceID {
				return Unknown // falco restarted mid-reload: outcome unknown
			}
			limit := baseline.StartedGeneration
			if st.RejectedGeneration > limit {
				limit = st.RejectedGeneration
			}
			if st.Ready && st.AppliedGeneration > limit {
				return Applied
			}
			if st.RejectedGeneration > baseline.StartedGeneration &&
				st.AppliedGeneration <= baseline.StartedGeneration {
				return Rejected
			}
		}
		select {
		case <-ctx.Done():
			return Unknown
		case <-time.After(poll):
		}
	}
}

// get issues a GET against the TCP webserver.
func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.webserverURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// postReload issues the control-socket POST with the explicit zero-length
// body the endpoint requires.
func (c *Client) postReload(ctx context.Context) (*http.Response, error) {
	return c.requestSocket(ctx, http.MethodPost, "/reload")
}

// requestSocket runs one HTTP request over the Unix socket.
func (c *Client) requestSocket(ctx context.Context, method, path string) (*http.Response, error) {
	if c.controlSocket == "" {
		return nil, fmt.Errorf("no control socket configured")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.controlSocket)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://falco"+path, nil)
	if err != nil {
		return nil, err
	}
	// Falco's reload_control accepts only a bodyless, queryless POST; httplib
	// treats a POST with no Content-Length header as malformed and answers
	// 400 with no body. Send the header explicitly.
	req.Header.Set("Content-Length", "0")
	return client.Do(req)
}
