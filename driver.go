// The Falco driver: the entire product-specific surface of the integration,
// answering the six-verb contract from opamp-agent/driver.
//
// Ported from github.com/agardnerIT/falco-opamp (frozen at 3e8b859): the
// product protocol (falco.Client) is that project's internal/falco package
// copied verbatim; everything it used to do around it — OpAMP transport,
// file ownership, LKG, status reporting — is the bridge's job now.
//
// Contract with the server (the falco profile): a push is a config_map with
// the key "falco.yaml" (the full main config) and/or "rules.yaml" (a rules
// file falco.yaml's rules_files must load). Unknown keys are refused.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/agardnerIT/opamp-agent/driver"
	"github.com/agardnerIT/opamp-falco/falco"

	"gopkg.in/yaml.v3"
)

// The config_map keys this driver understands — the falco profile's contract.
const (
	configKey = "falco.yaml"
	rulesKey  = "rules.yaml"
)

type FalcoDriver struct {
	ConfigPath string // the main config file this driver owns, e.g. /etc/falco/falco.yaml
	RulesPath  string // the managed rules file, referenced by falco.yaml's rules_files

	// FalcoBin, when set, pre-checks pushed rules with `falco --validate`.
	FalcoBin string

	// RequireReloadControl refuses pushes that set reload_control.enabled
	// false. Set false only when falco is started with
	// -o reload_control.enabled=true (the file then disagrees with the
	// running process by construction).
	RequireReloadControl bool

	client *falco.Client

	// baseline from Apply, polled by Verify. The bridge runs the pipeline
	// (render → validate → apply → verify) single-threaded, so one slot is
	// enough and no lock is needed.
	baseline falco.ReloadBaseline
}

// identity: who are you, and which files do you own? Version comes from
// Falco's own /versions endpoint; unreachable, the version is empty and the
// bridge reports without it.
func (d *FalcoDriver) Identity() driver.Identity {
	v, err := d.client.Versions(context.Background())
	var ver string
	if err == nil {
		ver = v.FalcoVersion
	}
	return driver.Identity{
		ServiceName: "falco",
		Version:     ver,
		OwnedFiles:  []string{d.ConfigPath, d.RulesPath},
		NonIdentifying: map[string]string{
			"falco.version": ver,
		},
	}
}

// render: split the config_map by key. falco.yaml is written to the config
// path, rules.yaml to the rules path; anything else the server had no
// contract to send. The bridge writes the artifacts; structural checks that
// need both objects together live in Validate.
func (d *FalcoDriver) Render(cfg driver.Config) (driver.Rendered, error) {
	for k := range cfg {
		if k != configKey && k != rulesKey {
			return driver.Rendered{}, fmt.Errorf("config_map must contain %q and/or %q; unknown key %q", configKey, rulesKey, k)
		}
	}
	var artifacts []driver.Artifact
	if body, ok := cfg[configKey]; ok {
		artifacts = append(artifacts, driver.Artifact{Path: d.ConfigPath, Body: body})
	}
	if body, ok := cfg[rulesKey]; ok {
		artifacts = append(artifacts, driver.Artifact{Path: d.RulesPath, Body: body})
	}
	if len(artifacts) == 0 {
		return driver.Rendered{}, fmt.Errorf("empty config_map")
	}
	return driver.Rendered{Artifacts: artifacts}, nil
}

// validate: the structural checks falco-opamp enforced in its store, plus the
// optional `falco --validate` pre-check. The bridge writes artifacts BEFORE
// calling this, so the on-disk files hold the NEW content — which is what a
// validator wants to see.
func (d *FalcoDriver) Validate(r driver.Rendered) error {
	var configBody, rulesBody []byte
	for _, a := range r.Artifacts {
		switch a.Path {
		case d.ConfigPath:
			configBody = a.Body
		case d.RulesPath:
			rulesBody = a.Body
		}
	}
	if configBody != nil {
		if err := d.validateConfig(configBody, rulesBody != nil); err != nil {
			return err
		}
	}
	if d.FalcoBin != "" && rulesBody != nil {
		return d.validateRules(context.Background(), rulesBody)
	}
	return nil
}

// validateConfig is the contract falco-opamp's Store.validate enforced:
// the pushed falco.yaml must parse, must keep reload_control enabled (it is
// the driver's own control surface — a push that disables it bricks
// management), and must load the managed rules file when rules are pushed.
func (d *FalcoDriver) validateConfig(configBody []byte, rules bool) error {
	var doc map[string]any
	if err := yaml.Unmarshal(configBody, &doc); err != nil {
		return fmt.Errorf("falco.yaml does not parse as YAML: %w", err)
	}
	if d.RequireReloadControl {
		if enabled, err := boolSetting(doc, "reload_control", "enabled"); err != nil || !enabled {
			return fmt.Errorf("push would disable the driver's own control surface: reload_control.enabled must be true in the pushed falco.yaml")
		}
	}
	if rules {
		files, _ := doc["rules_files"].([]any)
		found := false
		for _, f := range files {
			if p, ok := f.(string); ok && p == d.RulesPath {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("pushed rules file %s is not loaded: falco.yaml's rules_files must include %s", rulesKey, d.RulesPath)
		}
	}
	return nil
}

// validateRules runs `falco --validate` on the pushed rules, so a load error
// surfaces as FAILED before the reload.
func (d *FalcoDriver) validateRules(ctx context.Context, rules []byte) error {
	// --validate wants a rules file path; use the managed path itself —
	// the bridge has already written the new content there, and a rejected
	// push is rolled back by the bridge's LKG machinery, not by us.
	out, err := exec.CommandContext(ctx, d.FalcoBin, "--validate", d.RulesPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("falco --validate refused the rules: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// apply: activate the already-written artifacts through Falco's own
// reload-control API (POST /reload on the Unix socket). The response is a
// baseline to poll against, NOT a verdict — falco accepts the POST before it
// has read a line of the config.
func (d *FalcoDriver) Apply(ctx context.Context, r driver.Rendered) error {
	b, err := d.client.Reload(ctx)
	if err != nil {
		return err
	}
	d.baseline = b
	return nil
}

// verify: poll GET /reload until the reload cycle resolves. Falco reports
// generations, not reasons — a rejection's human-readable load error is in
// falco's own log output, and this says so instead of inventing one.
func (d *FalcoDriver) Verify(ctx context.Context, r driver.Rendered) (bool, string) {
	switch d.client.Apply(ctx, d.baseline, 500*time.Millisecond, 30*time.Second) {
	case falco.Applied:
		return true, ""
	case falco.Rejected:
		return false, "falco rejected the pushed config (it keeps running the previous one); the load error is in falco's log output"
	default:
		return false, "reload outcome unknown (falco restarted or the deadline passed); check falco's logs before retrying"
	}
}

// health: alive = the webserver answers /healthz, with the body as the
// detail. Falco's start time is not exposed by any endpoint — zero means
// unknown, and the bridge reports it as unknown rather than inventing one.
func (d *FalcoDriver) Health(ctx context.Context) driver.Health {
	body, err := d.client.Healthz(ctx)
	if err != nil {
		return driver.Health{Healthy: false, Detail: err.Error()}
	}
	return driver.Health{Healthy: true, Detail: body}
}

// effective config: the two files as written, under the profile's keys.
// Falco has no config read-back; this is the honest "what we handed Falco".
func (d *FalcoDriver) EffectiveConfig(ctx context.Context) map[string][]byte {
	out := map[string][]byte{}
	if b, err := os.ReadFile(d.ConfigPath); err == nil {
		out[configKey] = b
	}
	if b, err := os.ReadFile(d.RulesPath); err == nil && len(b) > 0 {
		out[rulesKey] = b
	}
	return out
}

func boolSetting(doc map[string]any, section, key string) (bool, error) {
	sec, ok := doc[section].(map[string]any)
	if !ok {
		return false, fmt.Errorf("section %q missing", section)
	}
	b, _ := sec[key].(bool)
	return b, nil
}
