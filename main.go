// opamp-falco — an OpAMP agent for Falco: the generic bridge
// (github.com/agardnerIT/opamp-agent) plus this driver.
//
// No changes to Falco's core. The driver manages the config files Falco
// loads, and drives Falco's own reload-control API to apply and verify a
// pushed config (Falco 0.45+):
//
//	write files  ->  POST /reload (Unix socket)  ->  poll GET /reload  ->  report APPLIED/FAILED
//
// The bridge owns the OpAMP transport, the instance uid, last-known-good
// rollback and status reporting; the only Falco-specific code here is the
// flag plumbing below.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/agardnerIT/opamp-agent/bridge"
	"github.com/agardnerIT/opamp-falco/falco"
)

func main() {
	server := flag.String("server", "ws://127.0.0.1:4320/v1/opamp", "OpAMP endpoint (ws(s):// or http(s)://)")
	token := flag.String("token", os.Getenv("OPAMP_TOKEN"), "agent bearer token")
	configPath := flag.String("config", "/etc/falco/falco.yaml", "the main config file this driver owns (Falco must already be loading it)")
	rulesPath := flag.String("rules", "/etc/falco/opamp/rules.yaml", "the managed rules file, referenced by falco.yaml's rules_files")
	webserver := flag.String("webserver", "http://localhost:8765", "base URL of Falco's TCP webserver (healthz/versions/reload observation)")
	controlSocket := flag.String("control-socket", "/run/falco/control.sock", "Falco reload-control Unix socket (reload_control.socket)")
	falcoBin := flag.String("falco-bin", "", "path to a falco binary; pushes are pre-checked with `falco --validate` when set")
	instanceUIDFile := flag.String("instance-uid-file", "", "file to persist the instance uid across restarts (default: instance.uid in the working directory)")
	requireRC := flag.Bool("require-reload-control", true, "refuse pushes that set reload_control.enabled=false; set false when falco is started with -o reload_control.enabled=true (the file may then say false by construction)")
	flag.Parse()

	drv := &FalcoDriver{
		ConfigPath:           *configPath,
		RulesPath:            *rulesPath,
		FalcoBin:             *falcoBin,
		RequireReloadControl: *requireRC,
		client:               falco.New(*webserver, *controlSocket),
	}
	if err := bridge.Run(context.Background(), bridge.Options{
		ServerURL:       *server,
		Token:           *token,
		InstanceUIDFile: *instanceUIDFile,
		Logger:          stderrLogger{},
	}, drv); err != nil {
		fmt.Fprintln(os.Stderr, "opamp-falco:", err)
		os.Exit(1)
	}
}

type stderrLogger struct{}

func (stderrLogger) Debugf(format string, v ...any) {}
func (stderrLogger) Errorf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}
