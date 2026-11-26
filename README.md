# opamp-falco

An OpAMP agent for [Falco](https://falco.org): the generic bridge
([github.com/agardnerIT/opamp-agent](https://github.com/agardnerIT/opamp-agent))
plus one driver file that knows Falco. No changes to Falco's core — the
driver manages the config files Falco loads and drives Falco's own
reload-control API (Falco 0.45+) to apply and verify a pushed config:

```
write files  ->  POST /reload (Unix socket)  ->  poll GET /reload  ->  report APPLIED/FAILED
```

## What is in here

| File | Lines | Origin |
|---|---|---|
| `falco/client.go` | 270 | falco-opamp `internal/falco/client.go`, **verbatim** (one comment reflowed by gofmt; no code change) |
| `falco/client_test.go` | 182 | falco-opamp, verbatim |
| `driver.go` | 223 | new: the six-verb mapping (below) |
| `main.go` | ~60 | new: flags + `bridge.Run` |

That is the deleted-lines arithmetic against
[github.com/agardnerIT/falco-opamp](https://github.com/agardnerIT/falco-opamp)
(957 lines, frozen at `3e8b859`): **270** lines of product protocol kept
verbatim, **344** lines of OpAMP transport deleted (the bridge does it, once,
for every product), **192** lines of config store deleted (the bridge owns
artifact writes and last-known-good rollback), and the **151**-line `main.go`
collapsed to 60 lines of flags. Total new product code: ~280 lines.

## The contract

The server pushes a config_map with the keys **`falco.yaml`** (the full main
config) and/or **`rules.yaml`** (a rules file `falco.yaml`'s `rules_files`
must load), content type `application/yaml`. Other keys are refused. A push
that would set `reload_control.enabled: false` is refused unless the driver
runs with `--require-reload-control=false`. Structural checks (YAML parses,
reload control stays enabled, `rules_files` includes the managed file) run in
`Validate`, before the reload; with `--falco-bin` set, pushed rules are also
pre-checked with `falco --validate`.

Apply/verify never trusts the reload POST's response: `POST /reload` returns
a baseline, and `Verify` polls `GET /reload` until the generation resolves to
`applied` or `rejected`. A rejection keeps the previous config running (the
bridge restores last-known-good files either way); the human-readable load
error is in **Falco's own logs**, not in the OpAMP status — the generations
API does not carry a reason.

## Run

```
go install github.com/agardnerIT/opamp-falco@latest

opamp-falco \
  --server wss://your-server/v1/opamp \
  --token "$OPAMP_TOKEN" \
  --config /etc/falco/falco.yaml \
  --rules /etc/falco/opamp/rules.yaml \
  --control-socket /run/falco/control.sock \
  --webserver http://localhost:8765
```

Bootstrap Falco once (see the server's falco profile snippet): enable
`webserver` and `reload_control`, add the managed rules file to
`rules_files`, and run Falco with `watch_config_files: false` so the reload
with feedback is the only reload.

## Conformance (2026-11-26, live Falco 0.45.2 in Docker)

Verified against a real `falcosecurity/falco:latest` (0.45.2, linux/arm64)
running in the Docker Desktop VM with the `nodriver` engine — the config
plane (webserver + reload-control socket + generation polling) is fully
live; only syscall detection (irrelevant to config management) is off.
The composed bridge + driver drove it through the opamp-server-py falco
profile (16 profile tests pass unchanged). Every claim below has a capture
in `captures/` or a Falco-side log line:

| Seam | Result | Evidence |
|---|---|---|
| Enroll/identity | `agent_type: falco`; `service.name: falco`, `falco.version: 0.45.2` | `captures/01-enroll-description.json` |
| Good rules push | `APPLIED` — real `POST /reload`, generation polling confirmed | `captures/02`-family; Falco log `Starting reload control` |
| Bad rules push | `FAILED` with rollback reason; LKG (good rules) restored on disk; Falco keeps running the previous config; load error only in Falco's logs (`hot restart failure: ... Invalid`) | `captures/03-remote-config-failed-rollback.json` |
| Two-object push (`falco.yaml` + `rules.yaml`) | `APPLIED` — both objects written, one reload (B1 fix proven end-to-end) | `captures/02-remote-config-applied.json` |
| Health | `/healthz` body reported as health status (`{"status": "ok"}`) | `captures/01` |
| RESTART command | Refused server-side: `AcceptsRestartCommand` not set (caps 6151) | `captures/04-restart-refused.json` |
| Reconnect re-apply | One re-apply per process start, then `APPLIED`; profile-tolerant | Falco log reload count 7→8 |
| Withdrawal (empty config_map) | **Gap, see below** | `captures/05-withdrawal-probe.json` |

Withdrawal probe: the server's `DELETE /agent/{id}/config` pushes an empty
config_map; the bridge fails it (`render: empty config_map`), the revision
is marked poisoned, and no rollback occurs — the applied config keeps
running. falco-opamp instead restored its startup snapshot. This is the
documented deferred bridge gap (withdrawal needs the *startup* snapshot,
not the per-push LKG); it is a bridge-side fix with a written reason, not a
driver change. Same-hash pushes after a failure are skipped silently
(no status report), which can leave the server's status view stale —
also a bridge-side finding, recorded in the stage notes.

## Honest limitations

- **Verified under the `nodriver` engine.** The apply/verify path is
  confirmed against a live Falco 0.45.2 (Docker Desktop VM, linux/arm64):
  real reload-control socket, real generation polling, real rejections.
  Falco's kernel syscall detection is not exercised (needs a real Linux
  host with eBPF/kmod); it does not participate in config management.
- **Reconnect re-applies once per process start.** The applied-config hash is
  in memory, not persisted, so after a restart the server's config is applied
  once more (a no-op reload for an unchanged config). Verified live and
  tolerated by the profile.
- **Capabilities differ from falco-opamp's.** falco-opamp advertised 2055;
  the bridge advertises 6151 — the RESTART/packages bits were off in both,
  and the bridge adds `ReportsRemoteConfig`. Same surfaces, stated plainly.
- **Health detail, not attributes.** falco-opamp reported reload generations
  as health attributes; the bridge's `driver.Health` carries a healthy flag
  and a detail string only, so `Health` reports `/healthz`'s body (or error).
  Generation attributes are a bridge interface gap to revisit, not a lie.
