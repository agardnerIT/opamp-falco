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
| `driver.go` | ~190 | new: the six-verb mapping (below) |
| `main.go` | ~60 | new: flags + `bridge.Run` |

That is the deleted-lines arithmetic against
[github.com/agardnerIT/falco-opamp](https://github.com/agardnerIT/falco-opamp)
(957 lines, frozen at `3e8b859`): **270** lines of product protocol kept
verbatim, **344** lines of OpAMP transport deleted (the bridge does it, once,
for every product), **192** lines of config store deleted (the bridge owns
artifact writes and last-known-good rollback), and the **151**-line `main.go`
collapsed to ~60 lines of flags. Total new product code: ~250 lines.

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

## Honest limitations

- **Apply is Linux-only in practice.** Falco's kernel driver needs Linux.
  The driver itself only needs Falco's webserver and reload-control socket,
  both of which run wherever Falco runs. This port was developed on macOS
  with no Falco binary available: the falco client is covered by its
  verbatim test suite (a fake reload-control listener with the real
  generation model), and the apply path is additionally exercised by
  falco-opamp's capture procedure against a real Falco 0.45.2 — but the
  composed bridge + driver has not yet been confirmed against a live Falco.
  Until a Linux run does that, treat apply as "not green for real".
- **Reconnect re-applies once per process start.** The applied-config hash is
  in memory, not persisted, so after a restart the server's config is applied
  once more (a no-op reload for an unchanged config).
- **Capabilities differ from falco-opamp's.** falco-opamp advertised 2055;
  the bridge advertises 6151 — the RESTART/packages bits were off in both,
  and the bridge adds `ReportsRemoteConfig`. Same surfaces, stated plainly.
- **Health detail, not attributes.** falco-opamp reported reload generations
  as health attributes; the bridge's `driver.Health` carries a healthy flag
  and a detail string only, so `Health` reports `/healthz`'s body (or error).
  Generation attributes are a bridge interface gap to revisit, not a lie.
