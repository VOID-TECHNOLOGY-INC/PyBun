# PyBun Documentation Notes

## Telemetry

Telemetry is opt-in by default. No telemetry data is sent unless you explicitly enable it.

Enable or disable:

```bash
pybun telemetry status
pybun telemetry enable
pybun telemetry disable
```

Environment controls:

- `PYBUN_TELEMETRY=1|0` (override on/off)
- `PYBUN_HOME` (controls where `telemetry.json` is stored)

Planned, not yet implemented (tracked in `docs/PLAN.md` PR6.3): per-invocation
`--telemetry`/`--no-telemetry` flags, `PYBUN_TELEMETRY_ENDPOINT` (custom endpoint
URL), and `PYBUN_TELEMETRY_TAGS` (optional metadata). Do not rely on these yet —
they do not exist in `src/cli.rs` today.

### Collected fields

- Command name (e.g. `install`, `run`, `gc`)
- Status (`ok` or `error`)
- Duration (ms)
- PyBun version
- OS and architecture
- CI flag (`CI` env present)

### Redaction list

Telemetry metadata keys containing the following substrings are redacted and replaced with
`[redacted]` before sending:

- `token`
- `secret`
- `password`
- `passwd`
- `api_key`
- `apikey`
- `access_key`
- `authorization`
- `auth`
- `session`
- `cookie`
- `bearer`
- `credential`
- `private_key`
- `ssh_key`

### Privacy notice

PyBun telemetry is designed to be low-sensitivity. It does not collect source code, file
paths, command arguments, or environment variable values. The data is used to improve
performance, reliability, and feature prioritization.
