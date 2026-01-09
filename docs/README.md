# PyBun Documentation Notes

## Telemetry

Telemetry is opt-in by default. No telemetry data is sent unless you explicitly enable it.

Enable or disable:

```bash
pybun telemetry status
pybun telemetry enable
pybun telemetry disable
```

Per-invocation overrides:

```bash
pybun --telemetry run script.py
pybun --no-telemetry run script.py
```

Environment controls:

- `PYBUN_TELEMETRY=1|0` (override on/off)
- `PYBUN_TELEMETRY_ENDPOINT` (custom endpoint URL)
- `PYBUN_TELEMETRY_TAGS` (optional metadata, `key=value,key2=value2`)
- `PYBUN_HOME` (controls where `telemetry.json` is stored)

### Collected fields

- Command name (e.g. `install`, `run`, `gc`)
- Status (`ok` or `error`)
- Duration (ms)
- PyBun version
- OS and architecture
- CI flag (`CI` env present)
- Optional `PYBUN_TELEMETRY_TAGS` metadata (redacted)

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
