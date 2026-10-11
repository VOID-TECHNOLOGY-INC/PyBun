# Authenticated private indexes

The default uv backend uses uv's index configuration and credential providers.
Define credential-free indexes in `pyproject.toml`:

```toml
[[tool.uv.index]]
name = "internal-proxy"
url = "https://packages.example.org/simple"
default = true
```

Supply authentication at execution time:

```sh
export UV_INDEX_INTERNAL_PROXY_USERNAME='your-user'
export UV_INDEX_INTERNAL_PROXY_PASSWORD='your-token'
pybun install
pybun add your-package
```

Index names become uppercase environment-variable names, with punctuation
replaced by underscores. `authenticate = "always"` can require credential lookup
before a request; uv also supports netrc/keyring and its own authentication CLI.
PyBun does not implement a separate credential store. See
[uv indexes](https://docs.astral.sh/uv/concepts/indexes/) and
[HTTP authentication](https://docs.astral.sh/uv/concepts/authentication/http/).

`install`, `add`, `remove`, `lock` and `upgrade` accept `--index URL` or
`--index NAME=URL`. MCP project tools accept the corresponding `index` string.
`UV_INDEX`, `UV_DEFAULT_INDEX`, `UV_INDEX_URL` and `UV_EXTRA_INDEX_URL` retain uv's
semantics. For compatibility, PyBun maps `PIP_INDEX_URL` to `UV_DEFAULT_INDEX`
and `PIP_EXTRA_INDEX_URL` to `UV_INDEX` only when neither the modern nor legacy
uv equivalent is present. uv controls CLI/config/environment precedence;
its default first-index strategy is retained.

Prefer named-index credentials over embedding credentials in configuration or
shell arguments. Authenticated URL inputs are supported, but uv stores index
URLs without user information in generated project/lock files. PyBun never
writes index credentials to its own lock/state or execution receipts.

Backend stdout/stderr remains withheld on errors, protecting credentials from
providers whose secret values are unavailable to PyBun. CLI JSON/text, argument
errors, MCP output and audit inputs, execution receipts and support bundles
redact authenticated URL user information, credential keys and known credential
environment values. User stdout/stderr retains its whitespace. Index-related
environment variables are removed before executing user Python, including when
listed in sandbox `allow_env`; they remain available to uv preparation.

A legacy JSON fixture `--index` path still requires `PYBUN_BACKEND=native` for
install/lock/upgrade. The new add/remove index selector requires uv.

Run the real authenticated local-index integration fixture with:
`PYBUN_E2E_NETWORK=1 cargo test --test cli_private_index`.
It uses an isolated cache and checks authenticated package downloads, rejected
credentials, output redaction and credential-free artifacts.
