//! Granular permissions for the existing Python guard, not an OS isolation boundary.
use super::SandboxConfig;
use color_eyre::eyre::{Result, eyre};

pub(super) fn validate(config: &SandboxConfig) -> Result<()> {
    for entry in &config.allow_net {
        let url = reqwest::Url::parse(&format!("tcp://{entry}"))
            .map_err(|_| eyre!("E_SANDBOX_POLICY_INVALID: invalid --allow-net destination"))?;
        if entry.is_empty()
            || entry.chars().any(char::is_whitespace)
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !url.path().is_empty()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(eyre!("E_SANDBOX_POLICY_INVALID: expected host[:port]"));
        }
    }
    if config
        .allow_run
        .iter()
        .any(|value| value.is_empty() || value.contains('\0'))
    {
        return Err(eyre!(
            "E_SANDBOX_POLICY_INVALID: invalid --allow-run executable"
        ));
    }
    Ok(())
}

pub(super) const PY: &str = r#"
import shutil

_ALLOW_NET = _load_policy_paths("PYBUN_SANDBOX_ALLOW_NET")
_ALLOW_RUN = _load_policy_paths("PYBUN_SANDBOX_ALLOW_RUN")
_RUN_TARGETS = set()
_NET_TARGETS = set()
_NET_HOSTS = set()


def _permission_denied(code, target, counter, flag):
    _deny(code + " " + str(target) + "; grant " + flag + " only for a trusted target", counter)


def _install_permissions():
    for entry in _ALLOW_RUN:
        resolved = shutil.which(entry)
        if not resolved:
            raise ValueError("allow-run executable is unavailable")
        _RUN_TARGETS.add(_normalize_path(resolved))
    for entry in _ALLOW_NET:
        if entry.startswith("["):
            host, _, suffix = entry[1:].partition("]")
            port = int(suffix[1:]) if suffix else None
        elif entry.count(":") == 1:
            host, value = entry.rsplit(":", 1)
            port = int(value)
        else:
            host, port = entry, None
        _NET_HOSTS.add((host.lower().rstrip("."), port))
        # Resolve once before installing guards: later DNS changes cannot widen
        # the allowed address set. Hosts sharing an IP share this permission.
        for item in socket.getaddrinfo(host, port or 0):
            _NET_TARGETS.add((item[4][0], port))

    def _network(address, dns=False):
        if ALLOW_NETWORK:
            return
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = str(address[0]), address[1]
        else:
            host, port = str(address), None
        candidates = _NET_HOSTS if dns else _NET_TARGETS
        host = host.lower().rstrip(".") if dns else host
        if (host, port) not in candidates and (host, None) not in candidates:
            _permission_denied("E_SANDBOX_NET_DENIED", host + ":" + str(port), "blocked_network", "--allow-net")

    def _executable(executable, cwd=None, env=None, search_path=False):
        try:
            executable = os.fsdecode(executable)
            cwd = os.fsdecode(cwd) if cwd is not None else os.getcwd()
            if os.path.dirname(executable) or not search_path:
                if not os.path.isabs(executable):
                    executable = os.path.join(cwd or os.getcwd(), executable)
                resolved = executable
            else:
                # Match subprocess semantics, including bytes PATH and child cwd.
                search = os.pathsep.join(os.path.join(cwd, directory) for directory in os.get_exec_path(env))
                resolved = shutil.which(executable, path=search)
            if resolved and _normalize_path(resolved) in _RUN_TARGETS:
                return
        except (TypeError, ValueError, OSError):
            pass
        _permission_denied("E_SANDBOX_RUN_DENIED", executable, "blocked_subprocesses", "--allow-run")

    def _permission_audit(event, args):
        if event == "subprocess.Popen":
            _executable(args[0], args[2], args[3], search_path=True)
        elif event in ("os.exec", "os.posix_spawn", "os.spawn"):
            # spawn and spawnp share this event, so a bare name is ambiguous.
            if event == "os.posix_spawn" and not os.path.dirname(os.fsdecode(args[0])):
                _permission_denied("E_SANDBOX_RUN_DENIED", args[0], "blocked_subprocesses", "--allow-run with an explicit executable path")
            _executable(args[0], env=args[2] if len(args) > 2 else None)
        elif event in ("os.system", "os.fork", "os.forkpty", "os.startfile", "os.startfile/2"):
            _permission_denied("E_SANDBOX_RUN_DENIED", event, "blocked_subprocesses", "--allow-run (use an explicit executable)")
        elif event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
            _network(args[-1])
        elif event == "socket.getaddrinfo":
            _network((args[0], args[1]), dns=True)
        elif event in ("socket.gethostbyname", "socket.gethostbyaddr"):
            _network(args[0], dns=True)
        elif event in ("socket.bind", "socket.__new__"):
            # AF_UNIX and raw sockets cannot be represented by host[:port].
            if event == "socket.__new__" and not ALLOW_NETWORK and args[1] not in (socket.AF_INET, socket.AF_INET6):
                _permission_denied("E_SANDBOX_NET_DENIED", "non-IP socket", "blocked_network", "--allow-network")
            if event == "socket.bind":
                _network(args[-1])
    # Resolve names before the syscall so audit checks the exact pinned IP.
    if not ALLOW_NETWORK and _ALLOW_NET:
        import ipaddress
        def resolved_address(self, address):
            if isinstance(address, tuple) and len(address) >= 2:
                host, port = address[:2]
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    _network((host, port), dns=True)
                    address = socket.getaddrinfo(host, port, self.family, self.type)[0][4]
            return address
        for method in ("connect", "connect_ex"):
            original = getattr(socket.socket, method)
            def checked(self, address, _original=original):
                return _original(self, resolved_address(self, address))
            setattr(socket.socket, method, checked)
        original_sendto = socket.socket.sendto
        def checked_sendto(self, *args):
            if len(args) in (2, 3):
                args = (*args[:-1], resolved_address(self, args[-1]))
            return original_sendto(self, *args)
        socket.socket.sendto = checked_sendto
    sys.addaudithook(_permission_audit)
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_network_destination_syntax_without_echoing_input() {
        for entry in ["127.0.0.1:80", "localhost", "[::1]:8080"] {
            assert!(
                validate(&SandboxConfig {
                    allow_net: vec![entry.into()],
                    ..Default::default()
                })
                .is_ok()
            );
        }
        for entry in [
            "",
            "user:secret@example.com",
            "example.com/path",
            "example.com:bad",
            "example.com?secret=x",
            "example.com\n",
        ] {
            let error = validate(&SandboxConfig {
                allow_net: vec![entry.into()],
                ..Default::default()
            })
            .unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
    }
}
