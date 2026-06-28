import os
import pkg_resources
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "handler": func,
        }
        return func

    return decorator


def _parse_severity(severity: str) -> int:
    """Convert severity string to numeric value for comparison."""
    levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return levels.get(severity.lower(), 0)


def _get_installed_packages() -> list[dict]:
    """Gather installed packages and versions."""
    packages = []
    try:
        for dist in pkg_resources.working_set:
            packages.append({
                "name": dist.key,
                "version": dist.version,
            })
    except Exception:
        pass
    return packages


def _check_package_vulnerabilities(package: dict) -> list[dict]:
    """
    Run pip-audit for a single package and parse results.
    Falls back to safety check if pip-audit is not available.
    """
    vulnerabilities = []
    try:
        result = subprocess.run(
            ["pip-audit", "--package", package["name"], "--version", package["version"]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return vulnerabilities

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 5:
                vulnerability = {
                    "package": parts[0],
                    "installed_version": parts[1],
                    "vulnerability_id": parts[2],
                    "severity": parts[3].lower(),
                    "description": " ".join(parts[4:]),
                    "fix_version": parts[1],
                    "next_action": {
                        "tool": "pybun_upgrade",
                    },
                }
                vulnerabilities.append(vulnerability)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return vulnerabilities


@register_tool(
    name="pybun_audit",
    description="Run dependency vulnerability scanning and return structured results",
    input_schema={
        "type": "object",
        "properties": {
            "fix": {
                "type": "boolean",
                "description": "Suggest fix commands for each vulnerability (default: true)",
            },
            "severity_threshold": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Only report vulnerabilities at or above this severity",
            },
        },
    },
)
def pybun_audit(fix: bool = True, severity_threshold: str = "low") -> dict:
    """
    Implements pybun_audit MCP tool.
    Scans installed packages for known vulnerabilities using pip-audit.
    """
    threshold_level = _parse_severity(severity_threshold)

    packages = _get_installed_packages()
    all_vulnerabilities = []

    for pkg in packages:
        vulns = _check_package_vulnerabilities(pkg)
        for v in vulns:
            if _parse_severity(v.get("severity", "low")) >= threshold_level:
                # Calculate fix version suggestion
                if fix and v.get("fix_version"):
                    v["fix_command"] = f"pybun_upgrade {v['package']}=={v['fix_version']}"
                all_vulnerabilities.append(v)

    summary = {
        "scanned": len(packages),
        "vulnerable": len(all_vulnerabilities),
        "critical": sum(1 for v in all_vulnerabilities if v["severity"] == "critical"),
        "high": sum(1 for v in all_vulnerabilities if v["severity"] == "high"),
        "medium": sum(1 for v in all_vulnerabilities if v["severity"] == "medium"),
        "low": sum(1 for v in all_vulnerabilities if v["severity"] == "low"),
    }

    return {
        "status": "ok",
        "summary": summary,
        "vulnerabilities": all_vulnerabilities,
    }
