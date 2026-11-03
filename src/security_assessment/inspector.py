"""Fixed CPython identity/tag probe; reads no installed distribution code."""
import json
import os
import platform
import subprocess
import sys
import types

if not sys.flags.isolated or not sys.flags.no_site:
    raise RuntimeError("isolated inspector required")
if sys.implementation.name != "cpython" or sys.version_info < (3, 8):
    raise RuntimeError("unsupported interpreter")

bundles = json.loads(sys.stdin.read(524288))
generator_version = "25.0" if sys.version_info < (3, 9) else "26.3"
sources = bundles[generator_version]
package = types.ModuleType("_pybun_packaging")
package.__path__ = []
sys.modules[package.__name__] = package
for name in ("_elffile", "_manylinux", "_musllinux", "tags"):
    module = types.ModuleType(package.__name__ + "." + name)
    module.__package__ = package.__name__
    sys.modules[module.__name__] = module
    setattr(package, name, module)
    exec(compile(sources[name], "<trusted-packaging-" + generator_version + "/" + name + ">", "exec"), module.__dict__)

# packaging's old-macOS compatibility probe invokes this same trusted Python.
# Retain isolation for that subprocess too; never search project/site paths.
original_run = subprocess.run
def isolated_run(args, *pargs, **kwargs):
    if args and args[0] == sys.executable:
        args = [args[0], "-I", "-S", "-B"] + list(args[1:])
    return original_run(args, *pargs, **kwargs)
subprocess.run = isolated_run

tags = []
for tag in package.tags.sys_tags():
    tags.append(str(tag))
    if len(tags) > 20000:
        raise RuntimeError("tag profile exceeds bounds")
libc_name, libc_version = platform.libc_ver()
def pep440_version(version_info):
    suffix = {"alpha": "a", "beta": "b", "candidate": "rc", "final": ""}[version_info.releaselevel]
    value = ".".join(str(n) for n in version_info[:3])
    return value + (suffix + str(version_info.serial) if suffix else "")

python_version = pep440_version(sys.version_info)
marker_environment = {
    "implementation_name": sys.implementation.name,
    "implementation_version": pep440_version(sys.implementation.version),
    "os_name": os.name,
    "platform_machine": platform.machine(),
    "platform_python_implementation": platform.python_implementation(),
    "platform_release": platform.release(),
    "platform_system": platform.system(),
    "platform_version": platform.version(),
    "python_full_version": python_version,
    "python_version": str(sys.version_info.major) + "." + str(sys.version_info.minor),
    "sys_platform": sys.platform,
}
result = {
    "generator_version": generator_version,
    "marker_environment": marker_environment,
    "implementation": sys.implementation.name,
    "python_version": python_version,
    "os": sys.platform,
    "architecture": platform.machine().lower(),
    "libc": (libc_name + "-" + libc_version) if libc_name else None,
    "deployment": platform.mac_ver()[0] if sys.platform == "darwin" else None,
    "tags": tags,
}
encoded = json.dumps(result, sort_keys=True)
if len(encoded.encode("utf-8")) > 5 * 1024 * 1024:
    raise RuntimeError("tag profile exceeds bounds")
print(encoded)
