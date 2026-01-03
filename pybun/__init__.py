try:
    from importlib.metadata import version as _pkg_version
except ImportError:  # pragma: no cover
    _pkg_version = None

_FALLBACK_VERSION = "0.1.0"

if _pkg_version:
    _PACKAGE_NAMES = ("pybun-cli", "pybun")
    for _name in _PACKAGE_NAMES:
        try:
            __version__ = _pkg_version(_name)
            break
        except Exception:
            continue
    else:  # pragma: no cover - fallback only when metadata lookup fails
        __version__ = _FALLBACK_VERSION
else:  # pragma: no cover - Python <3.8
    __version__ = _FALLBACK_VERSION

__all__ = ["__version__"]
