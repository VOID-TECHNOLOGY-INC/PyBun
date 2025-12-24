try:
    from importlib.metadata import version as _pkg_version
except ImportError:  # pragma: no cover
    _pkg_version = None

if _pkg_version:
    try:
        __version__ = _pkg_version("pybun")
    except Exception:
        __version__ = "0.1.0"
else:
    __version__ = "0.1.0"

__all__ = ["__version__"]
