"""The scheduler's verification command: fail if a declared helper disappeared."""

import sys
from importlib.metadata import PackageNotFoundError, version

try:
    version("evidence-helper")
except PackageNotFoundError:
    sys.exit(23)
