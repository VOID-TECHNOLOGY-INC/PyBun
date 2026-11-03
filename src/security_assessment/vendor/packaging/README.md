# Trusted tag generator

These four unmodified modules are vendored from PyPA packaging 26.3, distributed
under its Apache-2.0 or BSD-2-Clause licenses (included alongside the sources).
They run only inside the fixed isolated inspector, never by importing modules
from an inspected environment. There is no runtime download or installation.

Upstream: https://github.com/pypa/packaging/tree/26.3/src/packaging

Wheel: `packaging-26.3-py3-none-any.whl`

Wheel SHA-256: `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c`

Source SHA-256 values:

- `tags.py`: `0e717a082a79620d79cf0321b420df15593c4916fcda03c27cb9d82e07ef5d6e`
- `_manylinux.py`: `5b6e84324c42538ab4cdb148e2430fdba36f04427b0efda55bea083a35fa6136`
- `_musllinux.py`: `0328fb827b1170c77df4c107d49be8df8d37262103490a61e8acad8a2f9cadff`
- `_elffile.py`: `1f025f54c573f1a85740c4fbd908cc1d1fb0c177c14377ebf5f09d6cd5368780`

Update the pinned version, hashes, licenses, and profile conformance fixtures
together when updating these sources. The inspector uses a private in-memory
package namespace so unrelated installed `packaging` code cannot be imported.
