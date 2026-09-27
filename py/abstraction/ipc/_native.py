"""The native library a platform wheel bundles as package data, if any.

A source checkout ships no binary: `abstraction.ipc` then falls back to the
explicit `ABSTRACTION_IPC_LIBRARY` / `ABSTRACTION_IPC_PREFIX` configuration
`Library.__init__` already documents. A wheel built by `scripts/py_wheels.py`
carries the matching `abstraction_ipc.dll` / `libabstraction_ipc.so` /
`libabstraction_ipc.dylib` under `abstraction/ipc/_native/`, resolved here
through `importlib.resources` rather than any PATH or working-directory
search, consistent with the explicit-path contract the rest of this package
holds to.
"""
import sys
from importlib import resources

# The one file each platform's wheel carries, keyed by sys.platform. A wheel
# built for another OS, or a source checkout with no `_native/` data at all,
# resolves nothing here and the caller falls back to its own configuration.
_FILENAMES = {
    "win32": "abstraction_ipc.dll",
    "linux": "libabstraction_ipc.so",
    "darwin": "libabstraction_ipc.dylib",
}


def bundled_library_path():
    """This wheel's packaged native library, or None if it carries none."""
    filename = _FILENAMES.get(sys.platform)
    if filename is None:
        return None
    try:
        candidate = resources.files(__package__) / "_native" / filename
    except (ModuleNotFoundError, FileNotFoundError):
        return None
    try:
        if not candidate.is_file():
            return None
    except (FileNotFoundError, NotADirectoryError):
        return None
    # A wheel installs `_native/<file>` as a real file on disk; as_file then
    # yields that same path with no extraction and no cleanup to race against
    # the ctypes.CDLL load below. It exists to cover a zip-imported package,
    # which this project's installers never produce.
    with resources.as_file(candidate) as path:
        return path
