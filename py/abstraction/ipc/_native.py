"""The native library a platform wheel bundles as package data, if any.

A source checkout ships no binary: `abstraction.ipc` then falls back to the
explicit `ABSTRACTION_IPC_LIBRARY` / `ABSTRACTION_IPC_PREFIX` configuration
`Library.__init__` already documents, and on Windows last to the ipc_library
value the installed runtime records (`installed_library_path`). A wheel built by `scripts/py_wheels.py`
carries the matching `abstraction_ipc.dll` / `libabstraction_ipc.so` /
`libabstraction_ipc.dylib` under `abstraction/ipc/_native/`, resolved here
through `importlib.resources` rather than any PATH or working-directory
search, consistent with the explicit-path contract the rest of this package
holds to.
"""
import sys
from importlib import resources
from pathlib import Path

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


# The installer records the library's full path as HKMU
# Software\OpenAbstractions\Abstraction ipc_library (installer/abstraction.wxs):
# HKLM for a machine-wide install, HKCU for a per-user one.
RUNTIME_KEY = "Software\\OpenAbstractions\\Abstraction"


def _read_registry(root, view):
    """One view's ipc_library string, or None. Reads only; never writes."""
    import winreg
    try:
        with winreg.OpenKey(getattr(winreg, root), RUNTIME_KEY, 0, winreg.KEY_READ | view) as key:
            value, kind = winreg.QueryValueEx(key, "ipc_library")
    except OSError:
        return None
    return value if kind == winreg.REG_SZ and isinstance(value, str) else None


# Tests replace this reader; production reads the real registry on Windows only.
registry_reader = _read_registry if sys.platform == "win32" else None


def installed_library_path(*, _accept=None):
    """The recorded ipc_library, machine-wide first, or None.

    _accept is a private adopter filter applied only to otherwise valid
    recorded candidates. A refusal continues to the next hive. Generic
    discovery requires no Panel or adopter-specific installation layout.
    """
    read = registry_reader
    if read is None:
        return None
    view64 = 0x0100  # KEY_WOW64_64KEY
    for root, view in (("HKEY_LOCAL_MACHINE", view64), ("HKEY_CURRENT_USER", 0)):
        value = read(root, view)
        # A relative, missing or non-file value falls through to the next hive.
        if value and Path(value).is_absolute() and Path(value).is_file() and (_accept is None or _accept(value)):
            return value
    return None
