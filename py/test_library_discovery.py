"""Library() discovery order: bundled, ABSTRACTION_IPC_LIBRARY, ABSTRACTION_IPC_PREFIX,
then the installed runtime's recorded ipc_library. The registry reader is injected;
no test touches the real registry."""
import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from abstraction import ipc
from abstraction.ipc import _native


class Loaded(Exception):
    pass


def load(path):
    raise Loaded(path)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.files = {}
        for name in ("bundled", "env", "hklm", "hkcu"):
            self.files[name] = root / name / "abstraction_ipc.dll"
            self.files[name].parent.mkdir()
            self.files[name].write_bytes(b"")
        self.prefix = root / "prefix"
        relative = ("bin/abstraction_ipc.dll" if sys.platform == "win32" else
                    "lib/libabstraction_ipc.dylib" if sys.platform == "darwin" else "lib/libabstraction_ipc.so")
        (self.prefix / relative).parent.mkdir(parents=True)
        (self.prefix / relative).write_bytes(b"")
        self.prefixed = self.prefix / relative
        self.reads = []
        self.recorded = {"HKEY_LOCAL_MACHINE": str(self.files["hklm"]), "HKEY_CURRENT_USER": str(self.files["hkcu"])}
        self.addCleanup(self.dir.cleanup)
        env = {k: v for k, v in os.environ.items() if k not in ("ABSTRACTION_IPC_LIBRARY", "ABSTRACTION_IPC_PREFIX")}
        for p in (patch.dict(os.environ, env, clear=True), patch.object(ipc.C, "CDLL", side_effect=load),
                  patch.object(_native, "registry_reader", self.read),
                  patch.object(_native, "bundled_library_path", lambda: None)):
            p.start()
            self.addCleanup(p.stop)

    def read(self, root, view):
        self.reads.append(root)
        return self.recorded.get(root)

    def loaded(self, **options):
        with self.assertRaises(Loaded) as caught:
            ipc.Library(**options)
        return Path(caught.exception.args[0])

    def test_bundled_library_comes_first(self):
        with patch.object(_native, "bundled_library_path", lambda: self.files["bundled"]):
            os.environ["ABSTRACTION_IPC_LIBRARY"] = str(self.files["env"])
            self.assertEqual(self.loaded(), self.files["bundled"].resolve())
        self.assertEqual(self.reads, [])

    def test_development_loader_never_reads_installed_registration(self):
        with patch.object(_native, 'installed_library_path', side_effect=AssertionError('installed lookup')):
            with self.assertRaisesRegex(ValueError, 'ABSTRACTION_IPC_LIBRARY'):
                ipc.Library(allow_installed=False)
            self.assertEqual(self.loaded(path=self.files['env'], allow_installed=False), self.files['env'].resolve())
            with patch.object(_native, 'bundled_library_path', return_value=self.files['bundled']):
                self.assertEqual(self.loaded(allow_installed=False), self.files['bundled'].resolve())
            os.environ['ABSTRACTION_IPC_LIBRARY'] = str(self.files['env'])
            self.assertEqual(self.loaded(allow_installed=False), self.files['env'].resolve())
            os.environ['ABSTRACTION_IPC_LIBRARY'] = ''
            os.environ['ABSTRACTION_IPC_PREFIX'] = str(self.prefix)
            self.assertEqual(self.loaded(allow_installed=False), self.prefixed.resolve())
        self.assertEqual(self.reads, [])

    def test_environment_library_precedes_the_registry(self):
        os.environ["ABSTRACTION_IPC_LIBRARY"] = str(self.files["env"])
        self.assertEqual(self.loaded(), self.files["env"].resolve())
        self.assertEqual(self.reads, [])

    def test_environment_prefix_precedes_the_registry(self):
        os.environ["ABSTRACTION_IPC_PREFIX"] = str(self.prefix)
        self.assertEqual(self.loaded(), self.prefixed.resolve())
        self.assertEqual(self.reads, [])

    def test_explicit_path_precedes_bundle_environment_and_registry(self):
        with patch.object(_native, "bundled_library_path", side_effect=AssertionError("bundle read")):
            os.environ["ABSTRACTION_IPC_LIBRARY"] = str(self.files["env"])
            with self.assertRaises(Loaded) as caught:
                ipc.Library(self.files["hkcu"])
        self.assertEqual(Path(caught.exception.args[0]), self.files["hkcu"].resolve())
        self.assertEqual(self.reads, [])

    def test_explicit_prefix_precedes_bundle_environment_and_registry(self):
        with patch.object(_native, "bundled_library_path", side_effect=AssertionError("bundle read")):
            os.environ["ABSTRACTION_IPC_LIBRARY"] = str(self.files["env"])
            with self.assertRaises(Loaded) as caught:
                ipc.Library(prefix=self.prefix)
        self.assertEqual(Path(caught.exception.args[0]), self.prefixed.resolve())
        self.assertEqual(self.reads, [])

    def test_machine_wide_install_precedes_per_user(self):
        self.assertEqual(self.loaded(), self.files["hklm"].resolve())
        self.assertEqual(self.reads, ["HKEY_LOCAL_MACHINE"])

    def test_per_user_install_when_no_machine_wide_value(self):
        del self.recorded["HKEY_LOCAL_MACHINE"]
        self.assertEqual(self.loaded(), self.files["hkcu"].resolve())
        self.assertEqual(self.reads, ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"])

    def test_missing_machine_wide_file_falls_through_to_per_user(self):
        self.recorded["HKEY_LOCAL_MACHINE"] = str(Path(self.dir.name) / "gone" / "abstraction_ipc.dll")
        self.assertEqual(self.loaded(), self.files["hkcu"].resolve())
        self.assertEqual(self.reads, ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"])

    def test_relative_machine_wide_value_falls_through_to_per_user(self):
        self.recorded["HKEY_LOCAL_MACHINE"] = "bin\\abstraction_ipc.dll"
        self.assertEqual(self.loaded(), self.files["hkcu"].resolve())

    def test_private_filter_refusal_continues_to_per_user(self):
        seen = []
        def accept(path):
            seen.append(path)
            return path == str(self.files["hkcu"])
        self.assertEqual(_native.installed_library_path(_accept=accept), str(self.files["hkcu"]))
        self.assertEqual(seen, [str(self.files["hklm"]), str(self.files["hkcu"])])
        self.assertEqual(self.reads, ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"])

    def test_private_filter_sees_only_absolute_existing_files(self):
        for invalid in ("relative.dll", str(Path(self.dir.name) / "missing.dll"), self.dir.name):
            self.recorded["HKEY_LOCAL_MACHINE"] = invalid
            with self.subTest(machine=invalid), patch.object(_native, "registry_reader", self.read):
                seen = []
                self.assertEqual(_native.installed_library_path(_accept=lambda path: seen.append(path) or True),
                                 str(self.files["hkcu"]))
                self.assertEqual(seen, [str(self.files["hkcu"])])

    def test_service_only_discovery_needs_no_panel_or_shared_folder(self):
        # These files live in independent fixture directories. The only
        # registry value read is ipc_library; there is no Panel record.
        self.assertEqual(_native.installed_library_path(), str(self.files["hklm"]))
        self.assertEqual(self.reads, ["HKEY_LOCAL_MACHINE"])

    def test_nothing_recorded_names_the_configuration(self):
        self.recorded.clear()
        with self.assertRaisesRegex(ValueError, "ABSTRACTION_IPC_LIBRARY"):
            ipc.Library()

    def test_no_reader_off_windows_finds_nothing(self):
        with patch.object(_native, "registry_reader", None):
            self.assertIsNone(_native.installed_library_path())


class StubKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class StubWinreg(types.ModuleType):
    """Stands in for winreg; records each open, never reaches the registry."""
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER = "HKLM", "HKCU"
    KEY_READ, KEY_WOW64_64KEY = 0x20019, 0x0100
    REG_SZ, REG_EXPAND_SZ = 1, 2

    def __init__(self, value, kind):
        super().__init__("winreg")
        self.value, self.kind, self.opens = value, kind, []

    def OpenKey(self, root, subkey, reserved, access):
        self.opens.append((root, subkey, access))
        return StubKey()

    def QueryValueEx(self, key, name):
        return self.value, self.kind


class ReaderTests(unittest.TestCase):
    def test_access_mask_per_hive(self):
        stub = StubWinreg("C:\\x.dll", StubWinreg.REG_SZ)
        with patch.dict(sys.modules, {"winreg": stub}):
            self.assertEqual(_native._read_registry("HKEY_LOCAL_MACHINE", 0x0100), "C:\\x.dll")
            self.assertEqual(_native._read_registry("HKEY_CURRENT_USER", 0), "C:\\x.dll")
        self.assertEqual(stub.opens, [("HKLM", _native.RUNTIME_KEY, 0x20019 | 0x0100),
                                      ("HKCU", _native.RUNTIME_KEY, 0x20019)])

    def test_expand_string_is_refused(self):
        stub = StubWinreg("%ProgramFiles%\\x.dll", StubWinreg.REG_EXPAND_SZ)
        with patch.dict(sys.modules, {"winreg": stub}):
            self.assertIsNone(_native._read_registry("HKEY_CURRENT_USER", 0))

    def test_no_reader_off_windows(self):
        try:
            with patch.object(sys, "platform", "linux"):
                importlib.reload(_native)
                self.assertIsNone(_native.registry_reader)
        finally:
            importlib.reload(_native)


if __name__ == "__main__":
    unittest.main()
