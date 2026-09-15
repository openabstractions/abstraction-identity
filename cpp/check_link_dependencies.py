"""Fail when native IPC link requirements diverge from link-dependencies.txt.

The list beside this script is the single source. CMakeLists.txt applies it to
the exported target and installs it; Rust build.rs reads the installed copy.
The Node addon links the exported CMake target and inherits it; no node-gyp
binding exists. Checks:

  source      CMakeLists.txt and build.rs read the list and name no listed library
  --prefix    installed list equals the source and the exported CMake target's
              platform libraries equal the list's system entries
  --cargo-output
              a `cargo build -vv` log's abstraction-ipc link lines equal the
              list's entries for this host platform
  --self-test mutated copies (hardcoded library, missing entry) must fail
"""
import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORMS = {"windows": "Windows", "linux": "Linux", "macos": "Darwin"}
KINDS = ("system", "cxx-runtime")
NAME = re.compile(r"^[A-Za-z0-9_+.\-]+$")


class Divergence(Exception):
    pass


def parse(text, origin):
    entries = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[0] not in PLATFORMS or fields[1] not in KINDS or not NAME.match(fields[2]):
            raise Divergence(f"{origin}:{number}: expected '<platform> <kind> <library>': {raw}")
        entries.append(tuple(fields))
    if len(set(entries)) != len(entries):
        raise Divergence(f"{origin}: duplicate entry")
    return entries


def host_platform():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise Divergence("unsupported host platform " + sys.platform)


def without_comments(text, marker):
    return "\n".join(line.split(marker, 1)[0] for line in text.splitlines())


def check_sources(entries, cmake_text, build_rs_text):
    names = {name for _, _, name in entries}
    cmake = without_comments(cmake_text, "#")
    if "link-dependencies.txt" not in cmake:
        raise Divergence("CMakeLists.txt does not read link-dependencies.txt")
    for name in names:
        if re.search(r"PLATFORM_ID:[A-Za-z]+>:" + re.escape(name) + r">", cmake) or re.search(r"\b" + re.escape(name) + r"\b", cmake):
            raise Divergence(f"CMakeLists.txt names listed library {name} directly")
    rust = without_comments(build_rs_text, "//")
    if "link-dependencies.txt" not in rust:
        raise Divergence("build.rs does not read the installed link-dependencies.txt")
    for literal in re.findall(r'rustc-link-lib=([^"{}\s]+)', rust):
        if literal != "static=abstraction_ipc":
            raise Divergence(f"build.rs hardcodes link library {literal}")
    for name in names:
        if re.search(r'"' + re.escape(name) + r'"', rust):
            raise Divergence(f"build.rs names listed library {name} directly")


def check_prefix(entries, source_text, prefix):
    installed = prefix / "share/abstraction_ipc/link-dependencies.txt"
    if not installed.is_file():
        raise Divergence(f"{installed} is missing")
    if installed.read_bytes().replace(b"\r\n", b"\n") != source_text.encode("utf-8").replace(b"\r\n", b"\n"):
        raise Divergence("installed link-dependencies.txt differs from source")
    targets = list(prefix.glob("lib*/cmake/abstraction_ipc/abstraction_ipcTargets.cmake"))
    if len(targets) != 1:
        raise Divergence(f"expected one exported abstraction_ipcTargets.cmake under {prefix}, found {len(targets)}")
    # Exported generator expressions are escaped (\$<...>) and static usage
    # requirements are wrapped in $<LINK_ONLY:...>; unescape before matching.
    match = re.search(r'INTERFACE_LINK_LIBRARIES\s+"((?:[^"\\]|\\.)*)"', targets[0].read_text(encoding="utf-8"))
    value = (match.group(1) if match else "").replace("\\$", "$")
    exported = set(re.findall(r"\$<\$<PLATFORM_ID:([A-Za-z]+)>:([^>]+)>", value))
    expected = {(PLATFORMS[p], name) for p, kind, name in entries if kind == "system"}
    if exported != expected:
        raise Divergence(f"exported CMake platform libraries {sorted(exported)} differ from list {sorted(expected)}")


def check_cargo(entries, log_text):
    emitted = set(re.findall(r"\[abstraction-ipc [^\]]*\] cargo:rustc-link-lib=(\S+)", log_text))
    if not emitted:
        raise Divergence("cargo output has no abstraction-ipc build script link lines; build with -vv")
    platform = host_platform()
    expected = {"static=abstraction_ipc"} | {name for p, _, name in entries if p == platform}
    if emitted != expected:
        raise Divergence(f"cargo emitted {sorted(emitted)}; list requires {sorted(expected)}")


def run_checks(source, cmake, build_rs, prefix=None, cargo_output=None):
    source_text = source.read_text(encoding="utf-8")
    entries = parse(source_text, source.name)
    check_sources(entries, cmake.read_text(encoding="utf-8"), build_rs.read_text(encoding="utf-8"))
    if prefix is not None:
        check_prefix(entries, source_text, prefix)
    if cargo_output is not None:
        check_cargo(entries, cargo_output.read_text(encoding="utf-8", errors="replace"))
    return entries


def self_test(source, cmake, build_rs):
    run_checks(source, cmake, build_rs)
    cases = {
        "build.rs hardcodes a library": ("build.rs", lambda t: t.replace('println!("cargo:rustc-link-lib=static=abstraction_ipc");', 'println!("cargo:rustc-link-lib=static=abstraction_ipc");\n    println!("cargo:rustc-link-lib=advapi32");')),
        "build.rs ignores the list": ("build.rs", lambda t: t.replace("link-dependencies.txt", "other.txt")),
        "CMake hardcodes a library": ("CMakeLists.txt", lambda t: t.replace("install(DIRECTORY", "target_link_libraries(abstraction_ipc PUBLIC $<$<PLATFORM_ID:Windows>:msi>)\ninstall(DIRECTORY")),
        "malformed list": ("link-dependencies.txt", lambda t: t + "windows shared advapi32\n"),
    }
    with tempfile.TemporaryDirectory(prefix="oa-link-check-") as tmp:
        for label, (file, mutate) in cases.items():
            work = Path(tmp) / re.sub(r"\W+", "-", label)
            work.mkdir()
            paths = {"link-dependencies.txt": work / "link-dependencies.txt", "CMakeLists.txt": work / "CMakeLists.txt", "build.rs": work / "build.rs"}
            shutil.copyfile(source, paths["link-dependencies.txt"])
            shutil.copyfile(cmake, paths["CMakeLists.txt"])
            shutil.copyfile(build_rs, paths["build.rs"])
            text = paths[file].read_text(encoding="utf-8")
            changed = mutate(text)
            if changed == text:
                raise Divergence(f"self-test mutation did not apply: {label}")
            paths[file].write_text(changed, encoding="utf-8")
            try:
                run_checks(paths["link-dependencies.txt"], paths["CMakeLists.txt"], paths["build.rs"])
            except Divergence:
                print("refused as expected:", label)
            else:
                raise Divergence(f"self-test accepted: {label}")
        log = Path(tmp) / "cargo.log"
        entries = parse(source.read_text(encoding="utf-8"), source.name)
        platform = host_platform()
        good = "".join(f"[abstraction-ipc 0.0.0] cargo:rustc-link-lib={n}\n" for n in ["static=abstraction_ipc"] + [name for p, _, name in entries if p == platform])
        log.write_text(good, encoding="utf-8")
        check_cargo(entries, log.read_text(encoding="utf-8"))
        missing = good.splitlines()[:-1] if len(good.splitlines()) > 1 else []
        try:
            check_cargo(entries, "\n".join(missing) or "[abstraction-ipc 0.0.0] cargo:rustc-link-lib=static=abstraction_ipc")
        except Divergence:
            print("refused as expected: cargo output missing a listed library")
        else:
            raise Divergence("self-test accepted cargo output missing a listed library")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="check source consumers of the list")
    parser.add_argument("--prefix", type=Path, help="installed abstraction_ipc prefix to verify")
    parser.add_argument("--cargo-output", type=Path, help="captured `cargo build -vv` output of a crate depending on abstraction-ipc")
    parser.add_argument("--self-test", action="store_true", help="prove mutated consumers are refused")
    parser.add_argument("--list", type=Path, default=HERE / "link-dependencies.txt")
    parser.add_argument("--cmake", type=Path, default=HERE / "CMakeLists.txt")
    parser.add_argument("--build-rs", type=Path, default=HERE.parent / "rust/build.rs")
    args = parser.parse_args(argv)
    if not (args.check or args.prefix or args.cargo_output or args.self_test):
        parser.print_help()
        return 0
    try:
        if args.self_test:
            self_test(args.list, args.cmake, args.build_rs)
        entries = run_checks(args.list, args.cmake, args.build_rs, args.prefix, args.cargo_output)
    except Divergence as error:
        print("link dependency divergence:", error, file=sys.stderr)
        return 1
    scopes = ["sources"] + (["installed prefix"] if args.prefix else []) + (["cargo output"] if args.cargo_output else [])
    print(f"PASS link dependencies agree ({', '.join(scopes)}): " + ", ".join(" ".join(e) for e in entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
