use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=OA_IPC_PREFIX");
    println!("cargo:rerun-if-env-changed=OA_IPC_CHECK_ONLY");
    // Type-checking never links: cargo check needs no installed native prefix.
    if env::var_os("OA_IPC_CHECK_ONLY").is_some_and(|v| v == "1") {
        println!("cargo:warning=OA_IPC_CHECK_ONLY=1 links no abstraction_ipc; use it with cargo check only");
        return;
    }
    let prefix = PathBuf::from(
        env::var_os("OA_IPC_PREFIX")
            .expect("OA_IPC_PREFIX must name an installed static CMake prefix"),
    );
    assert!(prefix.is_absolute(), "OA_IPC_PREFIX must be absolute");
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    assert!(
        target != "windows" || env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc",
        "Windows requires the MSVC target and matching native library"
    );
    let name = if target == "windows" {
        "abstraction_ipc.lib"
    } else {
        "libabstraction_ipc.a"
    };
    assert!(
        prefix.join("lib").join(name).is_file(),
        "install the static abstraction_ipc library under prefix/lib"
    );
    println!(
        "cargo:rerun-if-changed={}",
        prefix.join("lib").join(name).display()
    );
    assert!(
        !prefix.join("bin/abstraction_ipc.dll").exists(),
        "use a static-only prefix, not a DLL import library"
    );
    // The installed native package exports its own link requirements; this
    // script names no platform library itself.
    let list = prefix.join("share/abstraction_ipc/link-dependencies.txt");
    assert!(
        list.is_file(),
        "install abstraction_ipc with share/abstraction_ipc/link-dependencies.txt"
    );
    println!("cargo:rerun-if-changed={}", list.display());
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=abstraction_ipc");
    let text = fs::read_to_string(&list).expect("readable link-dependencies.txt");
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let valid = fields.len() == 3
            && matches!(fields[0], "windows" | "linux" | "macos")
            && matches!(fields[1], "system" | "cxx-runtime")
            && !fields[2].is_empty()
            && fields[2]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'+' | b'.' | b'-'));
        assert!(valid, "malformed link-dependencies.txt line {}", index + 1);
        if fields[0] == target {
            println!("cargo:rustc-link-lib={}", fields[2]);
        }
    }
}
