use std::{env, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=OA_IPC_PREFIX");
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
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=abstraction_ipc");
    if target == "windows" {
        println!("cargo:rustc-link-lib=advapi32");
    } else if target == "macos" {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
