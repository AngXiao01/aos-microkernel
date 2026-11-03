use std::path::PathBuf;
use std::process::Command;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rustc-link-arg=-T{}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rerun-if-changed=link.ld");

    // The boot modules: the root task and the servers it starts, built from services/ for
    // the user target. The test kernel also carries the test programs.
    let services = dir.join("../services");
    let target_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("services");
    let mut packages = vec![
        "-p",
        "aos-root",
        "-p",
        "aos-memory",
        "-p",
        "aos-blk",
        "-p",
        "aos-hostlink",
        "-p",
        "aos-storage-server",
        "-p",
        "aos-net",
        "-p",
        "aos-netstack",
        "-p",
        "aos-egress-gateway",
        "-p",
        "aos-view",
    ];
    if std::env::var_os("CARGO_FEATURE_KTEST").is_some() {
        packages.extend(["-p", "aos-ktest-user"]);
    }
    let status = Command::new(std::env::var("CARGO").unwrap())
        .current_dir(&services)
        .args(["build", "--release"])
        .args(&packages)
        .arg("--target-dir")
        .arg(&target_dir)
        // The kernel's flags (linker script, target) must not leak into user programs.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_TARGET_DIR")
        // Do not run the outer clippy (or other wrapper) over the nested workspace.
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .status()
        .expect("run cargo for services/");
    assert!(status.success(), "building services/ failed");
    let bins = target_dir.join("aarch64-unknown-none/release");
    println!("cargo:rustc-env=AOS_SERVICES_DIR={}", bins.display());
    for path in [
        "Cargo.toml",
        "rt",
        "ktest-user",
        "root",
        "memory",
        "virtio",
        "blk",
        "hostlink",
        "storage",
        "net",
        "netstack",
        "egress",
        "view",
    ] {
        println!("cargo:rerun-if-changed={}", services.join(path).display());
    }
    println!("cargo:rerun-if-changed={}", dir.join("abi").display());
}
