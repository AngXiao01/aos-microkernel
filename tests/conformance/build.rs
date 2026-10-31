// The sandbox tests run a real action module: build actions/test-script for wasm32.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let actions = dir.join("../../actions");
    let target_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("actions");
    let status = Command::new(std::env::var("CARGO").unwrap())
        .current_dir(&actions)
        .args(["build", "--release", "-p", "aos-test-script", "--target-dir"])
        .arg(&target_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_TARGET_DIR")
        // Do not run the outer clippy (or other wrapper) over the nested workspace.
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .status()
        .expect("run cargo for actions/");
    assert!(status.success(), "building actions/test-script failed");
    let wasm = target_dir.join("wasm32-unknown-unknown/release/aos_test_script.wasm");
    println!("cargo:rustc-env=AOS_TEST_SCRIPT_WASM={}", wasm.display());
    for path in ["Cargo.toml", "sdk", "test-script"] {
        println!("cargo:rerun-if-changed={}", actions.join(path).display());
    }
    println!("cargo:rerun-if-changed={}", dir.join("../../core/aos-types/src").display());
}
