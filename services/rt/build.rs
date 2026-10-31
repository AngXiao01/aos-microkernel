// Puts the user linker script on the link search path of every program using aos-rt; the
// workspace's rustflags pass -Tuser.ld.
fn main() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::copy("user.ld", out.join("user.ld")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=user.ld");
}
