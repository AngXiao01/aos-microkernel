//! B-4 acceptance: public TLS handshake, BS1, BS6, BS8.
//!
//! Builds nothing itself. Expects `kernel/target/.../aos-kernel` built with `debug-syscalls`
//! so the capability audit is printed.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let kernel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kernel/target/aarch64-unknown-none-softfloat/release/aos-kernel");
    if !kernel.exists() {
        eprintln!("missing kernel {}", kernel.display());
        std::process::exit(1);
    }
    let dir = std::env::temp_dir().join(format!("aos-b4-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let serial = dir.join("serial.log");
    let mut child = Command::new("qemu-system-aarch64")
        .args([
            "-machine",
            "virt",
            "-cpu",
            "cortex-a72",
            "-m",
            "512M",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-global",
            "virtio-mmio.force-legacy=off",
            "-serial",
        ])
        .arg(format!("file:{}", serial.display()))
        .arg("-kernel")
        .arg(&kernel)
        .args(["-netdev", "user,id=net0", "-device", "virtio-net-device,netdev=net0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("qemu");

    let start = Instant::now();
    let mut log = String::new();
    let deadline = Duration::from_secs(90);
    while start.elapsed() < deadline {
        log = fs::read_to_string(&serial).unwrap_or_default();
        if log.contains("TLS handshake ok") || log.contains("TLS handshake failed") {
            // Give view and the cap dump a moment; both are printed around the same time.
            thread::sleep(Duration::from_millis(300));
            log = fs::read_to_string(&serial).unwrap_or_default();
            break;
        }
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    log = fs::read_to_string(&serial).unwrap_or(log);
    println!("----- serial -----");
    print!("{log}");
    println!("----- checks -----");

    let outbound = log.lines().filter(|l| l.contains("outbound_send=true")).count();
    // The debug dump prints endpoint badges. Count send-caps with badge 0xE6.
    let e6 = log.lines().filter(|l| l.starts_with("caps:") && l.contains("e6")).count();
    let bs1 = e6 == 1;
    let bs6 = log.contains("view: BS6 inbound connect refused");
    let bs8 = log.contains("egress: BS8 payload mismatch refused");
    let tls = log.contains("egress: TLS handshake ok");
    println!("BS1 e6-lines={e6} ok={bs1} (outbound_send lines {outbound})");
    println!("BS6 ok={bs6}");
    println!("BS8 ok={bs8}");
    println!("TLS ok={tls}");
    if !(bs1 && bs6 && bs8 && tls) {
        std::process::exit(1);
    }
}
