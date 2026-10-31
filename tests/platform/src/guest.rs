//! Boots the kernel in QEMU with a virtio-blk disk and a virtio-console socket.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct Guest {
    child: Child,
    pub serial: PathBuf,
    pub sock: PathBuf,
}

impl Guest {
    pub fn launch(kernel: &Path, disk: &Path, serial: &Path, sock: &Path) -> Guest {
        let _ = fs::remove_file(sock);
        let _ = fs::remove_file(serial);
        let child = Command::new("qemu-system-aarch64")
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
            .arg(kernel)
            .args(["-drive", &format!("file={},if=none,format=raw,id=hd,cache=writethrough", disk.display())])
            .args(["-device", "virtio-blk-device,drive=hd"])
            .arg("-chardev")
            .arg(format!("socket,id=host,path={},server=on,wait=off", sock.display()))
            .args(["-device", "virtio-serial-device", "-device", "virtconsole,chardev=host"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn qemu");
        Guest { child, serial: serial.to_path_buf(), sock: sock.to_path_buf() }
    }

    /// Blocks until any of `needles` appears in the serial log.
    pub fn wait_serial(&mut self, needles: &[&str], timeout: Duration) -> String {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let all = self.serial_so_far();
            if needles.iter().any(|n| all.contains(n)) {
                return all;
            }
            if let Some(status) = self.child.try_wait().ok().flatten() {
                panic!("qemu exited ({status}) before {needles:?}:\n{}", self.serial_so_far());
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {needles:?}:\n{}", self.serial_so_far());
    }

    pub fn serial_so_far(&self) -> String {
        fs::read_to_string(&self.serial).unwrap_or_default()
    }

    /// Power off. `Child::kill` is SIGKILL, which drops the guest without a shutdown.
    pub fn power_off(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
