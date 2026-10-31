//! B-3 acceptance: the conformance checks for the log, transactions, branches and undo,
//! speaking to the in-guest storage server over virtio-console, plus BS4 and BS5.

mod guest;
mod remote;
mod suite;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

use aos_branch::Store;
use aos_conformance::TestEnv;
use aos_log::{Log, LogStorage, MemStorage};
use aos_storage::wire;
use aos_types::cbor::Cbor;

use crate::guest::Guest;
use crate::remote::Remote;

fn kernel_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kernel/target/aarch64-unknown-none-softfloat/release/aos-kernel")
}

struct Boot {
    dir: PathBuf,
    disk: PathBuf,
}

impl Boot {
    fn new() -> Boot {
        let dir = env::temp_dir().join(format!("aos-b3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let disk = dir.join("disk.img");
        fs::write(&disk, vec![0u8; 64 * 1024 * 1024]).unwrap();
        Boot { dir, disk }
    }

    fn launch(&self, name: &str) -> Guest {
        let serial = self.dir.join(format!("{name}.log"));
        let sock = self.dir.join(format!("{name}.sock"));
        let mut guest = Guest::launch(&kernel_path(), &self.disk, &serial, &sock);
        guest.wait_serial(&["storage: ready", "read-only safe mode"], Duration::from_secs(30));
        guest
    }
}

fn open_store(sock: &Path) -> Store<Remote, TestEnv> {
    let remote = Remote::connect(sock);
    let stat = remote.stat();
    assert_eq!(stat.fault, 0, "volume is not healthy: {stat:?}");
    assert!(!stat.read_only);
    Store::open(remote, TestEnv::new(7), None).unwrap_or_else(|e| panic!("replay failed: {e:?}"))
}

fn durability(boot: &Boot, entries: &[Vec<u8>]) {
    let mut guest = boot.launch("durability");
    let remote = Remote::connect(&guest.sock);
    assert_eq!(remote.entries(), entries, "log bytes changed across a reboot");
    remote.shutdown();
    guest.power_off();
    println!("durability: {} entries survived reboot", entries.len());
}

fn bs5(boot: &Boot) {
    let mut guest = boot.launch("bs5");
    let mut remote = Remote::connect(&guest.sock);
    let stat = remote.stat();
    assert_eq!(stat.fault, 0, "{stat:?}");
    let before = stat.entries;
    let anchor = stat.anchor;
    let mut mem = MemStorage::new();
    for entry in remote.entries() {
        LogStorage::append(&mut mem, entry).unwrap();
    }
    let mut log = Log::open(mem, None, |_| Ok::<(), ()>(())).unwrap();
    let extra = log.append(Cbor::text("bs5-uncommitted")).unwrap().encode();
    // Flush the segment, then stop before the superblock. SIGKILL is the power cut.
    remote.arm_halt();
    let status = remote.append_raw(&extra);
    assert_eq!(status, wire::ST_WILL_HALT, "guest did not stop before the superblock (status {status})");
    guest.power_off();

    let mut guest = boot.launch("bs5-back");
    let remote = Remote::connect(&guest.sock);
    let stat = remote.stat();
    assert_eq!(stat.fault, 0, "power cut looked like corruption: {stat:?}");
    assert!(!stat.read_only);
    assert_eq!(stat.entries, before, "uncommitted append became visible");
    assert_eq!(stat.anchor, anchor, "anchor moved without a commit");
    let store = Store::open(remote, TestEnv::new(1), None).unwrap_or_else(|e| panic!("replay: {e:?}"));
    assert_eq!(store.log().len(), before);
    println!("BS5: power-off dropped the uncommitted entry; log len {before}, fault 0");
    store.log().storage().shutdown();
    guest.power_off();
}

fn bs4(boot: &Boot) {
    let mut guest = boot.launch("bs4-seed");
    let store = open_store(&guest.sock);
    assert!(!store.log().is_empty(), "BS4 needs a committed log");
    store.log().storage().shutdown();
    guest.power_off();

    let mut image = fs::read(&boot.disk).unwrap();
    let at = aos_storage::tamper_log_payload(&mut image).expect("tamper");
    fs::write(&boot.disk, &image).unwrap();
    println!("BS4: flipped disk byte at {at:#x}");

    let mut guest = boot.launch("bs4");
    let log = guest.serial_so_far();
    assert!(log.contains("hash chain broken"), "serial did not report a broken hash chain:\n{log}");
    assert!(log.contains("read-only safe mode"), "serial did not report read-only safe mode:\n{log}");
    let remote = Remote::connect(&guest.sock);
    let stat = remote.stat();
    assert_eq!(stat.fault, 1, "expected HashMismatch (1), got {stat:?}");
    assert!(stat.read_only, "volume stayed writable after tamper: {stat:?}");
    // A further append must be refused. Any bytes will do; the server rejects before linking.
    let mut remote = remote;
    let status = remote.append_raw(b"nope");
    assert_eq!(status, wire::ST_READ_ONLY, "append after tamper returned {status}");
    println!("BS4: hash chain broken at seq {}, read-only safe mode, append refused", stat.fault_seq);
    guest.power_off();
}

fn main() {
    let kernel = kernel_path();
    if !kernel.exists() {
        eprintln!("kernel not built: {}", kernel.display());
        eprintln!("build it with: cd kernel && cargo build --release --features debug-syscalls");
        exit(1);
    }
    let boot = Boot::new();
    println!("disk {}", boot.disk.display());

    let mut guest = boot.launch("suite");
    let mut store = open_store(&guest.sock);
    suite::run(&mut store);
    let entries: Vec<Vec<u8>> = (0..store.log().len()).map(|i| store.log().read(i).unwrap().encode()).collect();
    println!("suite: {} log entries, replay checks passed", entries.len());
    store.log().storage().shutdown();
    guest.power_off();
    drop(store);
    drop(guest);

    durability(&boot, &entries);
    bs5(&boot);
    bs4(&boot);
    println!("B-3 platform checks passed");
}
