//! AOS microkernel (SPEC part 2).
//!
//! B-0: boot on QEMU `virt` (aarch64), serial console, exception vectors, kernel page tables.
//! B-1: user threads and address spaces, preemptive scheduling, synchronous IPC.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
// Until the root task exists (B-2), much of the kernel is only exercised by the kernel
// tests; the ktest build still reports dead code.
#![cfg_attr(not(feature = "ktest"), allow(dead_code))]

#[macro_use]
mod console;
#[cfg(feature = "ktest")]
#[macro_use]
mod ktest;

mod arch;
mod cap;
#[cfg(feature = "ktest")]
mod cap_tests;
mod device;
mod elf;
mod fdt;
mod invoke;
mod ipc;
mod irq;
mod kobj;
mod mm;
mod pl011;
mod process;
mod root;
mod sched;
mod sync;
mod syscall;
mod thread;
#[cfg(feature = "ktest")]
mod user_tests;
mod vspace;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use mm::region::{Region, RegionList};

/// QEMU `virt` places the DTB at the start of RAM for bare-metal (non-Linux) ELF boots.
const QEMU_VIRT_DTB_PA: usize = 0x4000_0000;
/// QEMU `virt` PL011, used until the device tree has been read.
const QEMU_VIRT_UART_PA: usize = 0x0900_0000;

/// What boot discovered. The DTB stays reserved and mapped, so borrowed strings live forever.
pub struct BootInfo {
    pub platform: fdt::Platform<'static>,
    /// Physical range of the DTB.
    pub dtb: Region,
    /// Exception level the kernel was entered at.
    pub entry_el: u64,
}

static BOOT_INFO: sync::SetOnce<BootInfo> = sync::SetOnce::new();

macro_rules! service {
    ($name:literal) => {
        root::Module { name: $name, image: include_bytes!(concat!(env!("AOS_SERVICES_DIR"), "/", $name)) }
    };
}

/// The programs the root task receives (built from services/ by build.rs).
#[cfg(not(feature = "ktest"))]
pub static BOOT_MODULES: [root::Module; 9] = [
    service!("root"),
    service!("memory"),
    service!("blk"),
    service!("hostlink"),
    service!("storage"),
    service!("net"),
    service!("netstack"),
    service!("egress"),
    service!("view"),
];

/// The kernel tests also carry the user-space test program. Device servers start only when
/// the machine actually has those devices.
#[cfg(feature = "ktest")]
pub static BOOT_MODULES: [root::Module; 10] = [
    service!("root"),
    service!("memory"),
    service!("blk"),
    service!("hostlink"),
    service!("storage"),
    service!("net"),
    service!("netstack"),
    service!("egress"),
    service!("view"),
    service!("ktest-user"),
];

fn read_mmio(pa: usize) -> u32 {
    // SAFETY: `pa` is a virtio-mmio register in the boot map (this runs before `mm::init`
    // replaces it). The read has no side effect: magic and device id are pure.
    unsafe { (mm::phys_to_virt(pa) as *const u32).read_volatile() }
}

pub fn boot_info() -> &'static BootInfo {
    BOOT_INFO.get().expect("boot info not recorded yet")
}

#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb_pa: usize) -> ! {
    console::init(mm::phys_to_virt(QEMU_VIRT_UART_PA));
    let entry_el = arch::boot::entry_el();
    kprintln!(
        "AOS microkernel {} (entered at EL{entry_el}, running at EL{})",
        env!("CARGO_PKG_VERSION"),
        arch::cpu::current_el()
    );

    let dtb_pa = if dtb_pa == 0 { QEMU_VIRT_DTB_PA } else { dtb_pa };
    // SAFETY: the boot map covers PA [1 GiB, 4 GiB), where QEMU places the DTB; the DTB is
    // reserved below and never written, so it outlives the kernel.
    let fdt = unsafe { fdt::Fdt::from_ptr(mm::phys_to_virt(dtb_pa) as *const u8) }
        .unwrap_or_else(|e| panic!("no usable device tree at {dtb_pa:#x}: {e:?}"));
    let platform = fdt::Platform::discover(&fdt).unwrap_or_else(|e| panic!("device tree: {e:?}"));
    // The boot map still covers MMIO here. Only transports with a real virtio device are
    // published; empty virtio-mmio slots (device id 0) are ignored.
    let mut found = [device::BootDev { kind: 0, base: 0, irq: 0 }; device::MAX];
    let mut nfound = 0;
    for node in platform.virtio.iter().take(platform.virtio_count) {
        if nfound == device::MAX {
            break;
        }
        let magic = read_mmio(node.base);
        let id = read_mmio(node.base + 8);
        // 1 = net, 2 = blk, 3 = console. Empty transports report id 0.
        if magic == 0x7472_6976 && (id == 1 || id == 2 || id == 3) {
            found[nfound] = device::BootDev { kind: id, base: node.base, irq: node.irq };
            kprintln!("virtio: id {id} at {:#x} irq {}", node.base, node.irq);
            nfound += 1;
        }
    }
    device::publish(&found[..nfound]);
    let uart_pa = platform.uart.unwrap_or_else(|| panic!("device tree has no arm,pl011 UART"));
    if uart_pa != QEMU_VIRT_UART_PA {
        console::init(mm::phys_to_virt(uart_pa));
    }
    for r in platform.memory.as_slice() {
        kprintln!("  ram {:#011x}..{:#011x} ({} MiB)", r.start, r.end, r.len() >> 20);
    }

    let dtb = Region::new(dtb_pa, dtb_pa + fdt.total_size());
    let mut reserved: RegionList<9> = RegionList::new();
    let rsvmap = fdt.reservations().unwrap_or_else(|e| panic!("device tree reservations: {e:?}"));
    for r in core::iter::once(&dtb).chain(rsvmap.as_slice()) {
        reserved.push(*r).unwrap_or_else(|_| unreachable!("capacity covers the DTB and 8 reservations"));
    }
    let (gicd, gicc) = platform.gic.unwrap_or_else(|| panic!("device tree has no GICv2"));
    let devices = [Region::new(uart_pa, uart_pa + 0x1000), gicd, gicc];
    let stats = mm::init(&platform, reserved.as_slice(), &devices).unwrap_or_else(|e| panic!("mm: {e}"));
    kprintln!(
        "mm: kernel address space active ({} KiB of page tables, {} MiB free)",
        stats.table_frames * 4,
        stats.free_bytes >> 20
    );

    // SAFETY: both regions were just mapped as device memory.
    unsafe { irq::init(mm::phys_to_virt(gicd.start), mm::phys_to_virt(gicc.start)) };
    kprintln!("irq: GICv2, {} Hz tick, counter at {} MHz", irq::TICK_HZ, arch::timer::frequency() / 1_000_000);

    if BOOT_INFO.set(BootInfo { platform, dtb, entry_el }).is_err() {
        unreachable!("kernel_main runs once");
    }

    #[cfg(feature = "ktest")]
    ktest::run_all();

    #[cfg(not(feature = "ktest"))]
    {
        let mut k = sched::KERNEL.lock();
        root::start(&mut k, &BOOT_MODULES).unwrap_or_else(|e| panic!("root task: {e:?}"));
        k.run_until(|_| false, u64::MAX);
        arch::cpu::halt()
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if PANICKING.swap(true, Ordering::Relaxed) {
        arch::cpu::halt(); // panicked while panicking
    }
    console::print_unlocked(format_args!("\n*** KERNEL PANIC: {info}\n"));
    #[cfg(feature = "ktest")]
    arch::semihosting::exit(101);
    #[cfg(not(feature = "ktest"))]
    arch::cpu::halt()
}
