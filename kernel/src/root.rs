//! Starting the root task (§B4): it receives the boot modules, a `BootInfo` page, its own
//! thread, capability space and address space, and every byte of free memory as Untyped.
//! Its job is to hand these out according to the capability table and then exit.

use aos_abi::{
    BOOT_INFO_MAGIC, BootInfo, DeviceInfo, MAX_MODULES, MAX_UNTYPED, ModuleInfo, UntypedInfo, layout, root_slots,
};

use crate::cap::{self, Cap};
use crate::kobj::KPtr;
use crate::mm::paging::{Attrs, PAGE_SIZE};
use crate::mm::region::align_up;
use crate::mm::{self, phys_to_virt};
use crate::process::{self, SpawnError};
use crate::sched::Kernel;
use crate::thread::Thread;

pub const ROOT_PRIORITY: u8 = 200;
/// Translation tables for what the root task maps into itself after boot.
const ROOT_TABLE_POOL: usize = 256 * 1024;

pub struct Module {
    pub name: &'static str,
    pub image: &'static [u8],
}

/// Builds the root task from module "root", gives it everything, and makes it runnable.
/// After this the kernel allocates nothing more: the boot allocator is sealed.
pub fn start(k: &mut Kernel, modules: &[Module]) -> Result<KPtr<Thread>, SpawnError> {
    let image = modules.iter().find(|m| m.name == "root").ok_or(SpawnError::OutOfMemory)?.image;
    let p = process::build(k, image, ROOT_PRIORITY, [layout::BOOT_INFO, 0])?;
    // SAFETY: the address space was just built; no other reference exists.
    let space = unsafe { p.space.get() };

    // SAFETY: a zeroed frame is a valid BootInfo; it is written only here.
    let info_pa = space.map_new(layout::BOOT_INFO, Attrs::USER_RO)?;
    let info = unsafe { &mut *(phys_to_virt(info_pa) as *mut BootInfo) };
    info.magic = BOOT_INFO_MAGIC;

    let mut va = layout::MODULES;
    for (i, m) in modules.iter().take(MAX_MODULES).enumerate() {
        for (n, chunk) in m.image.chunks(PAGE_SIZE).enumerate() {
            let pa = space.map_new(va + (n * PAGE_SIZE) as u64, Attrs::USER_RO)?;
            // SAFETY: a fresh frame in the linear map; the chunk is at most a page.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_to_virt(pa) as *mut u8, chunk.len()) };
        }
        let mut name = [0u8; 16];
        let len = m.name.len().min(16);
        name[..len].copy_from_slice(&m.name.as_bytes()[..len]);
        info.modules[i] = ModuleInfo { name, va, len: m.image.len() as u64 };
        info.module_count = i as u64 + 1;
        va = align_up((va as usize) + m.image.len(), 1 << 21) as u64;
    }

    // SAFETY: the CNode was just built; no other reference exists.
    let cnode = unsafe { p.cnode.get() };
    let slot = |cnode: &mut crate::cap::CNode, i: u64| cnode.slot(i).expect("root slot in range");
    cap::insert(slot(cnode, root_slots::THREAD), Cap::Thread(p.thread), None);
    cap::insert(slot(cnode, root_slots::CNODE), Cap::CNode(p.cnode), None);
    cap::insert(slot(cnode, root_slots::ADDRESS_SPACE), Cap::AddressSpace(p.space), None);
    #[cfg(feature = "debug-syscalls")]
    cap::insert(slot(cnode, root_slots::DEBUG), Cap::Debug, None);

    let pool = mm::with_frames(|f| f.alloc_region(ROOT_TABLE_POOL, PAGE_SIZE)).ok_or(SpawnError::OutOfMemory)?;
    space.attach_pool(pool, ROOT_TABLE_POOL);

    // Everything still free becomes Untyped, in naturally aligned power-of-two blocks.
    let free = mm::with_frames(|f| f.seal());
    let mut next = root_slots::FIRST_UNTYPED;
    for r in free.as_slice() {
        let mut base = r.start;
        while base < r.end && (info.untyped_count as usize) < MAX_UNTYPED {
            let bits = (base.trailing_zeros()).min(usize::BITS - 1 - (r.end - base).leading_zeros());
            cap::insert(slot(cnode, next), Cap::Untyped { base, size_bits: bits as u8, free: 0 }, None);
            info.untyped[info.untyped_count as usize] = UntypedInfo { base: base as u64, size_bits: u64::from(bits) };
            info.untyped_count += 1;
            next += 1;
            base += 1 << bits;
        }
    }
    info.first_free_slot = next;
    for (i, dev) in crate::device::all().iter().enumerate() {
        let mmio = root_slots::FIRST_DEVICE + (i as u64) * 2;
        let irq = mmio + 1;
        // virtio-mmio windows are 0x200 bytes and often not page-aligned. The capability
        // names the page that contains the window; the driver adds `base & 0xfff`.
        cap::insert(slot(cnode, mmio), Cap::Device { pa: dev.base & !0xfff, mapped: None }, None);
        cap::insert(slot(cnode, irq), Cap::Irq { index: i as u8 }, None);
        crate::irq::register(i, dev.irq);
        info.devices[i] = DeviceInfo {
            kind: u64::from(dev.kind),
            base: dev.base as u64,
            irq: u64::from(dev.irq),
            mmio_slot: mmio,
            irq_slot: irq,
        };
        info.device_count = i as u64 + 1;
    }
    kprintln!(
        "root: {} modules, {} untyped ({} MiB), {} devices",
        info.module_count,
        info.untyped_count,
        info.untyped[..info.untyped_count as usize].iter().map(|u| 1u64 << u.size_bits).sum::<u64>() >> 20,
        info.device_count
    );
    k.make_ready(p.thread);
    Ok(p.thread)
}
