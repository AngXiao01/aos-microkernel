//! The root task (§B4): receives every Untyped capability at boot, starts the memory
//! server with a subset of them, starts the B-2 test client when the kernel tests boot it,
//! deletes everything else it holds, and exits. After that no process holds all of memory.
//!
//! x0 is the address of the kernel's `BootInfo` page.

#![no_std]
#![no_main]

use aos_rt::abi::{
    BOOT_INFO_MAGIC, BootInfo, CNODE_SLOTS, Error, ModuleInfo, ktest, ktest_b2, layout, method, object, rights,
    root_slots,
};
use aos_rt::cap::{configure, copy, delete, map, mint, move_cap, resume, retype, unmap, write_registers};
use aos_rt::println;

aos_rt::entry!(main);

/// Where the root task maps a frame it is filling.
const SCRATCH_VA: u64 = 0x0000_6000_0000_0000;
const PAGE: u64 = 4096;
/// In processes the root task builds: the slot of their own CNode, and where the
/// capabilities of their program, stack and IPC buffer frames go.
const CHILD_CNODE: u64 = 2;
/// The child's own thread capability: the root task's copy is deleted when it exits, and the
/// thread must not die with it.
const CHILD_THREAD: u64 = 3;
const CHILD_FRAMES: u64 = 64;
/// In the memory server: where its Untyped capabilities go.
const MEMORY_UNTYPED: u64 = 16;

fn boot_info(va: u64) -> &'static BootInfo {
    // SAFETY: the kernel maps the BootInfo page read-only at this address.
    unsafe { &*(va as *const BootInfo) }
}

fn module(info: &BootInfo, name: &str) -> Option<&'static [u8]> {
    let m: &ModuleInfo = info.modules[..info.module_count as usize]
        .iter()
        .find(|m| m.name.iter().take_while(|b| **b != 0).eq(name.as_bytes().iter()))?;
    // SAFETY: the kernel maps each module read-only at `va` for `len` bytes.
    Some(unsafe { core::slice::from_raw_parts(m.va as *const u8, m.len as usize) })
}

/// Free slots of the root CNode, handed out in order.
struct Slots {
    next: u64,
}

impl Slots {
    fn take(&mut self) -> Result<u64, Error> {
        if self.next >= CNODE_SLOTS {
            return Err(Error::NoMemory);
        }
        self.next += 1;
        Ok(self.next - 1)
    }
}

struct Child {
    thread: u64,
    cnode: u64,
    space: u64,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Builds a process from an ELF image with objects carved from `pool`: address space,
/// CNode, thread, program frames (each moved into the child's CNode, so the mappings
/// outlive the root task), stack and IPC buffer.
fn spawn(slots: &mut Slots, pool: u64, image: &[u8], priority: u64, args: [u64; 2]) -> Result<Child, Error> {
    let child = Child { space: slots.take()?, cnode: slots.take()?, thread: slots.take()? };
    retype(pool, object::ADDRESS_SPACE, child.space, 1)?;
    retype(pool, object::CNODE, child.cnode, 1)?;
    retype(pool, object::THREAD, child.thread, 1)?;
    copy(child.cnode, child.cnode, CHILD_CNODE, rights::ALL)?;
    let scratch = slots.take()?;
    let mut next_child_slot = CHILD_FRAMES;
    let mut place = |va: u64, rights: u64, bytes: &[u8], keep: bool| -> Result<(), Error> {
        retype(pool, object::FRAME, scratch, 1)?;
        if !bytes.is_empty() {
            map(root_slots::ADDRESS_SPACE, scratch, SCRATCH_VA, method::WRITE)?;
            // SAFETY: the frame was just mapped writable at SCRATCH_VA; `bytes` fits a page.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), SCRATCH_VA as *mut u8, bytes.len()) };
            unmap(scratch)?;
        }
        map(child.space, scratch, va, rights)?;
        if keep {
            return Ok(()); // the caller still needs it in the root CNode
        }
        move_cap(child.cnode, scratch, next_child_slot)?;
        next_child_slot += 1;
        Ok(())
    };

    if image.get(..4) != Some(b"\x7fELF") {
        return Err(Error::InvalidArgument);
    }
    let entry = u64_at(image, 24);
    let (phoff, phentsize, phnum) =
        (u64_at(image, 32) as usize, u16_at(image, 54) as usize, u16_at(image, 56) as usize);
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(image, ph) != 1 {
            continue; // not PT_LOAD
        }
        let flags = u32_at(image, ph + 4);
        let (offset, vaddr, filesz, memsz) =
            (u64_at(image, ph + 8), u64_at(image, ph + 16), u64_at(image, ph + 32), u64_at(image, ph + 40));
        let rights = if flags & 1 != 0 {
            method::EXECUTE
        } else if flags & 2 != 0 {
            method::WRITE
        } else {
            0
        };
        let first = vaddr & !(PAGE - 1);
        let mut page = first;
        while page < vaddr + memsz {
            // The part of the file image that falls into this page.
            let from = vaddr.max(page);
            let to = (vaddr + filesz).min(page + PAGE);
            let mut buf = [0u8; PAGE as usize];
            if from < to {
                let src = &image[(offset + from - vaddr) as usize..(offset + to - vaddr) as usize];
                buf[(from - page) as usize..(to - page) as usize].copy_from_slice(src);
            }
            place(page, rights, &buf, false)?;
            page += PAGE;
        }
    }
    let mut va = layout::STACK_TOP - layout::STACK_SIZE;
    while va < layout::STACK_TOP {
        place(va, method::WRITE, &[], false)?;
        va += PAGE;
    }
    place(layout::IPC_BUFFER, method::WRITE, &[], true)?;
    configure(child.thread, child.cnode, child.space, scratch, priority)?;
    write_registers(child.thread, entry, layout::STACK_TOP, args[0], args[1])?;
    move_cap(child.cnode, scratch, next_child_slot)?;
    Ok(child)
}

fn run(info: &BootInfo) -> Result<(), Error> {
    if info.magic != BOOT_INFO_MAGIC {
        return Err(Error::InvalidArgument);
    }
    let untyped = &info.untyped[..info.untyped_count as usize];
    // Build with the smallest Untyped of at least 2 MiB; everything else goes to the
    // memory server. What remains of the bootstrap pool is deleted with the root task.
    let (pool_index, _) = untyped
        .iter()
        .enumerate()
        .filter(|(_, u)| u.size_bits >= 21)
        .min_by_key(|(_, u)| u.size_bits)
        .ok_or(Error::NoMemory)?;
    let pool = root_slots::FIRST_UNTYPED + pool_index as u64;
    let mut slots = Slots { next: info.first_free_slot };

    let endpoint = slots.take()?;
    retype(pool, object::ENDPOINT, endpoint, 1)?;

    let given = untyped.len() as u64 - 1;
    let memory =
        spawn(&mut slots, pool, module(info, "memory").ok_or(Error::InvalidArgument)?, 150, [MEMORY_UNTYPED, given])?;
    copy(memory.cnode, endpoint, 1, rights::ALL)?;
    let others = untyped.iter().enumerate().filter(|(i, _)| *i != pool_index);
    for (dest, (i, _)) in (MEMORY_UNTYPED..).zip(others) {
        move_cap(memory.cnode, root_slots::FIRST_UNTYPED + i as u64, dest)?;
    }
    resume(memory.thread)?;
    move_cap(memory.cnode, memory.thread, CHILD_THREAD)?;

    // When the kernel tests boot us, they include a client for the memory server.
    if let Some(image) = module(info, "ktest-user") {
        let client = spawn(&mut slots, pool, image, 100, [ktest_b2::MEM_CLIENT, 0])?;
        mint(client.cnode, endpoint, ktest::SLOT_ENDPOINT, rights::SEND | rights::GRANT, 1)?;
        copy(client.cnode, client.space, ktest_b2::SLOT_SPACE, rights::ALL)?;
        resume(client.thread)?;
        move_cap(client.cnode, client.thread, CHILD_THREAD)?;
    }

    // Keep only our own thread, CNode and address space; then exit.
    for slot in 0..CNODE_SLOTS {
        if ![root_slots::THREAD, root_slots::CNODE, root_slots::ADDRESS_SPACE].contains(&slot) {
            delete(root_slots::CNODE, slot)?;
        }
    }
    Ok(())
}

fn main(info: u64, _: u64) -> u64 {
    match run(boot_info(info)) {
        Ok(()) => 0,
        Err(e) => {
            println!("root: setup failed: {e:?}");
            0x100 + e as u64
        }
    }
}
