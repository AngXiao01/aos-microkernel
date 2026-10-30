//! Minimal flattened device tree reader (Devicetree Specification v0.4, chapter 5): enough
//! to find RAM, the memory reservation block, the PL011 UART and `/chosen/bootargs`.
//! Every access is bounds-checked; nothing is allocated.

use crate::mm::region::{Region, RegionList};

const MAGIC: u32 = 0xd00d_feed;
const HEADER_LEN: usize = 40;
/// Larger blobs are rejected; QEMU's `virt` DTB is about 1 MiB at most.
pub const MAX_TOTAL_SIZE: usize = 2 << 20;

const TOKEN_BEGIN_NODE: u32 = 1;
const TOKEN_END_NODE: u32 = 2;
const TOKEN_PROP: u32 = 3;
const TOKEN_NOP: u32 = 4;
const TOKEN_END: u32 = 9;

const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdtError {
    BadMagic,
    BadVersion,
    Truncated,
    Malformed,
    TooManyRegions,
}

pub struct Fdt<'a> {
    blob: &'a [u8],
    structs: &'a [u8],
    strings: &'a [u8],
    rsvmap: &'a [u8],
}

fn be32(bytes: &[u8], off: usize) -> Result<u32, FdtError> {
    let b = bytes.get(off..off.checked_add(4).ok_or(FdtError::Truncated)?).ok_or(FdtError::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn be64(bytes: &[u8], off: usize) -> Result<u64, FdtError> {
    Ok((u64::from(be32(bytes, off)?) << 32) | u64::from(be32(bytes, off + 4)?))
}

fn slice(bytes: &[u8], off: u32, len: u32) -> Result<&[u8], FdtError> {
    let (off, len) = (off as usize, len as usize);
    bytes.get(off..off.checked_add(len).ok_or(FdtError::Truncated)?).ok_or(FdtError::Truncated)
}

/// The NUL-terminated string at the start of `bytes`, without the NUL.
fn cstr(bytes: &[u8]) -> Result<&[u8], FdtError> {
    let len = bytes.iter().position(|&b| b == 0).ok_or(FdtError::Malformed)?;
    Ok(&bytes[..len])
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub enum Event<'a> {
    BeginNode(&'a [u8]),
    Property(&'a [u8], &'a [u8]),
    EndNode,
}

impl<'a> Fdt<'a> {
    /// `blob` may extend past the tree; only the header's `totalsize` bytes are used.
    pub fn new(blob: &'a [u8]) -> Result<Fdt<'a>, FdtError> {
        if blob.len() < HEADER_LEN {
            return Err(FdtError::Truncated);
        }
        if be32(blob, 0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = be32(blob, 4)? as usize;
        if !(HEADER_LEN..=MAX_TOTAL_SIZE).contains(&total) || total > blob.len() {
            return Err(FdtError::Truncated);
        }
        let blob = &blob[..total];
        // Version 17 added size_dt_struct; anything still compatible with 16 parses the same.
        if be32(blob, 20)? < 17 || be32(blob, 24)? > 16 {
            return Err(FdtError::BadVersion);
        }
        let structs = slice(blob, be32(blob, 8)?, be32(blob, 36)?)?;
        let strings = slice(blob, be32(blob, 12)?, be32(blob, 32)?)?;
        let rsv_off = be32(blob, 16)? as usize;
        let rsvmap = blob.get(rsv_off..).ok_or(FdtError::Truncated)?;
        Ok(Fdt { blob, structs, strings, rsvmap })
    }

    /// # Safety
    /// `ptr` must point to readable memory holding a device tree that stays valid and
    /// unmodified for `'a`, or to at least `HEADER_LEN` readable bytes.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Fdt<'a>, FdtError> {
        // SAFETY: the header is readable (caller); `totalsize` bounds the rest.
        let header = unsafe { core::slice::from_raw_parts(ptr, HEADER_LEN) };
        if be32(header, 0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = (be32(header, 4)? as usize).min(MAX_TOTAL_SIZE);
        // SAFETY: the caller guarantees the whole tree is readable.
        Fdt::new(unsafe { core::slice::from_raw_parts(ptr, total) })
    }

    pub fn total_size(&self) -> usize {
        self.blob.len()
    }

    /// Entries of the memory reservation block.
    pub fn reservations(&self) -> Result<RegionList<8>, FdtError> {
        let mut out = RegionList::new();
        for i in 0.. {
            let (addr, size) = (be64(self.rsvmap, i * 16)?, be64(self.rsvmap, i * 16 + 8)?);
            if addr == 0 && size == 0 {
                break;
            }
            out.push(Region::new(addr as usize, (addr + size) as usize)).map_err(|_| FdtError::TooManyRegions)?;
        }
        Ok(out)
    }

    /// Calls `f` for every node and property in document order.
    pub fn walk(&self, mut f: impl FnMut(Event<'a>) -> Result<(), FdtError>) -> Result<(), FdtError> {
        let s = self.structs;
        let mut off = 0;
        let mut depth = 0usize;
        loop {
            let token = be32(s, off)?;
            off += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    let name = cstr(s.get(off..).ok_or(FdtError::Truncated)?)?;
                    off = align4(off + name.len() + 1);
                    depth += 1;
                    f(Event::BeginNode(name))?;
                }
                TOKEN_END_NODE => {
                    depth = depth.checked_sub(1).ok_or(FdtError::Malformed)?;
                    f(Event::EndNode)?;
                }
                TOKEN_PROP => {
                    let len = be32(s, off)?;
                    let name_off = be32(s, off + 4)? as usize;
                    let value = slice(s, (off + 8) as u32, len)?;
                    off = align4(off + 8 + len as usize);
                    let name = cstr(self.strings.get(name_off..).ok_or(FdtError::Truncated)?)?;
                    if depth == 0 {
                        return Err(FdtError::Malformed);
                    }
                    f(Event::Property(name, value))?;
                }
                TOKEN_NOP => {}
                TOKEN_END => return if depth == 0 { Ok(()) } else { Err(FdtError::Malformed) },
                _ => return Err(FdtError::Malformed),
            }
        }
    }
}

/// What the kernel needs from the device tree.
pub struct Platform<'a> {
    pub memory: RegionList<8>,
    /// PL011 MMIO base (physical).
    pub uart: Option<usize>,
    pub bootargs: Option<&'a str>,
}

#[derive(Default)]
struct NodeScan<'a> {
    depth: usize,
    name: &'a [u8],
    device_type_memory: bool,
    pl011: bool,
    reg: Option<&'a [u8]>,
}

impl<'a> Platform<'a> {
    pub fn discover(fdt: &Fdt<'a>) -> Result<Platform<'a>, FdtError> {
        let mut out = Platform { memory: RegionList::new(), uart: None, bootargs: None };
        // cells[d] = (#address-cells, #size-cells) declared by the open node at depth d for
        // its children; DTSpec defaults are 2 and 1.
        let mut cells = [(2u32, 1u32); MAX_DEPTH];
        let mut depth = 0usize;
        // Properties precede subnodes, so a node is complete at its first child or its end.
        let mut pending: Option<NodeScan<'a>> = None;
        fdt.walk(|event| {
            match event {
                Event::BeginNode(name) => {
                    if let Some(node) = pending.take() {
                        out.finish(node, &cells)?;
                    }
                    if depth == MAX_DEPTH {
                        return Err(FdtError::Malformed);
                    }
                    cells[depth] = (2, 1);
                    pending = Some(NodeScan { depth, name, ..NodeScan::default() });
                    depth += 1;
                }
                Event::Property(name, value) => {
                    let node = pending.as_mut().ok_or(FdtError::Malformed)?;
                    match name {
                        b"#address-cells" => cells[node.depth].0 = be32(value, 0)?,
                        b"#size-cells" => cells[node.depth].1 = be32(value, 0)?,
                        b"device_type" => node.device_type_memory = value == b"memory\0",
                        b"compatible" => node.pl011 = value.split(|&b| b == 0).any(|c| c == b"arm,pl011"),
                        b"reg" => node.reg = Some(value),
                        b"bootargs" if node.depth == 1 && node.name == b"chosen" => {
                            let text = cstr(value)?;
                            out.bootargs = Some(core::str::from_utf8(text).map_err(|_| FdtError::Malformed)?);
                        }
                        _ => {}
                    }
                }
                Event::EndNode => {
                    if let Some(node) = pending.take() {
                        out.finish(node, &cells)?;
                    }
                    depth -= 1;
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    fn finish(&mut self, node: NodeScan<'a>, cells: &[(u32, u32); MAX_DEPTH]) -> Result<(), FdtError> {
        let (Some(reg), Some(parent)) = (node.reg, node.depth.checked_sub(1)) else {
            return Ok(());
        };
        let (addr_cells, size_cells) = cells[parent];
        if !(1..=2).contains(&addr_cells) || size_cells > 2 {
            return Err(FdtError::Malformed);
        }
        let entry = 4 * (addr_cells + size_cells) as usize;
        if reg.len() % entry != 0 {
            return Err(FdtError::Malformed);
        }
        let read = |off: usize, n: u32| -> Result<u64, FdtError> {
            if n == 2 {
                be64(reg, off)
            } else if n == 1 {
                be32(reg, off).map(u64::from)
            } else {
                Ok(0)
            }
        };
        for off in (0..reg.len()).step_by(entry) {
            let addr = read(off, addr_cells)?;
            let size = read(off + 4 * addr_cells as usize, size_cells)?;
            if node.device_type_memory {
                let end = addr.checked_add(size).ok_or(FdtError::Malformed)?;
                self.memory.push(Region::new(addr as usize, end as usize)).map_err(|_| FdtError::TooManyRegions)?;
            } else if node.pl011 && self.uart.is_none() {
                self.uart = Some(addr as usize);
            }
        }
        Ok(())
    }

    /// The value of `key=value` in the kernel command line (`/chosen/bootargs`).
    pub fn bootarg(&self, key: &str) -> Option<&'a str> {
        self.bootargs?.split_ascii_whitespace().find_map(|arg| arg.strip_prefix(key)?.strip_prefix('='))
    }
}

#[cfg(feature = "ktest")]
mod tests {
    use super::*;

    /// A minimal tree: / { #address-cells = <1>; #size-cells = <1>;
    /// memory@1000 { device_type = "memory"; reg = <0x1000 0x2000>; }; }
    fn tiny_tree(buf: &mut [u8; 256]) -> usize {
        let mut structs = [0u8; 160];
        let mut s = 0;
        let mut put = |v: &[u8], s: &mut usize| {
            structs[*s..*s + v.len()].copy_from_slice(v);
            *s = align4(*s + v.len());
        };
        let strings = b"#address-cells\0#size-cells\0device_type\0reg\0";
        let prop = |len: u32, name_off: u32| {
            let mut p = [0u8; 12];
            p[0..4].copy_from_slice(&TOKEN_PROP.to_be_bytes());
            p[4..8].copy_from_slice(&len.to_be_bytes());
            p[8..12].copy_from_slice(&name_off.to_be_bytes());
            p
        };
        put(&TOKEN_BEGIN_NODE.to_be_bytes(), &mut s);
        put(&[0, 0, 0, 0], &mut s); // empty root name
        put(&prop(4, 0), &mut s);
        put(&1u32.to_be_bytes(), &mut s);
        put(&prop(4, 15), &mut s);
        put(&1u32.to_be_bytes(), &mut s);
        put(&TOKEN_BEGIN_NODE.to_be_bytes(), &mut s);
        put(b"memory@1000\0", &mut s);
        put(&prop(7, 27), &mut s);
        put(b"memory\0", &mut s);
        put(&prop(8, 39), &mut s);
        put(&[0, 0, 0x10, 0, 0, 0, 0x20, 0], &mut s);
        put(&TOKEN_END_NODE.to_be_bytes(), &mut s);
        put(&TOKEN_END_NODE.to_be_bytes(), &mut s);
        put(&TOKEN_END.to_be_bytes(), &mut s);

        let rsv = HEADER_LEN;
        let st = rsv + 16;
        let strs = st + s;
        let total = strs + strings.len();
        buf.fill(0);
        let header =
            [MAGIC, total as u32, st as u32, strs as u32, rsv as u32, 17, 16, 0, strings.len() as u32, s as u32];
        for (i, v) in header.iter().enumerate() {
            buf[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        buf[st..st + s].copy_from_slice(&structs[..s]);
        buf[strs..total].copy_from_slice(strings);
        total
    }

    ktest! {
        fn finds_the_qemu_virt_devices() {
            let p = &crate::boot_info().platform;
            kassert_eq!(p.uart, Some(0x0900_0000));
            kassert_eq!(p.memory.as_slice().len(), 1);
            kassert_eq!(p.memory.as_slice()[0].start, 0x4000_0000);
            let mib: usize = kunwrap!(p.bootarg("aos.test.mem_mib").ok_or("no aos.test.mem_mib bootarg").and_then(|v| v.parse().map_err(|_| "bad number")));
            kassert_eq!(p.memory.total(), mib << 20);
        }

        fn entry_el_matches_the_qemu_configuration() {
            let p = &crate::boot_info().platform;
            let expected = kunwrap!(p.bootarg("aos.test.entry_el").ok_or("no aos.test.entry_el bootarg"));
            kassert_eq!(crate::boot_info().entry_el, if expected == "2" { 2 } else { 1 });
            kassert_eq!(crate::arch::cpu::current_el(), 1);
        }

        fn parses_a_hand_built_tree() {
            let mut buf = [0u8; 256];
            let len = tiny_tree(&mut buf);
            let fdt = kunwrap!(Fdt::new(&buf[..len]));
            kassert_eq!(kunwrap!(fdt.reservations()).as_slice().len(), 0);
            let p = kunwrap!(Platform::discover(&fdt));
            kassert_eq!(p.memory.as_slice(), &[Region::new(0x1000, 0x3000)]);
            kassert_eq!(p.uart, None);
        }

        fn rejects_malformed_trees() {
            let mut buf = [0u8; 256];
            let len = tiny_tree(&mut buf);
            kassert_eq!(Fdt::new(&buf[..HEADER_LEN - 1]).err(), Some(FdtError::Truncated));
            kassert_eq!(Fdt::new(&buf[..len - 1]).err(), Some(FdtError::Truncated));

            let mut bad = buf;
            bad[0] ^= 1;
            kassert_eq!(Fdt::new(&bad[..len]).err(), Some(FdtError::BadMagic));

            let mut bad = buf;
            bad[23] = 16; // version 16
            kassert_eq!(Fdt::new(&bad[..len]).err(), Some(FdtError::BadVersion));

            let mut bad = buf;
            let st = HEADER_LEN + 16;
            bad[st + 3] = 7; // unknown first token
            let fdt = kunwrap!(Fdt::new(&bad[..len]));
            kassert_eq!(Platform::discover(&fdt).err(), Some(FdtError::Malformed));

            let mut bad = buf;
            let end_token = st + 4 * 26; // turn the final END into a NOP: the walk must not run off the block
            kassert_eq!(be32(&bad, end_token), Ok(TOKEN_END));
            bad[end_token + 3] = TOKEN_NOP as u8;
            let fdt = kunwrap!(Fdt::new(&bad[..len]));
            kassert_eq!(Platform::discover(&fdt).err(), Some(FdtError::Truncated));
        }
    }
}
