//! virtio-mmio devices discovered at boot and handed to the root task as capabilities.
//!
//! The kernel does not drive them (§B3.2). It only remembers which transports have a real
//! device behind them so the root task can pass MMIO and IRQ to a user driver.

use crate::sync::SetOnce;

pub const MAX: usize = 4;

#[derive(Clone, Copy, Debug)]
pub struct BootDev {
    /// virtio device id (2 = block, 3 = console).
    pub kind: u32,
    pub base: usize,
    pub irq: u32,
}

struct Table {
    count: usize,
    devs: [BootDev; MAX],
}

static TABLE: SetOnce<Table> = SetOnce::new();

pub fn publish(devs: &[BootDev]) {
    let mut table = Table { count: devs.len().min(MAX), devs: [BootDev { kind: 0, base: 0, irq: 0 }; MAX] };
    table.devs[..table.count].copy_from_slice(&devs[..table.count]);
    let _ = TABLE.set(table);
}

pub fn all() -> &'static [BootDev] {
    match TABLE.get() {
        Some(t) => &t.devs[..t.count],
        None => &[],
    }
}
