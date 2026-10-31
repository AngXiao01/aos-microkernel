//! ARM PL011 UART (ARM DDI 0183), transmit only: the kernel's debug log (§B3.1).

use core::fmt;
use core::ptr::{read_volatile, write_volatile};

const DR: usize = 0x00;
const FR: usize = 0x18;
const LCR_H: usize = 0x2c;
const CR: usize = 0x30;
const IMSC: usize = 0x38;
const ICR: usize = 0x44;

const FR_BUSY: u32 = 1 << 3;
const FR_TXFF: u32 = 1 << 5;
const LCR_H_FEN: u32 = 1 << 4;
const LCR_H_WLEN_8: u32 = 0b11 << 5;
const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;

pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// # Safety
    /// `base` must be the virtual address of a mapped PL011 register block.
    pub const unsafe fn new(base: usize) -> Pl011 {
        Pl011 { base }
    }

    fn read(&self, reg: usize) -> u32 {
        // SAFETY: `base` maps a PL011 (see `new`); `reg` is one of its registers.
        unsafe { read_volatile((self.base + reg) as *const u32) }
    }

    fn write(&self, reg: usize, value: u32) {
        // SAFETY: as for `read`.
        unsafe { write_volatile((self.base + reg) as *mut u32, value) }
    }

    /// 8N1 with FIFOs, transmitter enabled, interrupts masked. QEMU ignores the baud rate
    /// divisors, so they keep their reset values.
    pub fn init(&self) {
        self.write(CR, 0);
        while self.read(FR) & FR_BUSY != 0 {}
        self.write(LCR_H, LCR_H_WLEN_8 | LCR_H_FEN);
        self.write(IMSC, 0);
        self.write(ICR, 0x7ff);
        self.write(CR, CR_UARTEN | CR_TXE);
    }

    pub fn write_byte(&self, byte: u8) {
        while self.read(FR) & FR_TXFF != 0 {}
        self.write(DR, u32::from(byte));
    }
}

impl fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}
