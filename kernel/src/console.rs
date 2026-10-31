//! Kernel serial console.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::pl011::Pl011;
use crate::sync::SpinLock;

/// Virtual address of the console UART; 0 until `init`.
static BASE: AtomicUsize = AtomicUsize::new(0);
static LOCK: SpinLock<()> = SpinLock::new(());

/// Points the console at the PL011 mapped at `uart_va`.
pub fn init(uart_va: usize) {
    let _guard = LOCK.lock();
    // SAFETY: the caller maps a PL011 at `uart_va` for the lifetime of the kernel.
    unsafe { Pl011::new(uart_va) }.init();
    BASE.store(uart_va, Ordering::Release);
}

fn write(args: fmt::Arguments<'_>) {
    let base = BASE.load(Ordering::Acquire);
    if base != 0 {
        // SAFETY: `init` was given a mapped PL011 at `base`.
        let _ = unsafe { Pl011::new(base) }.write_fmt(args);
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let _guard = LOCK.lock();
    write(args);
}

/// Prints without taking the lock: the panicking code may hold it.
pub fn print_unlocked(args: fmt::Arguments<'_>) {
    write(args);
}

macro_rules! kprintln {
    () => { $crate::console::print(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::console::print(format_args!("{}\n", format_args!($($arg)*))) };
}
