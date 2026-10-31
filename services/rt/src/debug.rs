//! Debug output through the kernel console (`DEBUG_PUT`, debug kernels only).

use core::fmt::{self, Write};

use aos_abi::{DEBUG_BYTES, sys};

use crate::{ipc_buffer, syscall};

struct Console {
    len: usize,
}

impl Console {
    fn flush(&mut self) {
        if self.len > 0 {
            syscall(sys::DEBUG_PUT, [0, self.len as u64, 0, 0, 0, 0, 0]);
            self.len = 0;
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == DEBUG_BYTES {
                self.flush();
            }
            ipc_buffer().debug[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let mut c = Console { len: 0 };
    let _ = c.write_fmt(args);
    c.flush();
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { $crate::debug::print(format_args!("{}\n", format_args!($($arg)*))) };
}
