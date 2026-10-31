//! System call dispatch (ABI in `aos-abi`). A call either completes at once, with its
//! status in x0, or blocks the thread; the status is then set by whoever wakes it.

use aos_abi::{Error, sys};

use crate::ipc;
use crate::kobj::KPtr;
use crate::sched::Kernel;
use crate::thread::{Exit, Thread};

pub fn handle(k: &mut Kernel, t: KPtr<Thread>) {
    k.stats.syscalls += 1;
    // SAFETY: the reference ends here; the handlers take their own.
    let (number, x0) = {
        let th = unsafe { t.get() };
        (th.ctx.x[7], th.ctx.x[0])
    };
    let status = |e: Error| {
        // SAFETY: as above.
        unsafe { t.get() }.set_status(e)
    };
    match number {
        sys::CALL => ipc::send(k, t, true),
        sys::SEND => ipc::send(k, t, false),
        sys::RECV => ipc::recv(k, t),
        sys::REPLY => status(ipc::reply(k, t)),
        sys::REPLY_RECV => {
            // A failed reply (the caller gave up) does not stop the receive.
            ipc::reply(k, t);
            ipc::recv(k, t);
        }
        sys::YIELD => {
            status(Error::Ok);
            k.yield_current(t);
        }
        sys::SIGNAL => ipc::signal(k, t),
        sys::WAIT => ipc::wait(k, t),
        sys::THREAD_EXIT => k.exit(t, Exit::Code(x0)),
        #[cfg(feature = "debug-syscalls")]
        sys::DEBUG_PUT => status(debug_put(t)),
        _ => status(Error::UnknownSyscall),
    }
}

/// Prints bytes from the thread's IPC buffer debug area.
#[cfg(feature = "debug-syscalls")]
fn debug_put(t: KPtr<Thread>) -> Error {
    use aos_abi::{DEBUG_BYTES, IpcBuffer};
    // SAFETY: a short-lived reference to the running thread.
    let (len, buffer) = {
        let th = unsafe { t.get() };
        (th.ctx.x[1] as usize, th.ipc_buffer)
    };
    let Some(pa) = buffer else { return Error::InvalidArgument };
    if len > DEBUG_BYTES {
        return Error::InvalidArgument;
    }
    // SAFETY: the IPC buffer frame belongs to the kernel and is mapped in the linear map.
    let buf = unsafe { &*(crate::mm::phys_to_virt(pa) as *const IpcBuffer) };
    for chunk in buf.debug[..len].utf8_chunks() {
        crate::console::print(format_args!("{}", chunk.valid()));
        if !chunk.invalid().is_empty() {
            crate::console::print(format_args!("\u{fffd}"));
        }
    }
    Error::Ok
}
