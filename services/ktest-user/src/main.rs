//! User side of the kernel's B-1 tests; x0 selects the test (`aos_abi::ktest`).

#![no_std]
#![no_main]

use aos_rt::abi::{Error, MAX_MSG_WORDS, MsgInfo, ktest::*, ktest_b2, method};
use aos_rt::{call, counter, counter_frequency, ipc_buffer, println, recv, reply_recv, send, signal, wait};

aos_rt::entry!(main);

fn main(mode: u64, arg: u64) -> u64 {
    match mode {
        PING_SERVER => ping_server(),
        PING_CLIENT => ping_client(arg),
        REGCHECK => regcheck(arg),
        TIMEOUT => timeout(arg),
        FAULT => fault(arg),
        BAD_CALLS => bad_calls(),
        NOTIFY_WAIT => wait(SLOT_NOTIFICATION, 0).words[0],
        NOTIFY_SIGNAL => signal(SLOT_NOTIFICATION).status,
        FIFO_SENDER => send(SLOT_ENDPOINT, MsgInfo::new(arg, 0), [0; 4]).status,
        FIFO_RECEIVER => fifo_receiver(arg),
        ktest_b2::MEM_CLIENT => mem_client(),
        _ => 0xbad,
    }
}

const LEN: usize = 16;

fn ping_server() -> u64 {
    let mut r = recv(SLOT_ENDPOINT, 0);
    loop {
        if !r.is_ok() {
            return 0x100 + r.status;
        }
        let buf = ipc_buffer();
        for w in buf.msg.iter_mut().take(r.info.len()).skip(4) {
            *w += 1;
        }
        let words = r.words.map(|w| w + 1);
        if r.info.label() == LABEL_STOP {
            aos_rt::reply(r.info, words);
            return 0;
        }
        r = reply_recv(SLOT_ENDPOINT, r.info, words);
    }
}

fn ping_client(iterations: u64) -> u64 {
    let start = counter();
    for i in 0..iterations {
        let buf = ipc_buffer();
        for (k, w) in buf.msg[4..LEN].iter_mut().enumerate() {
            *w = i * 100 + k as u64;
        }
        let words = [i, i * 2, i * 3, u64::MAX - i];
        let r = call(SLOT_ENDPOINT, MsgInfo::new(i & 0xff, LEN), words, 0);
        if !r.is_ok() {
            return 0x100 + r.status;
        }
        if r.words != words.map(|w| w.wrapping_add(1)) || r.info != MsgInfo::new(i & 0xff, LEN) {
            return 2;
        }
        if ipc_buffer().msg[4..LEN].iter().enumerate().any(|(k, w)| *w != i * 100 + k as u64 + 1) {
            return 3;
        }
    }
    let ticks = counter() - start;
    let ns = ticks as u128 * 1_000_000_000 / counter_frequency() as u128 / iterations.max(1) as u128;
    println!("ping-pong: {iterations} calls, {ns} ns per round trip ({LEN} words)");
    let stop = call(SLOT_ENDPOINT, MsgInfo::new(LABEL_STOP, 0), [0; 4], 0);
    if stop.is_ok() { 0 } else { 4 }
}

unsafe extern "C" {
    /// 0 if every register kept its pattern while spinning `spins` iterations.
    fn aos_regcheck(seed: u64, spins: u64) -> u64;
}

core::arch::global_asm!(
    r#"
.macro FILLV n
    add     x2, x0, #(\n * 127)
    dup     v\n\().2d, x2
.endm
.macro CHECKV n
    add     x2, x0, #(\n * 127)
    umov    x4, v\n\().d[0]
    cmp     x4, x2
    b.ne    8f
    umov    x4, v\n\().d[1]
    cmp     x4, x2
    b.ne    8f
.endm
.macro FILLX r, k
    add     \r, x0, #(4000 + \k)
.endm
.macro CHECKX r, k
    add     x2, x0, #(4000 + \k)
    cmp     \r, x2
    b.ne    9f
.endm

.global aos_regcheck
aos_regcheck:
    stp     x29, x30, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     d8, d9, [sp, #-16]!
    stp     d10, d11, [sp, #-16]!
    stp     d12, d13, [sp, #-16]!
    stp     d14, d15, [sp, #-16]!
    mrs     x5, fpcr
    orr     x6, x5, #(1 << 24)          // FZ: a non-default FPCR the kernel must keep
    msr     fpcr, x6
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    FILLV   \n
    .endr
    FILLX   x9, 9
    FILLX   x10, 10
    FILLX   x11, 11
    FILLX   x12, 12
    FILLX   x13, 13
    FILLX   x14, 14
    FILLX   x15, 15
    FILLX   x16, 16
    FILLX   x17, 17
    FILLX   x18, 18
    FILLX   x19, 19
    FILLX   x20, 20
    FILLX   x21, 21
    FILLX   x22, 22
    FILLX   x23, 23
    FILLX   x24, 24
    FILLX   x25, 25
    FILLX   x26, 26
    FILLX   x27, 27
    FILLX   x28, 28
    mov     x3, x1
1:  subs    x3, x3, #1
    b.ne    1b
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    CHECKV  \n
    .endr
    CHECKX  x9, 9
    CHECKX  x10, 10
    CHECKX  x11, 11
    CHECKX  x12, 12
    CHECKX  x13, 13
    CHECKX  x14, 14
    CHECKX  x15, 15
    CHECKX  x16, 16
    CHECKX  x17, 17
    CHECKX  x18, 18
    CHECKX  x19, 19
    CHECKX  x20, 20
    CHECKX  x21, 21
    CHECKX  x22, 22
    CHECKX  x23, 23
    CHECKX  x24, 24
    CHECKX  x25, 25
    CHECKX  x26, 26
    CHECKX  x27, 27
    CHECKX  x28, 28
    mrs     x2, fpcr
    cmp     x2, x6
    b.ne    7f
    mov     x0, #0
    b       0f
7:  mov     x0, #3                      // FPCR lost
    b       0f
8:  mov     x0, #1                      // an FP/SIMD register lost its pattern
    b       0f
9:  mov     x0, #2                      // a general register lost its pattern
0:  msr     fpcr, x5
    ldp     d14, d15, [sp], #16
    ldp     d12, d13, [sp], #16
    ldp     d10, d11, [sp], #16
    ldp     d8, d9, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret
"#
);

fn regcheck(seed: u64) -> u64 {
    for round in 0..16 {
        // SAFETY: aos_regcheck follows the AAPCS64 and restores what it changes.
        let r = unsafe { aos_regcheck(seed, 3_000_000) };
        if r != 0 {
            return 0x10 * round + r;
        }
        if round % 4 == 3 {
            aos_rt::yield_now();
        }
    }
    0
}

fn timeout(ns: u64) -> u64 {
    let start = counter();
    let r = recv(SLOT_ENDPOINT, ns);
    let elapsed_ns = (counter() - start) as u128 * 1_000_000_000 / counter_frequency() as u128;
    if r.error() != Some(Error::Timeout) {
        return 1;
    }
    if elapsed_ns < ns as u128 {
        return 2;
    }
    0
}

fn fault(kind: u64) -> u64 {
    match kind {
        FAULT_READ_KERNEL => {
            // SAFETY: deliberately invalid; the kernel must fault this thread.
            unsafe { core::ptr::read_volatile(0xffff_0000_4020_0000 as *const u64) }
        }
        FAULT_WRITE_TEXT => {
            // SAFETY: deliberately invalid: program text is mapped read-only.
            unsafe { core::ptr::write_volatile(main as fn(u64, u64) -> u64 as usize as *mut u64, 0) };
            0
        }
        FAULT_EXEC_STACK => {
            let code = [0xd65f_03c0u32; 4]; // ret
            // SAFETY: deliberately invalid: the stack is mapped execute-never.
            let f: extern "C" fn() = unsafe { core::mem::transmute(code.as_ptr()) };
            f();
            0
        }
        // SAFETY: deliberately undefined.
        FAULT_UNDEFINED => unsafe {
            core::arch::asm!("udf #0");
            0
        },
        _ => 0xbad,
    }
}

fn bad_calls() -> u64 {
    let invalid = Some(Error::InvalidCap);
    if call(SLOT_EMPTY, MsgInfo::new(0, 0), [0; 4], 0).error() != invalid {
        return 1;
    }
    if call(1 << 40, MsgInfo::new(0, 0), [0; 4], 0).error() != invalid {
        return 2;
    }
    if send(SLOT_NOTIFICATION, MsgInfo::new(0, 0), [0; 4]).error() != invalid {
        return 3; // a notification is not an endpoint
    }
    if wait(SLOT_ENDPOINT, 0).error() != invalid {
        return 4;
    }
    if aos_rt::syscall(0x7777, [0; 7]).error() != Some(Error::UnknownSyscall) {
        return 5;
    }
    if call(SLOT_ENDPOINT, MsgInfo::new(0, MAX_MSG_WORDS + 1), [0; 4], 0).error() != Some(Error::InvalidArgument) {
        return 6;
    }
    if aos_rt::reply(MsgInfo::new(0, 0), [0; 4]).error() != Some(Error::NoReply) {
        return 7;
    }
    0
}

fn fifo_receiver(count: u64) -> u64 {
    let mut code = 0;
    for i in 0..count {
        let r = recv(SLOT_ENDPOINT, 0);
        if !r.is_ok() {
            return 0xbad;
        }
        code |= (r.info.label() & 0xf) << (4 * i);
    }
    code
}

/// Gets a frame from the memory server, maps it, and checks it is fresh and private.
fn mem_client() -> u64 {
    use aos_rt::proto::memory::ALLOC_FRAMES;
    const VA: u64 = 0x0000_0000_1000_0000;
    ipc_buffer().recv_slot = ktest_b2::SLOT_RECEIVED;
    let r = call(SLOT_ENDPOINT, MsgInfo::new(ALLOC_FRAMES, 1), [1, 0, 0, 0], 0);
    if !r.is_ok() || r.info.caps() != 1 || r.words[0] != 1 {
        println!("mem-client: allocation failed: {r:?}");
        return 1;
    }
    if let Err(e) = aos_rt::cap::map(ktest_b2::SLOT_SPACE, ktest_b2::SLOT_RECEIVED, VA, method::WRITE) {
        println!("mem-client: map failed: {e:?}");
        return 2;
    }
    let words = VA as *mut u64;
    for i in 0..512 {
        // SAFETY: the frame is mapped read-write at VA.
        if unsafe { words.add(i).read_volatile() } != 0 {
            return 3;
        }
        // SAFETY: as above.
        unsafe { words.add(i).write_volatile(i as u64 * 3) };
    }
    // SAFETY: as above.
    if (0..512).any(|i| unsafe { words.add(i).read_volatile() } != i as u64 * 3) {
        return 4;
    }
    if aos_rt::cap::retype(ktest_b2::SLOT_RECEIVED, 6, 20, 1).is_ok() {
        return 5; // a frame is not an Untyped
    }
    println!("mem-client: got a fresh frame from the memory server");
    0
}
