//! Synchronisation primitives. The kernel runs with IRQs masked throughout B-0; once
//! interrupts are enabled (B-1), locks shared with interrupt context must also mask them.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the lock serialises all access to `value`.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> SpinLock<T> {
        SpinLock { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// A value written once and then only read. Meant for statics: the value is never dropped.
pub struct SetOnce<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

// SAFETY: the value is written exactly once, before `state` becomes READY (release), and only
// shared references are handed out after observing READY (acquire).
unsafe impl<T: Send + Sync> Sync for SetOnce<T> {}

impl<T> SetOnce<T> {
    pub const fn new() -> SetOnce<T> {
        SetOnce { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        if self.state.compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(value);
        }
        // SAFETY: the WRITING state gives this call exclusive access.
        unsafe { (*self.value.get()).write(value) };
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    pub fn get(&self) -> Option<&T> {
        // SAFETY: READY means the value is initialised and no longer written.
        (self.state.load(Ordering::Acquire) == READY).then(|| unsafe { (*self.value.get()).assume_init_ref() })
    }
}
