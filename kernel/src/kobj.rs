//! Kernel objects and references to them.
//!
//! In B-1 every kernel object occupies a frame of its own from the boot allocator; from B-2
//! on, objects are carved out of Untyped memory on behalf of user space. Objects are never
//! freed in B-1.

use core::fmt;
use core::ptr::NonNull;

use crate::mm::{self, paging::PAGE_SIZE, phys_to_virt};

/// A reference to a kernel object in the linear map.
pub struct KPtr<T>(NonNull<T>);

impl<T> Clone for KPtr<T> {
    fn clone(&self) -> KPtr<T> {
        *self
    }
}

impl<T> Copy for KPtr<T> {}

impl<T> PartialEq for KPtr<T> {
    fn eq(&self, other: &KPtr<T>) -> bool {
        self.0 == other.0
    }
}

impl<T> Eq for KPtr<T> {}

impl<T> fmt::Debug for KPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:p}", self.0)
    }
}

impl<T> KPtr<T> {
    /// Moves `value` into a fresh frame; `None` when out of memory.
    pub fn new(value: T) -> Option<KPtr<T>> {
        const { assert!(size_of::<T>() <= PAGE_SIZE && align_of::<T>() <= PAGE_SIZE) };
        let pa = mm::with_frames(|f| f.alloc())?;
        let p = phys_to_virt(pa) as *mut T;
        // SAFETY: the frame is fresh, mapped read-write, page-aligned and large enough.
        unsafe { p.write(value) };
        NonNull::new(p).map(KPtr)
    }

    /// The object.
    ///
    /// # Safety
    /// The kernel is single-threaded and interrupt handlers never touch kernel objects, so
    /// the only rule is: no other reference to the same object may be live while the
    /// returned one is.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get<'a>(self) -> &'a mut T {
        // SAFETY: guaranteed by the caller.
        unsafe { &mut *self.0.as_ptr() }
    }
}
