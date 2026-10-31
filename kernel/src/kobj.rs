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
    /// Moves `value` into fresh pages from the boot allocator; `None` when out of memory.
    pub fn new(value: T) -> Option<KPtr<T>> {
        const { assert!(align_of::<T>() <= PAGE_SIZE) };
        let size = size_of::<T>().div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let pa = mm::with_frames(|f| f.alloc_region(size, PAGE_SIZE))?;
        // SAFETY: fresh, zeroed, page-aligned pages large enough for `T`.
        Some(unsafe { KPtr::place(pa, value) })
    }

    /// An object whose valid initial state is all zero bytes (`CNode`), in fresh pages.
    ///
    /// # Safety
    /// All-zero bytes must be a valid `T`.
    pub unsafe fn zeroed() -> Option<KPtr<T>> {
        let size = size_of::<T>().div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let pa = mm::with_frames(|f| f.alloc_region(size, PAGE_SIZE))?;
        NonNull::new(phys_to_virt(pa) as *mut T).map(KPtr)
    }

    /// Moves `value` to physical address `pa` (memory carved from Untyped for it).
    ///
    /// # Safety
    /// `[pa, pa + size_of::<T>())` must be RAM owned by the new object, suitably aligned.
    pub unsafe fn place(pa: usize, value: T) -> KPtr<T> {
        let p = phys_to_virt(pa) as *mut T;
        // SAFETY: guaranteed by the caller.
        unsafe { p.write(value) };
        KPtr(NonNull::new(p).expect("the linear map has no null address"))
    }

    /// A reference to an object embedded in another kernel object (a slot in a CNode).
    pub fn from_mut(value: &mut T) -> KPtr<T> {
        KPtr(NonNull::from(value))
    }

    /// The physical address of the object.
    pub fn pa(self) -> usize {
        mm::virt_to_phys(self.0.as_ptr() as usize)
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
