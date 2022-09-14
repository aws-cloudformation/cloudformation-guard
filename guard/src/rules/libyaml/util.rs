use std::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::Deref,
    ptr::{addr_of, NonNull},
};

use unsafe_libyaml as sys;
use crate::rules::path_value::Location;

pub(crate) struct Owned<T, Init = T> {
    ptr: NonNull<T>,
    marker: PhantomData<NonNull<Init>>,
}

impl<T> Owned<T> {
    pub fn new_uninit() -> Owned<MaybeUninit<T>, T> {
        // FIXME: use Box::new_uninit when stable
        let boxed = Box::new(MaybeUninit::<T>::uninit());
        Owned {
            ptr: unsafe { NonNull::new_unchecked(Box::into_raw(boxed)) },
            marker: PhantomData,
        }
    }

    pub unsafe fn assume_init(definitely_init: Owned<MaybeUninit<T>, T>) -> Owned<T> {
        let ptr = definitely_init.ptr;
        mem::forget(definitely_init);
        Owned {
            ptr: ptr.cast(),
            marker: PhantomData,
        }
    }
}

#[repr(transparent)]
pub(crate) struct InitPtr<T> {
    pub ptr: *mut T,
}

impl<T, Init> Deref for Owned<T, Init> {
    type Target = InitPtr<Init>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*addr_of!(self.ptr).cast::<InitPtr<Init>>() }
    }
}

impl<T, Init> Drop for Owned<T, Init> {
    fn drop(&mut self) {
        let _ = unsafe { Box::from_raw(self.ptr.as_ptr()) };
    }
}


pub(crate) fn system_mark_to_location(mark: sys::yaml_mark_t) -> Location {
    Location {
        line: mark.line as usize,
        col: mark.column as usize,
    }
}