use std::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::Deref,
    ptr::{addr_of, NonNull},
};

use crate::rules::path_value::Location;
#[allow(clippy::unsafe_removed_from_name)]
use unsafe_libyaml as sys;

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

/// libyaml counts lines and columns from zero. Everything downstream of this function counts from
/// one, so the conversion is where the two conventions have to meet.
///
/// Both readers of `Location.line` assume one-based. `validate::cfn`'s `emit_code` prints a
/// one-based excerpt of the file beside the `L:` value, so a zero-based `line` made one report block
/// state two different numbers for one position -- `L:9` above its own excerpt line `10.`. SARIF's
/// `build_region` assigns `line` into `startLine`, whose schema minimum is 1, and reads
/// `line < 1` as "this finding has no position at all", which is only correct for a one-based value.
///
/// The rules file does not share the convention and did not need changing: those locations come from
/// `nom`'s `LocatedSpan` by way of `rules/exprs.rs`, and `location_line()`/`get_utf8_column()` are
/// already one-based. So the product used to print one convention for the rules file it read and
/// another for the data file, which is what makes this a defect rather than a house style.
///
/// `Location::default()` stays `{0, 0}` and keeps meaning "no position": it is what a literal in the
/// rules file is given, and it is the value SARIF's `line < 1` check exists to recognise. Adding the
/// offset here rather than in `Display` is what keeps the two distinguishable.
pub(crate) fn system_mark_to_location(mark: sys::yaml_mark_t) -> Location {
    Location {
        line: mark.line as usize + 1,
        col: mark.column as usize + 1,
    }
}
