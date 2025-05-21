#[cfg(feature = "log")]
#[macro_use(trace_time)]
extern crate measure_time;

#[cfg(feature = "log")]
#[macro_use(trace)]
extern crate log;

#[cfg(not(feature = "log"))]
#[macro_use]
mod macros {
    macro_rules! trace {
        ($($tt:tt)*) => {
            let _ = if false {
                let _ = ::std::format_args!($($tt)*);
            };
        };
    }

    macro_rules! trace_time {
        ($($tt:tt)*) => {
            trace!($($tt)*)
        };
    }
}

macro_rules! bail {
    ($err:expr $(,)?) => {
        return Err(Into::into($err))
    };
}

pub mod archive;
pub mod fsst;
pub mod metadata;
pub mod section;

pub use positioned_io;

/// The (included) minimum (major, minor) version this library supports.
pub const DWARFS_VERSION_MIN: (u8, u8) = (2, 5);

/// The (included) maximum (major, minor) version this library supports.
pub const DWARFS_VERSION_MAX: (u8, u8) = (2, 5);

use std::{cmp::Ordering, ops::Range};

pub use archive::{
    Archive, ArchiveIndex, AsChunks, Device, Dir, DirEntry, Error, File, Inode, InodeKind,
    InodeMetadata, Ipc, Result, SharedFile, Symlink, UniqueFile,
};

/// There is currently no binary search functions in std over a generic range.
/// This is copied from std: <https://github.com/rust-lang/rust/blob/1.86.0/library/core/src/slice/mod.rs#L2817>
/// License: MIT OR Apache-2.0
fn bisect_range_by<F>(range: Range<usize>, mut f: F) -> Option<usize>
where
    F: FnMut(usize) -> Ordering,
{
    let total_size = range.end - range.start;
    let mut size = total_size;
    if size == 0 {
        return None;
    }
    let mut base = 0usize;

    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let cmp = f(mid);
        // WAIT: Rust 1.88
        // base = (cmp == Ordering::Greater).select_unpredictable(base, mid);
        base = if cmp == Ordering::Greater { base } else { mid };
        size -= half;
    }

    let cmp = f(base);
    if cmp == Ordering::Equal {
        debug_assert!(base < total_size);
        Some(base)
    } else {
        None
    }
}
