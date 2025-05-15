pub mod archive;
pub mod fsst;
pub mod metadata;
pub mod section;

/// The (major, minor) version this library supports.
pub const DWARFS_VERSION: (u8, u8) = (2, 5);

pub use archive::{
    ArchiveIndex, Device, Dir, DirEntry, Error, File, Inode, InodeKind, InodeMetadata, Ipc, Result,
    SharedFile, Symlink, UniqueFile,
};
