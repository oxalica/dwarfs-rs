//! DwarFS archive hierarchy builder.
//!
//! This module provides [`Builder`] to build [`dwarfs::metadata::Metadata`] of
//! a DwarFS archive, which is the spine structure for directory hierarchy and
//! file chunks information.
//!
//! ## Limitations
//!
//! Due to implementation limitations, the `Metadata` structure cannot exceeds
//! 2³² bytes. This also implies lengths of all substructures, eg. number of
//! files, directories, chunks and etc, must also not exceed 2³².
//!
//! Note that this limitation only applies to `Metadata` itself, not file
//! (chunk) data. The total length of chunks is not limited, as long as it
//! is addressable. Eg. It's possible to have 2²⁰ files each consists of 2²⁰
//! chunks of 2²⁰ bytes without any issue.
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    num::NonZero,
};

use dwarfs::metadata;
use indexmap::IndexSet;

use crate::{Error, ErrorInner, Result};

// These values are stored on disk, thus should be platform-agnostic.
// But `rustix` does not expose them on non-UNIX platforms yet.
// TODO: Maybe define them in `dwarfs`?
// From: <https://man.archlinux.org/man/inode.7.en#The_file_type_and_mode>
const S_IFSOCK: u32 = 0o0140000;
const S_IFLNK: u32 = 0o0120000;
const S_IFREG: u32 = 0o0100000;
const S_IFBLK: u32 = 0o0060000;
const S_IFDIR: u32 = 0o0040000;
const S_IFCHR: u32 = 0o0020000;
const S_IFIFO: u32 = 0o0010000;

/// Metadata construction configurations.
#[derive(Debug, Clone)]
pub struct Config {
    block_size: NonZero<u32>,
    mtime_only: bool,
    time_resolution_sec: NonZero<u32>,
    // TODO: source_date_epoch: Option<NonZero<u64>>,
    creator: Option<Cow<'static, str>>,
    created_timestamp: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_size: NonZero::new(16 << 20).expect("not zero"),
            mtime_only: false,
            time_resolution_sec: NonZero::new(1).expect("not zero"),
            creator: Some(Cow::Borrowed(Self::DEFAULT_CREATOR_VERSION)),
            created_timestamp: None,
        }
    }
}

impl Config {
    const DEFAULT_CREATOR_VERSION: &str =
        concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"));

    /// Set the block size of this archive.
    ///
    /// Default value is 16MiB.
    ///
    /// Each [`BLOCK` section][dwarfs::section::SectionType::BLOCK] must have
    /// this size (before compression) except for the last one.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is not a power of two.
    pub fn block_size(&mut self, bytes: NonZero<u32>) -> &mut Self {
        assert!(bytes.is_power_of_two());
        self.block_size = bytes;
        self
    }

    pub fn get_block_size(&self) -> NonZero<u32> {
        self.block_size
    }

    /// Only store file modification time (mtime) and ignore access (atime) or
    /// change (ctime) times.
    ///
    /// Default value is `false`.
    ///
    /// This will cause all access and change times to be ignored, and will set
    /// a flag in metadata informing their unavailability.
    pub fn mtime_only(&mut self, yes: bool) -> &mut Self {
        self.mtime_only = yes;
        self
    }

    /// Set the minimum resolution of all file times.
    ///
    /// Default value is 1 second, which is also the minimal possible value.
    ///
    /// A non-one resolution will cause all file times to be truncated to the
    /// max multiples of the resolution not-greater than the original value.
    pub fn time_resolution_sec(&mut self, sec: NonZero<u32>) -> &mut Self {
        self.time_resolution_sec = sec;
        self
    }

    /// Set a custom string indicating the name and version of the creator program.
    ///
    /// Default value is
    #[doc = concat!("`\"", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"), "\"`.")]
    pub fn creator(&mut self, info: impl Into<Option<Cow<'static, str>>>) -> &mut Self {
        self.creator = info.into();
        self
    }

    /// Set a timestamp indicating the archive creation time.
    ///
    /// Default value is `None`.
    pub fn created_timestamp(&mut self, ts: impl Into<Option<u64>>) -> &mut Self {
        self.created_timestamp = ts.into();
        self
    }
}

/// The metadata builder.
///
/// See [module level documentations][self].
#[derive(Debug)]
pub struct Builder {
    config: Config,

    inodes: Vec<InodeData>,
    dir_entries: IndexSet<DirEntry>,
    chunks: Vec<Chunk>,
    file_chunk_start: Vec<u32>,
    /// Symlinks do not store its target (index) in inode data, but is looked up
    /// through an indirect table with its inode.
    symlink_target_idxs: Vec<u32>,
    devices: Vec<u64>,

    // TODO: Optimize memory footprint of these small strings.
    name_table: IndexSet<String>,
    symlink_table: IndexSet<String>,

    modes: IndexSet<u32>,
    uids: IndexSet<u32>,
    gids: IndexSet<u32>,
}

impl Builder {
    /// Create a builder with default configurations.
    pub fn new(root_meta: &InodeMetadata) -> Self {
        Self::new_with_config(&Config::default(), root_meta)
    }

    /// Create a builder with custom configurations.
    pub fn new_with_config(config: &Config, root_meta: &InodeMetadata) -> Self {
        let mut this = Self {
            config: config.clone(),
            inodes: Default::default(),
            dir_entries: Default::default(),
            chunks: Default::default(),
            file_chunk_start: Default::default(),
            symlink_target_idxs: Default::default(),
            devices: Default::default(),
            name_table: Default::default(),
            symlink_table: Default::default(),
            modes: Default::default(),
            uids: Default::default(),
            gids: Default::default(),
        };
        this.put_inode(S_IFDIR, InodeKind::Dir, root_meta)
            .expect("no overflow");
        // NB. The self-link of root directory is handled in `finish`.
        // We do not want to check duplicates against te special (0, 0, 0) link.
        this
    }

    /// Get the configuration used to build this `Builder`.
    #[inline]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the implicitly created root directory.
    #[inline]
    pub fn root(&self) -> DirId {
        DirId(0)
    }

    fn put_inode(&mut self, file_type: u32, kind: InodeKind, meta: &InodeMetadata) -> Result<u32> {
        let ino = u32::try_from(self.inodes.len())
            .ok()
            .ok_or(ErrorInner::Limit("inode count exceeds 2^32"))?;

        let cvt_time = |timestamp: u64| {
            u32::try_from(timestamp / u64::from(self.config.time_resolution_sec.get()))
                .map_err(|_| Error::from(ErrorInner::Limit("relative timestamp exceeds 2^32")))
        };
        let mtime_offset = cvt_time(meta.mtime)?;
        let (atime_offset, ctime_offset) = if self.config.mtime_only {
            (0, 0)
        } else {
            (cvt_time(meta.atime)?, cvt_time(meta.ctime)?)
        };

        let mode = file_type | meta.mode_without_type;
        let mode_idx = self.modes.insert_full(mode).0 as u32;
        let uid_idx = self.uids.insert_full(meta.uid).0 as u32;
        let gid_idx = self.gids.insert_full(meta.gid).0 as u32;

        self.inodes.push(InodeData {
            kind,
            orig_ino: ino,
            mode_idx,
            uid_idx,
            gid_idx,
            mtime_offset,
            atime_offset,
            ctime_offset,
        });

        Ok(ino)
    }

    fn put_entry_inner(&mut self, parent: DirId, name: &str, child: u32) -> Result<()> {
        u32::try_from(self.dir_entries.len())
            .ok()
            .ok_or(ErrorInner::Limit("directory entry count exceeds 2^32"))?;
        let name_idx = self.name_table.insert_full(name.into()).0 as u32;
        let (_, inserted) = self.dir_entries.insert_full(DirEntry {
            parent: parent.0,
            name_idx,
            child,
        });
        if !inserted {
            return Err(ErrorInner::DuplicatedEntry.into());
        }
        Ok(())
    }

    /// Add an empty directory under a directory.
    ///
    /// # Errors
    ///
    /// Return `Err` if either:
    ///
    /// - Inode count overflows.
    /// - Directory entry count overflows.
    /// - There is already an entry with the same name in the directory.
    #[inline]
    pub fn put_dir(&mut self, parent: DirId, name: &str, meta: &InodeMetadata) -> Result<DirId> {
        let ino = self.put_inode(S_IFDIR, InodeKind::Dir, meta)?;
        self.put_entry_inner(parent, name, ino)?;
        Ok(DirId(ino))
    }

    /// Add a hard link to an existing inode under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    pub fn put_hard_link(
        &mut self,
        parent: DirId,
        name: &str,
        inode: impl Into<LinkableInodeId>,
    ) -> Result<()> {
        self.put_entry_inner(parent, name, inode.into().0)
    }

    /// Add a regular file under a directory.
    ///
    /// # Panics
    ///
    /// Panics if any chunk has a offset exceeding [`Config::block_size`].
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    pub fn put_file(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
        chunks: impl IntoIterator<Item = Chunk>,
    ) -> Result<FileId> {
        let chunk_start = self.chunks.len() as u32;
        self.chunks.extend(chunks);
        u32::try_from(self.chunks.len())
            .ok()
            .ok_or(ErrorInner::Limit("file chunk count exceeds 2^32"))?;
        if let Some(c) = self.chunks[chunk_start as usize..].iter().find(|c| {
            c.offset
                .checked_add(c.size)
                .is_none_or(|end| end > self.config.block_size.get())
        }) {
            panic!(
                "invalid chunk for block size {}B: {:?}",
                self.config.block_size, c,
            );
        }
        let ino = self.put_inode(S_IFREG, InodeKind::UniqueFile, meta)?;
        self.file_chunk_start.push(chunk_start);
        self.put_entry_inner(parent, name, ino)?;
        Ok(FileId(ino))
    }

    /// Add a symbolic link (symlink) under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    #[inline]
    pub fn put_symlink(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
        target: &str,
    ) -> Result<LinkableInodeId> {
        let ino = self.put_inode(S_IFLNK, InodeKind::Symlink, meta)?;
        let tgt_idx = self.symlink_table.insert_full(target.into()).0 as u32;
        self.symlink_target_idxs.push(tgt_idx);
        self.put_entry_inner(parent, name, ino)?;
        Ok(LinkableInodeId(ino))
    }

    /// Add a block device inode under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    #[inline]
    pub fn put_block_device(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
        device_id: u64,
    ) -> Result<LinkableInodeId> {
        let ino = self.put_inode(S_IFBLK, InodeKind::Device, meta)?;
        self.devices.push(device_id);
        self.put_entry_inner(parent, name, ino)?;
        Ok(LinkableInodeId(ino))
    }

    /// Add a character device inode under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    #[inline]
    pub fn put_char_device(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
        device_id: u64,
    ) -> Result<LinkableInodeId> {
        let ino = self.put_inode(S_IFCHR, InodeKind::Device, meta)?;
        self.devices.push(device_id);
        self.put_entry_inner(parent, name, ino)?;
        Ok(LinkableInodeId(ino))
    }

    /// Add a FIFO (named pipe) inode under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    #[inline]
    pub fn put_fifo(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
    ) -> Result<LinkableInodeId> {
        let ino = self.put_inode(S_IFIFO, InodeKind::Ipc, meta)?;
        self.put_entry_inner(parent, name, ino)?;
        Ok(LinkableInodeId(ino))
    }

    /// Add a socket inode under a directory.
    ///
    /// # Errors
    ///
    /// See [`Builder::put_dir`].
    #[inline]
    pub fn put_socket(
        &mut self,
        parent: DirId,
        name: &str,
        meta: &InodeMetadata,
    ) -> Result<LinkableInodeId> {
        let ino = self.put_inode(S_IFSOCK, InodeKind::Ipc, meta)?;
        self.put_entry_inner(parent, name, ino)?;
        Ok(LinkableInodeId(ino))
    }

    // TODO: FSST compressor.
    fn build_string_table(
        tbl: IndexSet<String>,
        err_msg: &'static str,
    ) -> Result<Option<metadata::StringTable>> {
        if tbl.is_empty() {
            return Ok(None);
        }

        let mut out = metadata::StringTable::default();
        // Delta indices.
        out.packed_index = true;

        let total_len = tbl.iter().map(|s| s.len()).sum::<usize>();
        u32::try_from(total_len)
            .ok()
            .ok_or(ErrorInner::Limit(err_msg))?;
        out.buffer.reserve(total_len);

        // NB. For `packed_index`, the first zero should be omitted.
        out.index.reserve(tbl.len());
        for s in tbl {
            out.buffer.extend_from_slice(s.as_bytes());
            out.index.push(s.len() as u32);
        }

        Ok(Some(out))
    }

    /// Finalize and construct the result [`Metadata`][dwarfs::metadata::Metadata].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the hierarchy is invalid, or exceeds certain limitations,
    /// including and not limited to:
    /// - Duplicated entry names in a directory.
    /// - Any (intermediate) low-level structures exceeds 2³² bytes.
    ///   See [module level documentations][self].
    pub fn finish(mut self) -> Result<metadata::Metadata> {
        let mut out = metadata::Metadata::default();
        let opts = out.options.insert(metadata::FsOptions::default());

        //// Configurables ////

        opts.mtime_only = self.config.mtime_only;
        opts.time_resolution_sec = (self.config.time_resolution_sec.get() != 1)
            .then_some(self.config.time_resolution_sec.get());
        // TODO: Pack more fields if possible.

        //// Inodes ////

        // Stable sort to keep relative order unchanged. It is important to keep
        // the topological order of directories.
        self.inodes.sort_by_key(|inode| inode.kind as u8);
        let orig_ino_to_final = {
            let mut map = vec![0u32; self.inodes.len()];
            for (final_ino, inode) in self.inodes.iter().enumerate() {
                map[inode.orig_ino as usize] = final_ino as u32;
            }
            map
        };

        out.inodes = self
            .inodes
            .iter()
            .map(|inode| {
                let mut data = metadata::InodeData::default();
                data.mode_index = inode.mode_idx;
                data.owner_index = inode.uid_idx;
                data.group_index = inode.gid_idx;
                data.atime_offset = inode.atime_offset;
                data.mtime_offset = inode.mtime_offset;
                data.ctime_offset = inode.ctime_offset;
                data
            })
            .collect();

        //// Directory and entries ////

        let dir_cnt = self
            .inodes
            .iter()
            .take_while(|data| data.kind == InodeKind::Dir)
            .count();
        assert_ne!(dir_cnt, 0, "root exists");

        // Directory relative order is kept unchanged because of stable sort above.
        // So this will sort `dir_entries` to the final order.
        // Note that `dir_entries[0]` is the self-link for the root directory.
        let mut dir_entries = std::iter::once(DirEntry {
            parent: 0,
            child: 0,
            // This index is unused.
            name_idx: 0,
        })
        .chain(self.dir_entries)
        .collect::<Vec<_>>();
        dir_entries[1..]
            .sort_by_key(|ent| (ent.parent, &self.name_table[ent.name_idx as usize][..]));
        // Checked on inserting entries.
        debug_assert!(
            dir_entries[1..]
                .windows(2)
                .all(|w| (w[0].parent, w[0].name_idx) != (w[1].parent, w[1].name_idx))
        );

        // Initialize directories links.
        {
            // One more sentinel element.
            out.directories = vec![Default::default(); dir_cnt + 1];

            // Skip the 0-th root directory, which should be kept zero-initialized.
            let mut offset = 1u32;
            for (final_ino, inode) in self.inodes[..dir_cnt].iter().enumerate() {
                let dir = &mut out.directories[final_ino];
                dir.first_entry = offset;
                // For child directories of root, this is the default 0, as expected.
                // For other directories, this should already be initialized by
                // the entry traversal of its parent entries, because of
                // the topological order enforced by APIs.
                let parent_entry = dir.self_entry;

                // Update parent links of child directories.
                while let Some(ent) = dir_entries
                    .get(offset as usize)
                    .filter(|ent| ent.parent == inode.orig_ino)
                {
                    let child_final_ino = orig_ino_to_final[ent.child as usize] as usize;
                    if let Some(subdir) = out.directories.get_mut(child_final_ino) {
                        subdir.self_entry = offset;
                        subdir.parent_entry = parent_entry;
                    }
                    offset += 1;
                }
            }
            debug_assert_eq!(offset as usize, dir_entries.len());

            // Sentinel.
            out.directories.last_mut().unwrap().first_entry = dir_entries.len() as u32;
        }

        out.dir_entries = Some(
            dir_entries
                .into_iter()
                .map(|ent| {
                    let mut out = metadata::DirEntry::default();
                    out.name_index = ent.name_idx;
                    out.inode_num = orig_ino_to_final[ent.child as usize];
                    out
                })
                .collect(),
        );

        //// String tables ////

        out.compact_names =
            Self::build_string_table(self.name_table, "total file name length exceeds 2^32")?;
        out.compact_symlinks =
            Self::build_string_table(self.symlink_table, "total symlink length exceeds 2^32")?;

        //// Trivial fields ////

        out.block_size = self.config.block_size.get();
        out.total_fs_size = 0; // Not really necessary but only for human.
        out.dwarfs_version = self.config.creator.map(|s| String::from(s).into());
        out.create_timestamp = self.config.created_timestamp;

        out.symlink_table = self.symlink_target_idxs;
        out.modes = self.modes.into_iter().collect();
        out.uids = self.uids.into_iter().collect();
        out.gids = self.gids.into_iter().collect();
        out.devices = (!self.devices.is_empty()).then_some(self.devices);

        out.chunk_table = self.file_chunk_start;
        // Sentinel.
        out.chunk_table.push(self.chunks.len() as u32);

        out.chunks = self
            .chunks
            .into_iter()
            .map(|chunk| {
                let mut data = metadata::Chunk::default();
                data.block = chunk.section_idx;
                data.offset = chunk.offset;
                data.size = chunk.size;
                data
            })
            .collect();

        Ok(out)
    }
}

#[derive(Debug)]
struct DirEntry {
    parent: u32,
    name_idx: u32,
    child: u32,
}

// Hash and Eq impls are only on `(parent, name_idx)` pair, because we want to
// check entry names in a directory do not duplicate.
impl Hash for DirEntry {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_u64(u64::from(self.parent) | u64::from(self.name_idx) << 32);
    }
}
impl PartialEq for DirEntry {
    fn eq(&self, other: &Self) -> bool {
        (self.parent, self.name_idx) == (other.parent, other.name_idx)
    }
}
impl Eq for DirEntry {}

/// A chunk of data for a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chunk {
    pub section_idx: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeKind {
    // NB. The order matters for sorting.
    // It should match the DwarFS inode type order.
    Dir,
    Symlink,
    UniqueFile,
    // TODO: SharedFile
    Device,
    Ipc,
}

#[derive(Debug)]
struct InodeData {
    kind: InodeKind,
    // To maintain mapping after sorting inodes by their kinds.
    orig_ino: u32,

    mode_idx: u32,
    uid_idx: u32,
    gid_idx: u32,
    mtime_offset: u32,
    atime_offset: u32,
    ctime_offset: u32,
}

/// The metadata of an inode.
#[derive(Debug, Clone)]
pub struct InodeMetadata {
    mode_without_type: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    atime: u64,
    ctime: u64,
}

impl TryFrom<&std::fs::Metadata> for InodeMetadata {
    type Error = Error;

    fn try_from(meta: &std::fs::Metadata) -> Result<Self, Self::Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let cvt_time = |sec: i64| {
                u64::try_from(sec)
                    .ok()
                    .ok_or(ErrorInner::Limit("negative timestamps are not supported"))
            };

            let mut ret = InodeMetadata::new(meta.mode() & 0o777);
            ret.mtime(cvt_time(meta.mtime())?)
                .atime(cvt_time(meta.atime())?)
                .ctime(cvt_time(meta.ctime())?)
                .uid(meta.uid())
                .gid(meta.gid());
            Ok(ret)
        }

        #[cfg(not(unix))]
        {
            compile_error!("TODO: Only *NIX platforms are supported yet");
            unimplemented!()
        }
    }
}

impl InodeMetadata {
    /// Create a default metadata with given [file mode][mode].
    ///
    /// [mode]: https://man.archlinux.org/man/inode.7.en#The_file_type_and_mode
    pub const fn new(mode_without_type: u32) -> Self {
        assert!(
            mode_without_type & !0o777 == 0,
            "`mode_without_type` should only have 0o7777 bits set",
        );
        Self {
            mode_without_type,
            uid: 0,
            gid: 0,
            mtime: 0,
            atime: 0,
            ctime: 0,
        }
    }

    /// Set the owner numeric id.
    ///
    /// If unset, it defaults to `0`.
    pub fn uid(&mut self, uid: u32) -> &mut Self {
        self.uid = uid;
        self
    }

    /// Set the owner group numeric id.
    ///
    /// If unset, it defaults to `0`.
    pub fn gid(&mut self, gid: u32) -> &mut Self {
        self.gid = gid;
        self
    }

    /// Set the modification time (mtime).
    ///
    /// If unset, it defaults to `0`.
    pub fn mtime(&mut self, timestamp: u64) -> &mut Self {
        self.mtime = timestamp;
        self
    }

    /// Set the access time (atime).
    ///
    /// If unset, it defaults to `0`.
    /// If [`Config::mtime_only`] is set, this value is ignored.
    pub fn atime(&mut self, timestamp: u64) -> &mut Self {
        self.atime = timestamp;
        self
    }

    /// Set the change time (ctime).
    ///
    /// If unset, it defaults to `0`.
    /// If [`Config::mtime_only`] is set, this value is ignored.
    pub fn ctime(&mut self, timestamp: u64) -> &mut Self {
        self.ctime = timestamp;
        self
    }
}

/// A handle to a directory inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirId(u32);

/// A handle to an inode that is allowed to be hard-linked.
///
/// All inodes except directories are linkable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkableInodeId(u32);

/// A handle to a regular file inode.
///
/// This type implements `Into<LinkableInodeId>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(u32);

impl From<FileId> for LinkableInodeId {
    fn from(i: FileId) -> Self {
        Self(i.0)
    }
}
