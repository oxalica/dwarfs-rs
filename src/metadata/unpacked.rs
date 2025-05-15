//! Unpacked metadata structures for standalone easy access.
//!
//! These struct, eg [`Metadata`] can ber converted recursively from packed
//! [`crate::metadata::Metadata`] using [`Into`].
#![expect(deprecated, reason = "for internal conversion")]
use std::collections::{BTreeMap, BTreeSet};

use bstr::BString;

use crate::metadata::frozen::FromRaw;

type Str = BString;
type List<T> = Vec<T>;
type Set<T> = BTreeSet<T>;
type Map<K, V> = BTreeMap<K, V>;

#[derive(Debug, Clone)]
pub struct Metadata {
    pub chunks: List<Chunk>,
    pub directories: List<Directory>,
    pub inodes: List<InodeData>,
    pub chunk_table: List<u32>,
    #[deprecated = "deprecated since dwarfs 2.3"]
    pub entry_table: List<u32>,
    pub symlink_table: List<u32>,
    pub uids: List<u32>,
    pub gids: List<u32>,
    pub modes: List<u32>,
    pub names: List<Str>,
    pub symlinks: List<Str>,
    pub timestamp_base: u64,
    pub chunk_inode_offset: u32,
    pub link_inode_offset: u32,
    pub block_size: u32,
    pub total_fs_size: u64,
    pub devices: Option<List<u64>>,

    pub options: Option<FsOptions>,
    pub dir_entries: Option<List<DirEntry>>,
    pub shared_files_table: Option<List<u32>>,
    pub total_hardlink_size: Option<u64>,
    pub dwarfs_version: Option<Str>,
    pub create_timestamp: Option<u64>,
    pub compact_names: Option<StringTable>,
    pub compact_symlinks: Option<StringTable>,
    pub preferred_path_separator: Option<u32>,
    pub features: Option<Set<Str>>,
    pub category_names: Option<List<Str>>,
    pub block_categories: Option<List<Str>>,
    pub reg_file_size_cache: Option<InodeSizeCache>,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub block: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct Directory {
    pub parent_entry: u32,
    pub first_entry: u32,
    pub self_entry: u32,
}

#[derive(Debug, Clone)]
pub struct InodeData {
    pub mode_index: u32,
    pub owner_index: u32,
    pub group_index: u32,
    pub atime_offset: u32,
    pub mtime_offset: u32,
    pub ctime_offset: u32,

    #[deprecated = "deprecated since dwarfs 2.3"]
    pub name_index: u32,
    #[deprecated = "deprecated since dwarfs 2.3"]
    pub inode: u32,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name_index: u32,
    pub inode_num: u32,
}

#[derive(Debug, Clone)]
pub struct FsOptions {
    pub mtime_only: bool,
    pub time_resolution_sec: Option<u32>,
    pub packed_chunk_table: bool,
    pub packed_directories: bool,
    pub packed_shared_files_table: bool,
}

#[derive(Debug, Clone)]
pub struct StringTable {
    pub buffer: Str,
    pub symtab: Option<Str>,
    pub index: List<u32>,
    pub packed_index: bool,
}

#[derive(Debug, Clone)]

pub struct InodeSizeCache {
    pub lookup: Map<u32, u64>,
    pub min_chunk_count: u64,
}

impl<'a, T: FromRaw<'a>, U: From<T>> From<super::List<'a, T>> for Vec<U> {
    fn from(v: super::List<'a, T>) -> Self {
        v.into_iter().map(|e| e.into()).collect()
    }
}

impl<'a, T: FromRaw<'a>, U: From<T> + Ord> From<super::Set<'a, T>> for BTreeSet<U> {
    fn from(v: super::Set<'a, T>) -> Self {
        v.into_iter().map(Into::into).collect()
    }
}

impl<'a, K1, V1, K2, V2> From<super::Map<'a, K1, V1>> for BTreeMap<K2, V2>
where
    K1: FromRaw<'a>,
    V1: FromRaw<'a>,
    K2: From<K1> + Ord,
    V2: From<V1> + Ord,
{
    fn from(v: super::Map<'a, K1, V1>) -> Self {
        v.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
    }
}

impl From<super::Metadata<'_>> for Metadata {
    fn from(v: super::Metadata<'_>) -> Self {
        Self {
            chunks: v.chunks().into(),
            directories: v.directories().into(),
            inodes: v.inodes().into(),
            chunk_table: v.chunk_table().into(),
            entry_table: v.entry_table().into(),
            symlink_table: v.symlink_table().into(),
            uids: v.uids().into(),
            gids: v.gids().into(),
            modes: v.modes().into(),
            names: v.names().into(),
            symlinks: v.symlinks().into(),
            timestamp_base: v.timestamp_base(),
            chunk_inode_offset: v.chunk_inode_offset(),
            link_inode_offset: v.link_inode_offset(),
            block_size: v.block_size(),
            total_fs_size: v.total_fs_size(),
            devices: v.devices().map(Into::into),
            options: v.options().map(Into::into),
            dir_entries: v.dir_entries().map(Into::into),
            shared_files_table: v.shared_files_table().map(Into::into),
            total_hardlink_size: v.total_hardlink_size(),
            dwarfs_version: v.dwarfs_version().map(Into::into),
            create_timestamp: v.create_timestamp(),
            compact_names: v.compact_names().map(Into::into),
            compact_symlinks: v.compact_symlinks().map(Into::into),
            preferred_path_separator: v.preferred_path_separator(),
            features: v.features().map(Into::into),
            category_names: v.category_names().map(Into::into),
            block_categories: v.block_categories().map(Into::into),
            reg_file_size_cache: v.reg_file_size_cache().map(Into::into),
        }
    }
}

impl From<super::Chunk<'_>> for Chunk {
    fn from(v: super::Chunk<'_>) -> Self {
        Self {
            block: v.block(),
            offset: v.offset(),
            size: v.size(),
        }
    }
}

impl From<super::Directory<'_>> for Directory {
    fn from(v: super::Directory<'_>) -> Self {
        Self {
            parent_entry: v.parent_entry(),
            first_entry: v.first_entry(),
            self_entry: v.self_entry(),
        }
    }
}

impl From<super::InodeData<'_>> for InodeData {
    fn from(v: super::InodeData<'_>) -> Self {
        Self {
            mode_index: v.mode_index(),
            owner_index: v.owner_index(),
            group_index: v.group_index(),
            atime_offset: v.atime_offset(),
            mtime_offset: v.mtime_offset(),
            ctime_offset: v.ctime_offset(),
            name_index: v.name_index(),
            inode: v.inode(),
        }
    }
}

impl From<super::DirEntry<'_>> for DirEntry {
    fn from(v: super::DirEntry<'_>) -> Self {
        Self {
            name_index: v.name_index(),
            inode_num: v.inode_num(),
        }
    }
}

impl From<super::FsOptions<'_>> for FsOptions {
    fn from(v: super::FsOptions<'_>) -> Self {
        Self {
            mtime_only: v.mtime_only(),
            time_resolution_sec: v.time_resolution_sec(),
            packed_chunk_table: v.packed_chunk_table(),
            packed_directories: v.packed_directories(),
            packed_shared_files_table: v.packed_shared_files_table(),
        }
    }
}

impl From<super::StringTable<'_>> for StringTable {
    fn from(v: super::StringTable<'_>) -> Self {
        Self {
            buffer: v.buffer().into(),
            symtab: v.symtab().map(Into::into),
            index: v.index().into(),
            packed_index: v.packed_index(),
        }
    }
}

impl From<super::InodeSizeCache<'_>> for InodeSizeCache {
    fn from(v: super::InodeSizeCache<'_>) -> Self {
        Self {
            lookup: v.lookup().into(),
            min_chunk_count: v.min_chunk_count(),
        }
    }
}
