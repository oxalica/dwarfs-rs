//! See: <https://github.com/mhx/dwarfs/blob/v0.12.3/thrift/metadata.thrift>
use std::{fmt, marker::PhantomData};

use self::frozen::{FromRaw, Source, Str};
use self::schema::SchemaLayout;
use crate::{Error, Result};

mod frozen;
mod schema;

pub use self::frozen::{List, ListIter, Map};

pub struct Schema(schema::Schema);

impl fmt::Debug for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Schema {
    pub fn parse(src: &[u8]) -> Result<Self> {
        schema::parse_schema(src)
            .map(Self)
            .map_err(|_| Error::InvalidSchema)
    }
}

macro_rules! define_value_struct {
    (__getter [] $($tt:tt)*) => {};
    (__getter [$vis:vis] [$($meta:tt)*] $($tt:tt)*) => {
        $($meta)*
        $vis $($tt)*
    };
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident<$a:lifetime> {
            $(
                $(#[$field_meta:meta])*
                $([$getter_vis:tt])?
                $field:ident : $field_ty:ty = $field_id:literal,
            )*
        }
    )*) => {
        $(
            $(#[$meta])*
            $vis struct $name<$a> {
                $($field : $field_ty,)*
                _marker: PhantomData<&$a [u8]>,
            }

            impl<$a> FromRaw<$a> for $name<$a> {
                fn load(src: &Source<$a>, base_bit: u64, layout: &SchemaLayout) -> Self {
                    Self {
                        $($field: src.load_field(base_bit, layout, $field_id),)*
                        _marker: PhantomData,
                    }
                }

                fn from_empty(src: &Source<$a>) -> Self {
                    Self {
                        $($field: FromRaw::from_empty(src),)*
                        _marker: PhantomData,
                    }
                }
            }

            impl<$a> $name<$a> {
                $(define_value_struct! {
                    __getter
                    [$($getter_vis)?]
                    [$(#[$field_meta])*]
                    fn $field(&self) -> $field_ty {
                        self.$field
                    }
                })*
            }
        )*
    };
}

impl<'a> Metadata<'a> {
    pub fn parse(schema: &'a Schema, bytes: &'a [u8]) -> Self {
        // FIXME: Validate this.
        let src = Source {
            schema: &schema.0,
            bytes,
        };
        let layout = &src.schema[src.schema.root_layout];
        src.load(0, layout)
    }
}

define_value_struct! {
    #[derive(Debug)]
    pub struct Metadata<'a> {
        [pub] chunks: List<'a, Chunk<'a>> = 1,
        [pub] directories: List<'a, Directory<'a>> = 2,
        [pub] inodes: List<'a, InodeData<'a>> = 3,
        [pub] chunk_table: List<'a, u32> = 4,
        #[deprecated = "deprecated since dwarfs 2.3"]
        [pub] entry_table: List<'a, u32> = 5,
        [pub] symlink_table: List<'a, u32> = 6,
        [pub] uids: List<'a, u32> = 7,
        [pub] gids: List<'a, u32> = 8,
        [pub] modes: List<'a, u32> = 9,
        [pub] names: List<'a, Str<'a>> = 10,
        [pub] symlinks: List<'a, Str<'a>> = 11,
        [pub] timestamp_base: u64 = 12,
        [pub] chunk_inode_offset: u32 = 13,
        [pub] link_inode_offset: u32 = 14,
        [pub] block_size: u32 = 15,
        [pub] total_fs_size: u64 = 16,
        [pub] devices: Option<List<'a, u64>> = 17,

        [pub] options: Option<FsOptions<'a>> = 18,
        [pub] dir_entries: Option<List<'a, DirEntry<'a>>> = 19,
        [pub] shared_files_table: Option<List<'a, u32>> = 20,
        [pub] total_hardlink_size: Option<u64> = 21,
        [pub] dwarfs_version: Option<Str<'a>> = 22,
        [pub] create_timestamp: Option<u64> = 23,
        [pub] compact_names: Option<StringTable<'a>> = 24,
        [pub] compact_symlinks: Option<StringTable<'a>> = 25,
        [pub] preferred_path_separator: Option<u32> = 26,
        // features: Option<Set> = 27, // I don't know the layout of Set, because there is currently no features.
        [pub] category_names: Option<List<'a, Str<'a>>> = 28,
        [pub] block_categories: Option<List<'a, Str<'a>>> = 29,
        [pub] reg_file_size_cache: Option<InodeSizeCache<'a>> = 30,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Chunk<'a> {
        [pub] block: u32 = 1,
        [pub] offset: u32 = 2,
        [pub] size: u32 = 3,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Directory<'a> {
        [pub] parent_entry: u32 = 1,
        [pub] first_entry: u32 = 2,
        [pub] self_entry: u32 = 3,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct InodeData<'a> {
        [pub] mode_index: u32 = 2,
        [pub] owner_index: u32 = 4,
        [pub] group_index: u32 = 5,
        [pub] atime_offset: u32 = 6,
        [pub] mtime_offset: u32 = 7,
        [pub] ctime_offset: u32 = 8,

        #[deprecated = "deprecated since dwarfs 2.3"]
        [pub] name_index: u32 = 1,
        #[deprecated = "deprecated since dwarfs 2.3"]
        [pub] inode: u32 = 3,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct DirEntry<'a> {
        [pub] name_index: u32 = 1,
        [pub] inode_num: u32 = 2,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct FsOptions<'a> {
        [pub] mtime_only: bool = 1,
        [pub] time_resolution_sec: Option<u32> = 2,
        [pub] packed_chunk_table: bool = 3,
        [pub] packed_directories: bool = 4,
        [pub] packed_shared_files_table: bool = 5,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct StringTable<'a> {
        [pub] buffer: Str<'a> = 1,
        [pub] symtab: Option<Str<'a>> = 2,
        [pub] index: List<'a, u32> = 3,
        [pub] packed_index: bool = 4,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct InodeSizeCache<'a> {
        [pub] lookup: Map<'a, u32, u64> = 1,
        [pub] min_chunk_count: u64 = 2,
    }
}
