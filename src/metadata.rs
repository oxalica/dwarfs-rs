//! See: <https://github.com/mhx/dwarfs/blob/v0.12.3/thrift/metadata.thrift>
use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Serialize, de};

use self::frozen::{FromRaw, Offset, ResultExt as _, Source, Str};

mod frozen;
mod serde_thrift;
pub mod unpacked;

#[cfg(test)]
mod tests;

pub use frozen::{List, ListIter, Map, MapIter, Set, SetIter};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct Error(Box<str>);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

/// A dense map of i16 -> T, stored as `Vec<Option<T>>`.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct VecMap<T>(pub Vec<Option<T>>);

impl<T: fmt::Debug> fmt::Debug for VecMap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.0
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, elem)| Some((idx, elem.as_ref()?))),
            )
            .finish()
    }
}

impl<'de, T: de::Deserialize<'de>> de::Deserialize<'de> for VecMap<T> {
    fn deserialize<D: de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: de::Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = VecMap<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a dense map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                // Keys start at 1.
                let len = map.size_hint().unwrap_or(0) + 1;
                let mut vecmap = Vec::with_capacity(len);
                while let Some((k, v)) = map.next_entry::<i16, T>()? {
                    let k = usize::try_from(k).map_err(|_| {
                        de::Error::invalid_value(
                            de::Unexpected::Signed(k.into()),
                            &"an unsigned dense map key",
                        )
                    })?;
                    if vecmap.len() <= k {
                        vecmap.resize_with(k + 1, || None);
                    }
                    vecmap[k] = Some(v);
                }
                Ok(VecMap(vecmap))
            }
        }

        de.deserialize_map(Visitor::<T>(PhantomData))
    }
}

impl<T: Serialize> Serialize for VecMap<T> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let size = self.iter().count();
        let mut ser = ser.serialize_map(Some(size))?;
        for (k, v) in self.iter() {
            ser.serialize_entry(&k, v)?;
        }
        ser.end()
    }
}

impl<T> std::ops::Index<i16> for VecMap<T> {
    type Output = T;

    fn index(&self, index: i16) -> &Self::Output {
        self.get(index).expect("index out of bound")
    }
}

impl<T> VecMap<T> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, i: i16) -> Option<&T> {
        self.0.get(usize::try_from(i).ok()?)?.as_ref()
    }

    fn iter(&self) -> impl Iterator<Item = (i16, &T)> + use<'_, T> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(k, v)| Some((k as i16, v.as_ref()?)))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Schema {
    // NB. Field order matters for ser/de impl.
    #[serde(default, skip_serializing_if = "is_default")]
    pub relax_type_checks: bool,
    pub layouts: VecMap<SchemaLayout>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub root_layout: i16,
    #[serde(default, skip_serializing_if = "is_default")]
    pub file_version: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SchemaLayout {
    // NB. Field order matters for ser/de impl.
    #[serde(default, skip_serializing_if = "is_default")]
    pub size: i32,
    #[serde(default, skip_serializing_if = "is_default")]
    pub bits: i16,
    pub fields: VecMap<SchemaField>,
    pub type_name: String,
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SchemaField {
    // NB. Field order matters for ser/de impl.
    pub layout_id: i16,
    #[serde(default, skip_serializing_if = "is_default")]
    pub offset: i16,
}

impl SchemaField {
    fn offset_bits(&self) -> u16 {
        let o = self.offset;
        if o >= 0 { o as u16 * 8 } else { (-o) as u16 }
    }
}

impl Schema {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let this = serde_thrift::deserialize_struct::<Self>(input)
            .map_err(|err| Error(format!("failed to parse schema: {err}").into()))?;
        this.validate()?;
        Ok(this)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_thrift::serialize_struct(self)
            .map_err(|err| Error(format!("failed to serialize schema: {err}").into()))
    }

    fn validate(&self) -> Result<()> {
        self.validate_inner()
            .map_err(|msg| Error(msg.into_boxed_str()))
    }

    fn validate_inner(&self) -> Result<(), String> {
        const FILE_VERSION: i32 = 1;

        if self.file_version != FILE_VERSION {
            return Err(format!(
                "unsupported schema file_version {:?}",
                self.file_version
            ));
        }
        if self.layouts.get(self.root_layout).is_none() {
            return Err("missing root_layout".into());
        }

        for (layout_id, layout) in self.layouts.iter() {
            if layout.fields.is_empty() && layout.bits > 64 {
                return Err(format!(
                    "layout {}: primitive type is too large to have {}bits",
                    layout_id, layout.bits,
                ));
            }

            for (field_id, field) in layout.fields.iter() {
                (|| -> Result<(), &str> {
                    let field_layout = self
                        .layouts
                        .get(field.layout_id)
                        .ok_or("layout index out of range")?;
                    let bit_offset = if field.offset >= 0 {
                        field.offset.checked_mul(8)
                    } else {
                        field.offset.checked_neg()
                    };
                    if field_layout.bits < 0 {
                        return Err("layout bits cannot be negative");
                    }
                    let bit_total_size = bit_offset
                        .and_then(|off| (off as u16).checked_add(field_layout.bits as u16));
                    bit_total_size.ok_or("offset overflows")?;
                    Ok(())
                })()
                .map_err(|err| format!("field {field_id} of layout {layout_id}: {err}"))?;
            }
        }

        Ok(())
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
                fn load(src: Source<$a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self, frozen::Error> {
                    Ok(Self {
                        $($field: src.load_field(base_bit, layout, $field_id)
                            .context(concat!(stringify!($name), ".", stringify!($field)))?,)*
                        _marker: PhantomData,
                    })
                }

                fn empty(src: Source<$a>) -> Self {
                    Self {
                        $($field: FromRaw::empty(src),)*
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
    pub fn parse(schema: &'a Schema, bytes: &'a [u8]) -> Result<Self> {
        if cfg!(debug_assertions) {
            schema.validate().expect("invalid schema");
        }

        let src = Source { schema, bytes };
        let layout = &src.schema.layouts[src.schema.root_layout];
        src.load(0, layout)
            .map_err(|err| Error(err.to_string().into_boxed_str()))
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
        [pub] features: Option<Set<'a, Str<'a>>> = 27,
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
