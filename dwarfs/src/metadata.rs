//! The low-level metadata structures and parsers.
//!
//! The parsed [`Metadata`] and [`Schema`] is given as-is from the underlying
//! structure without additional modification. Notably, for `Metadata`, no
//! unpacking is performed, no value validation is performed, and only binary
//! syntax and structure are validated.
//!
//! For high-level access of the image hierarchy and content, use
//! [`Archive`][crate::Archive] instead.
//!
//! See upstream documentations for the meaning of structs and fields:
//!
//! - Metadata definition: <https://github.com/mhx/dwarfs/blob/v0.12.4/thrift/metadata.thrift>
//!
//! - Frozen schema definition: <https://github.com/facebook/fbthrift/blob/2f5415eed3a4981b5b1535a504a76b9309834a90/thrift/lib/thrift/frozen.thrift>
//!   
//!   Typically, users should treat [`Schema`] as an opaque type, because the
//!   definition in this crate is specialized only for [`Metadata::parse`].
use std::{borrow::Borrow, fmt, marker::PhantomData, ops};

use bstr::BString;
use serde::{Deserialize, Serialize, de};

mod serde_frozen;
mod serde_thrift;

#[cfg(test)]
mod tests;

type Result<T, E = Error> = std::result::Result<T, E>;

/// An error raised from parsing schema or metadata.
#[derive(Debug)]
pub struct Error(Box<str>);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

/// A dense map of i16 -> T, stored as `Vec<Option<T>>` for quick indexing.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct DenseMap<T>(pub Vec<Option<T>>);

impl<T: fmt::Debug> fmt::Debug for DenseMap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'de, T: de::Deserialize<'de>> de::Deserialize<'de> for DenseMap<T> {
    fn deserialize<D: de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: de::Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = DenseMap<T>;

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
                Ok(DenseMap(vecmap))
            }
        }

        de.deserialize_map(Visitor::<T>(PhantomData))
    }
}

impl<T: Serialize> Serialize for DenseMap<T> {
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

impl<T> ops::Index<i16> for DenseMap<T> {
    type Output = T;

    fn index(&self, index: i16) -> &Self::Output {
        self.get(index).expect("index out of bound")
    }
}

impl<T> DenseMap<T> {
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

/// The Frozen schema. You should treat this type as opaque.
///
/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Schema {
    // NB. Field order matters for ser/de impl.
    #[serde(default, skip_serializing_if = "is_default")]
    pub relax_type_checks: bool,
    pub layouts: DenseMap<SchemaLayout>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub root_layout: i16,
    #[serde(default, skip_serializing_if = "is_default")]
    pub file_version: i32,
}

/// You should treat this type as opaque.
///
/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SchemaLayout {
    // NB. Field order matters for ser/de impl.
    #[serde(default, skip_serializing_if = "is_default")]
    pub size: i32,
    #[serde(default, skip_serializing_if = "is_default")]
    pub bits: i16,
    pub fields: DenseMap<SchemaField>,
    pub type_name: String,
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// You should treat this type as opaque.
///
/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
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
    /// Parse the schema from the on-disk serialized from
    /// ([`SectionType::METADATA_V2_SCHEMA`](crate::section::SectionType::METADATA_V2_SCHEMA)),
    /// and validate basic invariants.
    ///
    /// The schema type and parser are specialized for [`Metadata::parse`]. It
    /// should not be used for Frozen schema of other data structures.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let this = serde_thrift::deserialize_struct::<Self>(input)
            .map_err(|err| Error(format!("failed to parse schema: {err}").into()))?;
        this.validate()?;
        Ok(this)
    }

    /// Serialize the schema to on-disk bytes, does the reverse of [`Schema::parse`].
    ///
    /// Note that the serialization format is not canonical, so
    /// `Schema::parse(bytes)?.to_bytes() == bytes` may NOT hold.
    /// However, this function alone is reproducible and the result is
    /// revertible, that means:
    ///
    /// - If `schema1 == schema2`, then `schema1.to_bytes()? == schema2.to_bytes()?`
    /// - `Schema::parse(schema.to_bytes()?)? == schema`
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

/// A wrapper of a `Vec<T>` representing a ordered set of ascending `T`.
#[derive(Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct OrderedSet<T>(pub Vec<T>);

impl<T: fmt::Debug> fmt::Debug for OrderedSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(&self.0).finish()
    }
}

impl<T> OrderedSet<T> {
    /// Returns the number of elements in the underlying `Vec`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the underlying `Vec` contains no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return true if the underlying `Vec` contains `value`.
    ///
    /// This uses binary search and the underlying `Vec` must be sorted by
    /// ascending `T`, otherwise, it will return an unspecified result but will
    /// not panic.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.0
            .binary_search_by(|probe| Ord::cmp(probe.borrow(), value))
            .is_ok()
    }
}

/// A wrapper of a `Vec<(K, V)>` representing a ordered map of ascending key `K`.
#[derive(Default, Clone, PartialEq)]
pub struct OrderedMap<K, V>(pub Vec<(K, V)>);

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for OrderedMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

impl<'de, K: Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de> for OrderedMap<K, V> {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor<K, V>(PhantomData<(K, V)>);

        impl<'de, K: Deserialize<'de>, V: Deserialize<'de>> de::Visitor<'de> for Visitor<K, V> {
            type Value = OrderedMap<K, V>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut v = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(pair) = map.next_entry()? {
                    v.push(pair);
                }
                Ok(OrderedMap(v))
            }
        }

        de.deserialize_map(Visitor::<K, V>(PhantomData))
    }
}

impl<K: Serialize, V: Serialize> Serialize for OrderedMap<K, V> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.collect_map(self.0.iter().map(|(k, v)| (k, v)))
    }
}

impl<K, V> OrderedMap<K, V> {
    /// Returns the number of elements in the underlying `Vec`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the underlying `Vec` contains no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Search and get the `value` corresponding to `key` in the map.
    ///
    /// This uses binary search and the underlying `Vec` must be sorted by
    /// ascending `K`, otherwise, it will return an unspecified result but will
    /// not panic.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let i = self
            .0
            .binary_search_by(|(probe, _)| Ord::cmp(probe.borrow(), key))
            .ok()?;
        Some(&self.0[i].1)
    }
}

impl Metadata {
    /// Parse the metadata from on-disk serialized form
    /// ([`SectionType::METADATA_V2`](crate::section::SectionType::METADATA_V2)),
    /// using layout defined by the given schema.
    pub fn parse(schema: &Schema, bytes: &[u8]) -> Result<Self> {
        serde_frozen::deserialize(schema, bytes)
            .map_err(|err| Error(format!("failed to parse metadata: {err}").into()))
    }
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct Metadata {
    // NB. Field order matters for ser/de impl.
    // #1
    pub chunks: Vec<Chunk>,
    pub directories: Vec<Directory>,
    pub inodes: Vec<InodeData>,
    pub chunk_table: Vec<u32>,
    #[deprecated = "deprecated since dwarfs 2.3"]
    pub entry_table: Vec<u32>,
    pub symlink_table: Vec<u32>,
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
    pub modes: Vec<u32>,
    pub names: Vec<BString>,
    pub symlinks: Vec<BString>,
    pub timestamp_base: u64,

    // #13
    pub chunk_inode_offset: u32,
    pub link_inode_offset: u32,

    // #15
    pub block_size: u32,
    pub total_fs_size: u64,

    // #17
    pub devices: Option<Vec<u64>>,
    pub options: Option<FsOptions>,

    // #19
    pub dir_entries: Option<Vec<DirEntry>>,
    pub shared_files_table: Option<Vec<u32>>,
    pub total_hardlink_size: Option<u64>,
    pub dwarfs_version: Option<BString>,
    pub create_timestamp: Option<u64>,
    pub compact_names: Option<StringTable>,
    pub compact_symlinks: Option<StringTable>,

    // #26
    pub preferred_path_separator: Option<u32>,
    pub features: Option<OrderedSet<BString>>,
    pub category_names: Option<Vec<BString>>,
    pub block_categories: Option<Vec<BString>>,
    // pub reg_file_size_cache: Option<InodeSizeCache>,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct Chunk {
    // NB. Field order matters for ser/de impl.
    pub block: u32,
    pub offset: u32,
    pub size: u32,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct Directory {
    // NB. Field order matters for ser/de impl.
    pub parent_entry: u32,
    pub first_entry: u32,
    pub self_entry: u32,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct InodeData {
    // NB. Field order matters for ser/de impl.
    #[deprecated = "deprecated since dwarfs 2.3"]
    pub name_index: u32,
    pub mode_index: u32,
    #[deprecated = "deprecated since dwarfs 2.3"]
    pub inode: u32,
    pub owner_index: u32,
    pub group_index: u32,
    pub atime_offset: u32,
    pub mtime_offset: u32,
    pub ctime_offset: u32,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct DirEntry {
    // NB. Field order matters for ser/de impl.
    pub name_index: u32,
    pub inode_num: u32,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct FsOptions {
    // NB. Field order matters for ser/de impl.
    pub mtime_only: bool,
    pub time_resolution_sec: Option<u32>,
    pub packed_chunk_table: bool,
    pub packed_directories: bool,
    pub packed_shared_files_table: bool,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct StringTable {
    // NB. Field order matters for ser/de impl.
    pub buffer: BString,
    pub symtab: Option<BString>,
    pub index: Vec<u32>,
    pub packed_index: bool,
}

/// See [module level documentation][self] for details.
#[allow(missing_docs, reason = "users should check upstream docs")]
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(default)]
pub struct InodeSizeCache {
    // NB. Field order matters for ser/de impl.
    pub lookup: OrderedMap<u32, u64>,
    pub min_chunk_count: u64,
}
