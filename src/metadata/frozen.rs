//! fbthrift's Frozen2 format, a bit-compressed compact format that has
//! nothing to do with Thrift.
//!
//! Source: <https://github.com/facebook/fbthrift/blob/4375e4b08135d06fd56399b86ef93f3e6d43017c/thrift/lib/cpp2/frozen/Frozen.h>
//!
//! Here we implemented a lazy parsing interface and only primitive types
//! necessary for parsing dwarfs metadata struct.
//!
//! There is almost no documentation about this format. The details are mostly from:
//! - Helps from Marcus Holland-Moritz <github@mhxnet.de>, who wrote some explanation
//!   and examples:
//!   <https://github.com/mhx/dwarfs/blob/63b0cc70d04a95f366399d60be66b34791762058/doc/dwarfs-format.md>
//!   
//! - Me (oxalica) reverse engineering bytes layouts in dwarfs metadata block, and
//!   comparing with the metadata dump from:
//!   `dwarfsck $imgfile -d metadata_full_dump`
use std::{borrow::Borrow, cmp::Ordering, fmt, marker::PhantomData, ops::Range};

use bstr::BStr;

use crate::metadata::schema::{Schema, SchemaLayout};

/// Parsable types.
pub(crate) trait FromRaw<'a>: Sized {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self;
    fn empty(src: Source<'a>) -> Self;
}

/// The input raw bytes with attached schema.
#[derive(Clone, Copy)]
pub(crate) struct Source<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) bytes: &'a [u8],
}

impl fmt::Debug for Source<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Source")
            .field("schema", &self.schema)
            .field("bytes_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Source<'a> {
    // The source is "rebased" to a separate storage region for container
    // (`List` and `Map`) elements, and all inner structure's `distance` will be
    // based on the new base location.
    // For structs, the base location is unchanged when iterating fields and
    // only bit offset is advanced.
    fn rebase(self, distance: u64) -> Self {
        Self {
            schema: self.schema,
            bytes: &self.bytes[distance as usize..],
        }
    }

    fn load_bits(&self, mut base: u64, bits: u16) -> u64 {
        debug_assert!(bits <= 64);

        // FIXME: Optimize this.
        let mut ret = 0u64;
        for i in 0..bits {
            let bit = (self.bytes[base as usize / 8] >> (base % 8)) & 1;
            ret |= (bit as u64) << i;
            base += 1;
        }
        ret
    }

    pub(crate) fn load<T: FromRaw<'a>>(self, base_bit: u64, layout: &SchemaLayout) -> T {
        FromRaw::load(self, base_bit, layout)
    }

    pub(crate) fn load_field<T: FromRaw<'a>>(
        self,
        mut base_bit: u64,
        layout: &SchemaLayout,
        field_id: u16,
    ) -> T {
        let Some(f) = layout.field(field_id) else {
            return T::empty(self);
        };
        base_bit += f.offset_bits();
        let layout = &self.schema[f.layout_id];
        self.load(base_bit, layout)
    }
}

macro_rules! impl_int_from_raw {
    ($($i:tt),* $(,)?) => {
        $(impl<'a> FromRaw<'a> for $i {
            fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
                // TODO: Error handling.
                assert!(layout.fields.is_empty());
                let v = src.load_bits(base_bit, layout.bits);
                Self::try_from(v).unwrap()
            }
            fn empty(_: Source<'a>) -> Self {
                0
            }
        })*
    };
}

impl_int_from_raw!(u8, u16, u32, u64);

impl<'a> FromRaw<'a> for bool {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        // TODO: This can be more efficient.
        u8::load(src, base_bit, layout) != 0
    }
    fn empty(_: Source<'a>) -> Self {
        false
    }
}

macro_rules! impl_tuple_from_raw {
    ($($ty:ident $idx:literal),*) => {
        impl<'a, $($ty: FromRaw<'a>),*> FromRaw<'a> for ($($ty,)*) {
            fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
                ($(src.load_field(base_bit, layout, $idx),)*)
            }
            fn empty(src: Source<'a>) -> Self {
                ($(<$ty>::empty(src),)*)
            }
        }
    };
}

impl_tuple_from_raw!(A 1);
impl_tuple_from_raw!(A 1, B 2);
impl_tuple_from_raw!(A 1, B 2, C 3);

impl<'a, T: FromRaw<'a>> FromRaw<'a> for Option<T> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        if src.load_field::<bool>(base_bit, layout, 1) {
            Some(src.load_field(base_bit, layout, 2))
        } else {
            None
        }
    }
    fn empty(_src: Source<'a>) -> Self {
        None
    }
}

/// String is expected to be in UTF-8, but it's not validated.
pub(crate) type Str<'a> = &'a BStr;

impl<'a> FromRaw<'a> for Str<'a> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        let (distance, count): (u64, u64) = src.load(base_bit, layout);
        let bytes = &src.bytes[distance as usize..][..count as usize];
        BStr::new(bytes)
    }
    fn empty(_: Source<'a>) -> Self {
        BStr::new("")
    }
}

#[derive(Clone, Copy)]
struct RawList<'a> {
    /// The rebased location for element storage.
    elem_src: Source<'a>,
    len: u64,
    elem_layout_id: u16,
    elem_bits: u16,
}

impl<'a> RawList<'a> {
    fn at<T: FromRaw<'a>>(&self, idx: usize) -> T {
        if self.elem_bits == 0 {
            return T::empty(self.elem_src);
        }
        let base_bit = idx as u64 * self.elem_bits as u64;
        let layout = &self.elem_src.schema[self.elem_layout_id];
        self.elem_src.load(base_bit, layout)
    }
}

impl<'a> FromRaw<'a> for RawList<'a> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        let (distance, count): (u64, u64) = src.load(base_bit, layout);
        let elem_layout = layout.field(3).map(|f| f.layout_id);
        let elem_bits = elem_layout.map_or(0, |lid| src.schema[lid].bits);
        Self {
            elem_src: src.rebase(distance),
            len: count,
            // Layout field is `None` if:
            // - The list is empty, then it is unused anyway.
            // - The list element type consists of zero bits, that is, all elements are 0.
            //   This case is special cased in `RawList::at` and this field is unused.
            elem_layout_id: elem_layout.unwrap_or(!0),
            elem_bits,
        }
    }

    fn empty(src: Source<'a>) -> Self {
        RawList {
            elem_src: Source {
                schema: src.schema,
                // Should not be read.
                bytes: &[],
            },
            len: 0,
            elem_layout_id: 0,
            elem_bits: 0,
        }
    }
}

/// A lazy list reference.
pub struct List<'a, T> {
    raw: RawList<'a>,
    _marker: PhantomData<T>,
}

impl<T> Copy for List<'_, T> {}
impl<T> Clone for List<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, T> fmt::Debug for List<'a, T>
where
    T: fmt::Debug + FromRaw<'a>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alt = f.alternate();
        let mut d = f.debug_struct("List");
        d.field("len", &self.raw.len)
            .field("elem_bits", &self.raw.elem_bits);
        if alt {
            d.field("elems", &self.into_iter()).finish()
        } else {
            d.finish_non_exhaustive()
        }
    }
}

impl<'a, T: FromRaw<'a>> FromRaw<'a> for List<'a, T> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        Self {
            raw: RawList::load(src, base_bit, layout),
            _marker: PhantomData,
        }
    }

    fn empty(src: Source<'a>) -> Self {
        List {
            raw: RawList::empty(src),
            _marker: PhantomData,
        }
    }
}

#[expect(private_bounds, reason = "all exposed types implement this")]
impl<'a, T: FromRaw<'a>> List<'a, T> {
    /// The number of elements in this list.
    pub fn len(&self) -> usize {
        self.raw.len as _
    }

    /// Return `true` if this list contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the element at index `idx`.
    pub fn get(&self, idx: usize) -> Option<T> {
        (idx < self.len()).then(|| self.raw.at(idx))
    }

    /// Get the element at index `idx`, or panic if it's out of bound.
    pub fn at(&self, idx: usize) -> T {
        self.get(idx).expect("index out of bound")
    }
}

/// The [`Iterator`] of [`List`].
pub struct ListIter<'a, T>(usize, List<'a, T>);

impl<T> Clone for ListIter<'_, T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}

impl<'a, T: fmt::Debug + FromRaw<'a>> fmt::Debug for ListIter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, T: FromRaw<'a>> IntoIterator for List<'a, T> {
    type IntoIter = ListIter<'a, T>;
    type Item = T;
    fn into_iter(self) -> Self::IntoIter {
        ListIter(0, self)
    }
}

// TODO: More iterator traits and functions.
impl<'a, T: FromRaw<'a>> Iterator for ListIter<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0 < self.1.len() {
            let v = self.1.raw.at(self.0);
            self.0 += 1;
            Some(v)
        } else {
            None
        }
    }
}

/// A lazy, ordered key-value map reference.
///
/// It is stored in ascending order of key `K`.
pub struct Map<'a, K, V> {
    raw: RawList<'a>,
    _marker: PhantomData<(K, V)>,
}

impl<K, V> Copy for Map<'_, K, V> {}
impl<K, V> Clone for Map<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, V> fmt::Debug for Map<'a, K, V>
where
    K: fmt::Debug + FromRaw<'a>,
    V: fmt::Debug + FromRaw<'a>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alt = f.alternate();
        let mut d = f.debug_struct("Map");
        d.field("len", &self.raw.len)
            .field("elem_bits", &self.raw.elem_bits);
        if alt {
            d.field("entries", &self.into_iter()).finish()
        } else {
            d.finish_non_exhaustive()
        }
    }
}

impl<'a, K: FromRaw<'a>, V: FromRaw<'a>> FromRaw<'a> for Map<'a, K, V> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        Self {
            raw: src.load(base_bit, layout),
            _marker: PhantomData,
        }
    }

    fn empty(src: Source<'a>) -> Self {
        Map {
            raw: RawList::empty(src),
            _marker: PhantomData,
        }
    }
}

#[expect(private_bounds, reason = "all exposed types implement this")]
impl<'a, K: FromRaw<'a>, V: FromRaw<'a>> Map<'a, K, V> {
    /// The number of elements in this map.
    pub fn len(&self) -> usize {
        self.raw.len as _
    }

    /// Return `true` if this list contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the key-value tuple at index `idx`.
    pub fn get_index_entry(&self, idx: usize) -> Option<(K, V)> {
        (idx < self.len()).then(|| self.raw.at::<(K, V)>(idx))
    }

    /// Get the key-value tuple at index `idx`, or panic if it's out of bound.
    pub fn at(&self, idx: usize) -> (K, V) {
        self.get_index_entry(idx).expect("index out of bound")
    }

    /// Returns the index of the key, if it exists in the map.
    pub fn get_index_of<Q>(&self, key: &Q) -> Option<usize>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        bisect_range_by(0..self.len(), |i| {
            Ord::cmp(self.raw.at::<(K,)>(i).0.borrow(), key)
        })
    }

    /// Returns the key-value pair corresponding to the supplied key.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let i = self.get_index_of(key)?;
        Some(self.raw.at::<(K, V)>(i))
    }

    /// Returns true if the set contains an element equal to the value.
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.get_index_of(key).is_some()
    }

    // TODO: More map methods.
}

/// The [`Iterator`] of [`Map`].
pub struct MapIter<'a, K, V>(usize, Map<'a, K, V>);

impl<K, V> Clone for MapIter<'_, K, V> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}

impl<'a, K, V> fmt::Debug for MapIter<'a, K, V>
where
    K: fmt::Debug + FromRaw<'a>,
    V: fmt::Debug + FromRaw<'a>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.clone()).finish()
    }
}

impl<'a, K: FromRaw<'a>, V: FromRaw<'a>> IntoIterator for Map<'a, K, V> {
    type IntoIter = MapIter<'a, K, V>;
    type Item = (K, V);
    fn into_iter(self) -> Self::IntoIter {
        MapIter(0, self)
    }
}

// TODO: More iterator traits and functions.
impl<'a, K: FromRaw<'a>, V: FromRaw<'a>> Iterator for MapIter<'a, K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        if self.0 < self.1.len() {
            let v = self.1.raw.at(self.0);
            self.0 += 1;
            Some(v)
        } else {
            None
        }
    }
}

/// A lazy ordered set reference.
pub struct Set<'a, T> {
    raw: RawList<'a>,
    _marker: PhantomData<T>,
}

impl<T> Copy for Set<'_, T> {}
impl<T> Clone for Set<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, T> fmt::Debug for Set<'a, T>
where
    T: fmt::Debug + FromRaw<'a>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alt = f.alternate();
        let mut d = f.debug_struct("Set");
        d.field("len", &self.raw.len)
            .field("elem_bits", &self.raw.elem_bits);
        if alt {
            d.field("elems", &self.into_iter()).finish()
        } else {
            d.finish_non_exhaustive()
        }
    }
}

impl<'a, T: FromRaw<'a>> FromRaw<'a> for Set<'a, T> {
    fn load(src: Source<'a>, base_bit: u64, layout: &SchemaLayout) -> Self {
        Self {
            raw: RawList::load(src, base_bit, layout),
            _marker: PhantomData,
        }
    }

    fn empty(src: Source<'a>) -> Self {
        Set {
            raw: RawList::empty(src),
            _marker: PhantomData,
        }
    }
}

#[expect(private_bounds, reason = "all exposed types implement this")]
impl<'a, T: FromRaw<'a>> Set<'a, T> {
    /// The number of elements in this set.
    pub fn len(&self) -> usize {
        self.raw.len as _
    }

    /// Return `true` if this set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the element at index `idx`.
    pub fn get_index(&self, idx: usize) -> Option<T> {
        (idx < self.len()).then(|| self.raw.at(idx))
    }

    /// Get the element at index `idx`, or panic if it's out of bound.
    pub fn at(&self, idx: usize) -> T {
        self.get_index(idx).expect("index out of bound")
    }

    /// Returns the index of the value, if it exists in the map.
    pub fn get_index_of<Q>(&self, value: &Q) -> Option<usize>
    where
        T: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        bisect_range_by(0..self.len(), |i| {
            Ord::cmp(self.raw.at::<T>(i).borrow(), value)
        })
    }

    /// Returns true if the set contains an element equal to the value.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.get_index_of(value).is_some()
    }
}

/// The [`Iterator`] of [`Set`].
pub struct SetIter<'a, T>(usize, Set<'a, T>);

impl<T> Clone for SetIter<'_, T> {
    fn clone(&self) -> Self {
        Self(self.0, self.1)
    }
}

impl<'a, T: fmt::Debug + FromRaw<'a>> fmt::Debug for SetIter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.clone()).finish()
    }
}

impl<'a, T: FromRaw<'a>> IntoIterator for Set<'a, T> {
    type IntoIter = SetIter<'a, T>;
    type Item = T;
    fn into_iter(self) -> Self::IntoIter {
        SetIter(0, self)
    }
}

// TODO: More iterator traits and functions.
impl<'a, T: FromRaw<'a>> Iterator for SetIter<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0 < self.1.len() {
            let v = self.1.raw.at(self.0);
            self.0 += 1;
            Some(v)
        } else {
            None
        }
    }
}

/// There is currently no binary search functions in std over a generic range.
/// This is copied from std: <https://github.com/rust-lang/rust/blob/1.86.0/library/core/src/slice/mod.rs#L2817>
/// License: MIT OR Apache-2.0
pub fn bisect_range_by<F>(range: Range<usize>, mut f: F) -> Option<usize>
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
