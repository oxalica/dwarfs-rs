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
use std::{borrow::Borrow, fmt, marker::PhantomData};

use bstr::BStr;

use crate::{
    bisect_range_by,
    metadata::{Schema, SchemaLayout},
};

/// The offset type we use to index into metadata bytes.
///
/// We expect metadata to be relatively small comparing to the actual data and
/// it's efficiently bit-packed. Assume 4GiB is enough for it.
pub(crate) type Offset = u32;

// Assert that offset -> usize never overflows.
fn to_usize(offset: Offset) -> usize {
    const _: () = assert!(size_of::<Offset>() <= size_of::<usize>());
    offset as usize
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(Box<ErrorInner>);

#[derive(Debug)]
struct ErrorInner {
    msg: &'static str,
    context: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.msg)?;
        f.write_str(&self.0.context)
    }
}

impl From<&'static str> for Error {
    #[cold]
    fn from(msg: &'static str) -> Self {
        Self(Box::new(ErrorInner {
            msg,
            context: String::new(),
        }))
    }
}

impl Error {
    #[cold]
    fn append_context(mut self, msg: impl fmt::Display) -> Self {
        use std::fmt::Write;
        write!(self.0.context, ", in {msg}").unwrap();
        self
    }
}

pub(crate) trait ResultExt<T> {
    fn context(self, msg: impl fmt::Display) -> Result<T>;
}
impl<T> ResultExt<T> for Result<T> {
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(err.append_context(msg)),
        }
    }
}

/// Parsable types.
pub(crate) trait FromRaw<'a>: Sized {
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self>;
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
    fn rebase(self, distance: Offset) -> Result<Self> {
        Ok(Self {
            schema: self.schema,
            bytes: self
                .bytes
                .get(to_usize(distance)..)
                .ok_or("distance overflow")?,
        })
    }

    /// Load 1 bits at `base_bit`, using little-endian.
    ///
    /// This assumes the input is in bound. Validation should be done on structs.
    fn load_bit(&self, base_bit: Offset) -> Result<bool> {
        let (byte_idx, bit_idx) = (to_usize(base_bit) / 8, base_bit % 8);
        let b = *self.bytes.get(byte_idx).ok_or("bit location overflow")?;
        Ok((b >> bit_idx) & 1 != 0)
    }

    /// Load `bits` bits starting at `base_bit`, using little-endian,
    /// fill upper bits as 0.
    ///
    /// This assumes the input is in bound. Validation should be done on structs.
    fn load_bits(&self, base_bit: Offset, bits: u16) -> Result<u64> {
        // Already checked by schema validation.
        debug_assert!(bits > 0);
        debug_assert!(bits <= 64);
        let (byte_idx, bit_start) = (to_usize(base_bit) / 8, base_bit as u16 % 8);
        let last_byte_idx = (base_bit + Offset::from(bits) - 1) / 8;
        if to_usize(last_byte_idx) >= self.bytes.len() {
            return Err("bits location overflow".into());
        }

        // Always load a 8-byte chunk for performance.
        let rest = &self.bytes[byte_idx..];
        let x = if rest.len() >= 8 {
            u64::from_le_bytes(rest[..8].try_into().unwrap())
        } else {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            u64::from_le_bytes(buf)
        };

        let start_and_bits = bit_start + bits;
        Ok(if start_and_bits <= 64 {
            // Simple case:
            // Bit | 63, 62, ...          1, 0 |
            //     |up_bits|  bits | bit_start |
            //             ~~~~~~~~~ target
            x << (64 - start_and_bits) >> (64 - bits)
        } else {
            // Overshooting case:
            // Bit | 71 .. 64 | 63, 62, ...          1, 0 |
            //     |     |      bits          | bit_start |
            //           ~~~~~~~~~~~~~~~~~~~~~~ target

            // We need the 9-th (idx=8) byte. This can only happen if bits >= 56.
            let overshooting_bits = start_and_bits & 63;
            let hi = u64::from(rest[8]);
            x >> bit_start | hi << (64 - overshooting_bits) >> (64 - bits)
        })
    }

    pub(crate) fn load<T: FromRaw<'a>>(self, base_bit: Offset, layout: &SchemaLayout) -> Result<T> {
        FromRaw::load(self, base_bit, layout)
    }

    pub(crate) fn load_field<T: FromRaw<'a>>(
        self,
        mut base_bit: Offset,
        layout: &SchemaLayout,
        field_id: i16,
    ) -> Result<T> {
        let Some(f) = layout.fields.get(field_id) else {
            return Ok(T::empty(self));
        };
        base_bit += Offset::from(f.offset_bits());
        let layout = &self.schema.layouts[f.layout_id];
        self.load(base_bit, layout)
    }
}

macro_rules! impl_int_from_raw {
    ($($i:tt),* $(,)?) => {
        $(impl<'a> FromRaw<'a> for $i {
            fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
                assert!(layout.fields.is_empty());
                let v = src.load_bits(base_bit, layout.bits as u16)?;
                Ok(Self::try_from(v).ok().ok_or(concat!("integer overflow for ", stringify!($i)))?)
            }
            fn empty(_: Source<'a>) -> Self {
                0
            }
        })*
    };
}

impl_int_from_raw!(u32, u64);

impl<'a> FromRaw<'a> for bool {
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        // If this bool occupies zero-bit, the field should be eliminated and
        // `FromRaw::empty` will be called instead.
        if layout.bits == 1 {
            src.load_bit(base_bit)
        } else {
            Err("invalid bit length for bool".into())
        }
    }

    fn empty(_: Source<'a>) -> Self {
        false
    }
}

macro_rules! impl_tuple_from_raw {
    ($($ty:ident $idx:literal),*) => {
        impl<'a, $($ty: FromRaw<'a>),*> FromRaw<'a> for ($($ty,)*) {
            fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
                Ok((
                    $(src.load_field(base_bit, layout, $idx)
                        .context(concat!("tuple field ", stringify!($idx)))?,)*
                ))
            }
            fn empty(src: Source<'a>) -> Self {
                ($(<$ty>::empty(src),)*)
            }
        }
    };
}

impl_tuple_from_raw!(A 1);
impl_tuple_from_raw!(A 1, B 2);

impl<'a, T: FromRaw<'a>> FromRaw<'a> for Option<T> {
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        let is_some = src
            .load_field::<bool>(base_bit, layout, 1)
            .context("discriminant of optional")?;
        Ok(if is_some {
            Some(src.load_field(base_bit, layout, 2).context("optional")?)
        } else {
            None
        })
    }
    fn empty(_src: Source<'a>) -> Self {
        None
    }
}

/// String is expected to be in UTF-8, but it's not validated.
pub(crate) type Str<'a> = &'a BStr;

impl<'a> FromRaw<'a> for Str<'a> {
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        let (distance, count) = src.load::<(Offset, Offset)>(base_bit, layout)?;
        let content = src
            .rebase(distance)?
            .bytes
            .get(..to_usize(count))
            .ok_or("string length overflow")?;
        Ok(BStr::new(content))
    }

    fn empty(_: Source<'a>) -> Self {
        BStr::new("")
    }
}

#[derive(Clone, Copy)]
struct RawList<'a> {
    /// The rebased location for element storage.
    elem_src: Source<'a>,
    len: Offset,
    elem_layout_id: i16,
    elem_bits: u16,
}

impl<'a> RawList<'a> {
    fn load_validated<T: FromRaw<'a>>(
        src: Source<'a>,
        base_bit: Offset,
        layout: &SchemaLayout,
    ) -> Result<Self> {
        let this = Self::load(src, base_bit, layout)?;
        for i in 0..this.len() {
            this.try_at::<T>(i).context(format_args!("list[{i}]"))?;
        }
        Ok(this)
    }

    fn len(&self) -> usize {
        to_usize(self.len)
    }

    fn try_at<T: FromRaw<'a>>(&self, idx: usize) -> Result<T> {
        if self.elem_bits == 0 {
            return Ok(T::empty(self.elem_src));
        }
        // We already checked this does not overflow in `RawList::load`.
        let base_bit = (idx as Offset) * Offset::from(self.elem_bits);
        let layout = &self.elem_src.schema.layouts[self.elem_layout_id];
        self.elem_src.load(base_bit, layout)
    }

    fn at<T: FromRaw<'a>>(&self, idx: usize) -> T {
        self.try_at(idx).expect("validated")
    }
}

impl<'a> FromRaw<'a> for RawList<'a> {
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        let (distance, count) = src.load::<(Offset, Offset)>(base_bit, layout)?;
        let elem_layout_id = layout.fields.get(3).map(|f| f.layout_id);
        let elem_src = src.rebase(distance)?;
        let elem_bits = elem_layout_id.map_or(0, |lid| src.schema.layouts[lid].bits as u16);
        Offset::from(elem_bits)
            .checked_mul(count)
            .filter(|&bit_len| to_usize(bit_len.div_ceil(8)) <= elem_src.bytes.len())
            .ok_or("list bit length overflow")?;

        Ok(Self {
            elem_src,
            len: count,
            // Layout field is `None` if:
            // - The list is empty, then it is unused anyway.
            // - The list element type consists of zero bits, that is, all elements are 0.
            //   This case is special cased in `RawList::at` and this field is unused.
            elem_layout_id: elem_layout_id.unwrap_or(!0),
            elem_bits,
        })
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
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        Ok(Self {
            raw: RawList::load_validated::<T>(src, base_bit, layout)?,
            _marker: PhantomData,
        })
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
        self.raw.len()
    }

    /// Return `true` if this list contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the element at index `idx`.
    pub fn get(&self, idx: usize) -> Option<T> {
        (idx < self.len()).then(|| self.raw.at::<T>(idx))
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
            let v = self.1.raw.at::<T>(self.0);
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
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        Ok(Self {
            raw: RawList::load_validated::<(K, V)>(src, base_bit, layout)?,
            _marker: PhantomData,
        })
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
        self.raw.len()
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
    fn load(src: Source<'a>, base_bit: Offset, layout: &SchemaLayout) -> Result<Self> {
        Ok(Self {
            raw: RawList::load_validated::<T>(src, base_bit, layout)?,
            _marker: PhantomData,
        })
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
        self.raw.len()
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
