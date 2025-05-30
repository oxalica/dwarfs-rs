//! fbthrift's Frozen2 format, a bit-compressed compact format that has
//! nothing to do with Thrift.
//!
//! Here we use serde for structure deserialization. The metadata is expected to
//! be fully unpacked in memory for performance, thus it makes little sense to
//! lazily parse it, except seeking for more trouble on invalid unread data.
//!
//! Source: <https://github.com/facebook/fbthrift/blob/4375e4b08135d06fd56399b86ef93f3e6d43017c/thrift/lib/cpp2/frozen/Frozen.h>
//!
//! There is almost no documentation about this format. The details are mostly from:
//! - Helps from Marcus Holland-Moritz <github@mhxnet.de>, who wrote some explanation
//!   and examples:
//!   <https://github.com/mhx/dwarfs/blob/63b0cc70d04a95f366399d60be66b34791762058/doc/dwarfs-format.md>
//!   
//! - Me (oxalica) reverse engineering bytes layouts in DwarFS metadata block, and
//!   comparing with the metadata dump from:
//!   `dwarfsck $imgfile -d metadata_full_dump`

use serde::{de, forward_to_deserialize_any};

use super::{Schema, SchemaLayout};

type Result<T, E = Error> = std::result::Result<T, E>;
type Error = de::value::Error;

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

pub(crate) fn deserialize<T: de::DeserializeOwned>(schema: &Schema, bytes: &[u8]) -> Result<T> {
    let root_layout = schema.layouts.get(schema.root_layout).expect("validated");
    let de = Deserializer {
        src: &Source { schema, bytes },
        layout: Some(root_layout),
        bit_offset: 0,
        storage_start: 0,
    };
    T::deserialize(de)
}

/// The input raw bytes with attached schema.
#[derive(Clone, Copy)]
struct Source<'a> {
    schema: &'a Schema,
    bytes: &'a [u8],
}

impl Source<'_> {
    /// Load 1 bits at `base_bit`, using little-endian.
    ///
    /// This assumes the input is in bound. Validation should be done on structs.
    fn load_bit(&self, base_bit: Offset) -> Result<bool> {
        let (byte_idx, bit_idx) = (to_usize(base_bit) / 8, base_bit % 8);
        let b = *self
            .bytes
            .get(byte_idx)
            .ok_or_else(|| de::Error::custom("bit location overflow"))?;
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
            return Err(de::Error::custom("bits location overflow"));
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
}

#[derive(Clone, Copy)]
struct Deserializer<'a, 'de> {
    src: &'a Source<'de>,
    layout: Option<&'de SchemaLayout>,
    bit_offset: Offset,
    storage_start: Offset,
}

impl<'de> Deserializer<'_, 'de> {
    fn field_deserializer(&self, i: i16) -> Self {
        let (layout, offset_bits) = if let Some(field) = self.layout.and_then(|l| l.fields.get(i)) {
            (
                self.src.schema.layouts.get(field.layout_id),
                field.offset_bits(),
            )
        } else {
            (None, 0)
        };
        Self {
            src: self.src,
            layout,
            bit_offset: self.bit_offset + Offset::from(offset_bits),
            storage_start: self.storage_start,
        }
    }

    fn deserialize_field<T: de::Deserialize<'de>>(&self, i: i16) -> Result<T> {
        de::Deserialize::deserialize(self.field_deserializer(i))
    }
}

impl<'de> de::Deserializer<'de> for Deserializer<'_, 'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        // Not used.
        unimplemented!()
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let b = self.layout.is_some()
            && self
                .src
                .load_bit(self.storage_start * 8 + self.bit_offset)?;
        visitor.visit_bool(b)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let Some(layout) = self.layout else {
            return visitor.visit_u64(0);
        };
        if !layout.fields.is_empty() {
            return Err(de::Error::invalid_type(
                de::Unexpected::Other("a schema layout with some fields"),
                &"an unsigned integer",
            ));
        }
        let bits = layout.bits;
        if !(0..=64).contains(&bits) {
            return Err(de::Error::custom("too many bits for an unsigned int"));
        }
        visitor.visit_u64(
            self.src
                .load_bits(self.storage_start * 8 + self.bit_offset, bits as u16)?,
        )
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let distance = self.deserialize_field::<u32>(1)?;
        let len = self.deserialize_field::<u32>(2)?;

        let content = (|| {
            let start = self.storage_start.checked_add(distance)?;
            let end = start.checked_add(len)?;
            self.src
                .bytes
                .get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
        })()
        .ok_or_else(|| <Error as de::Error>::custom("string offset or length overflow"))?;
        visitor.visit_borrowed_bytes(content)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let distance = self.deserialize_field::<u32>(1)?;
        let len = self.deserialize_field::<u32>(2)?;
        let elem_layout = self.layout.and_then(|l| {
            let id = l.fields.get(3)?.layout_id;
            Some(self.src.schema.layouts.get(id).expect("validated"))
        });
        visitor.visit_seq(CollectionDeserializer {
            elem_de: Self {
                src: self.src,
                layout: elem_layout,
                bit_offset: 0,
                storage_start: self.storage_start + distance,
            },
            len,
        })
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let distance = self.deserialize_field::<u32>(1)?;
        let len = self.deserialize_field::<u32>(2)?;
        let elem_layout = self.layout.and_then(|l| {
            let id = l.fields.get(3)?.layout_id;
            Some(self.src.schema.layouts.get(id).expect("validated"))
        });
        visitor.visit_map(CollectionDeserializer {
            elem_de: Self {
                src: self.src,
                layout: elem_layout,
                bit_offset: 0,
                storage_start: self.storage_start + distance,
            },
            len,
        })
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        if !self.deserialize_field::<bool>(1)? {
            return visitor.visit_none();
        }
        visitor.visit_some(self.field_deserializer(2))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_map(StructDeserializer {
            de: self,
            field_id: 0,
        })
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        i8 i16 i32 i64 i128 u8 u16 u128 f32 f64 char str string
        unit unit_struct newtype_struct tuple
        tuple_struct enum identifier
    }
}

struct StructDeserializer<'i, 'de> {
    de: Deserializer<'i, 'de>,
    field_id: usize,
}

impl<'de> de::MapAccess<'de> for StructDeserializer<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        let Some(layout) = self.de.layout else {
            return Ok(None);
        };

        let fields = &layout.fields.0;
        while self.field_id < fields.len() {
            if fields[self.field_id].is_some() {
                // Map 1.. to 0.. for serde.
                let serde_field_id = self.field_id as u64 - 1;
                return seed
                    .deserialize(de::value::U64Deserializer::new(serde_field_id))
                    .map(Some);
            }
            self.field_id += 1;
        }
        Ok(None)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        self.field_id += 1;
        seed.deserialize(self.de.field_deserializer(self.field_id as i16 - 1))
    }
}

struct CollectionDeserializer<'a, 'de> {
    elem_de: Deserializer<'a, 'de>,
    len: u32,
}

impl<'de> de::SeqAccess<'de> for CollectionDeserializer<'_, 'de> {
    type Error = Error;

    fn size_hint(&self) -> Option<usize> {
        self.len.try_into().ok()
    }

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: de::DeserializeSeed<'de>,
    {
        if self.len == 0 {
            return Ok(None);
        }

        let ret = seed.deserialize(self.elem_de);
        self.len -= 1;
        if let Some(layout) = self.elem_de.layout {
            self.elem_de.bit_offset += layout.bits as Offset;
        }
        ret.map(Some)
    }
}

impl<'de> de::MapAccess<'de> for CollectionDeserializer<'_, 'de> {
    type Error = Error;

    fn size_hint(&self) -> Option<usize> {
        self.len.try_into().ok()
    }

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        if self.len == 0 {
            return Ok(None);
        }
        self.len -= 1;

        seed.deserialize(self.elem_de.field_deserializer(1))
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        let ret = seed.deserialize(self.elem_de.field_deserializer(2));
        if let Some(layout) = self.elem_de.layout {
            self.elem_de.bit_offset += layout.bits as Offset;
        }
        ret
    }
}
