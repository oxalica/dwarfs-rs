//! Dwarven thrift, with fbthrift flavor.
//!
//! This implements just enough features to handle DwarFS schema type (Frozen 2 schema).
//! It is and will never be standard compliant.
//! Supported types: struct, map, string, bool, i16, i32, u32 (map/string length).
//!
//! Currently it will reject unsupported types thus is not future-proof. I'm not
//! expecting it to change in the near future and DwarFS, as an on disk format,
//! should not eagerly update its Frozen dependency.
//!
//! Frozen 2 schema: <https://github.com/facebook/fbthrift/blob/5a7214411bfb184c176c437f67c199d4fd50de02/thrift/lib/thrift/frozen.thrift>
//!
//! Thrift-compact spec: <https://github.com/apache/thrift/blob/master/doc/specs/thrift-compact-protocol.md>
//! NB. fbthrift has different handling of varints which seems to be not incompatible with Apache Thrift.
use serde::{de, forward_to_deserialize_any, ser};

type Result<T, E = Error> = std::result::Result<T, E>;
type Error = de::value::Error;

pub(crate) fn deserialize_struct<T: de::DeserializeOwned>(input: &[u8]) -> Result<T> {
    let mut de = ValueDeserializer {
        rest: input,
        typ: Tag::Struct,
    };
    let v = T::deserialize(&mut de)?;
    if !de.rest.is_empty() {
        return Err(de::Error::custom(format_args!(
            "unexpected trailing bytes at {}",
            input.len() - de.rest.len(),
        )));
    }
    Ok(v)
}

pub(crate) fn serialize_struct<T: ser::Serialize>(input: &T) -> Result<Vec<u8>> {
    // TODO: Set a good default capacity here.
    let mut out = Vec::new();
    input.serialize(ValueSerializer {
        w: &mut out,
        inline_bool: false,
    })?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    BoolTrue = 1,
    BoolFalse = 2,
    I16 = 4,
    I32 = 5,
    Binary = 8,
    Map = 11,
    Struct = 12,

    // Pseudo tags.
    UnknownBool = 0,
    Invalid = 15,
}

impl Tag {
    fn without_inline_bool(self) -> Self {
        if let Self::BoolTrue | Self::BoolFalse = self {
            Self::UnknownBool
        } else {
            self
        }
    }
}

impl TryFrom<u8> for Tag {
    type Error = Error;

    fn try_from(typ: u8) -> Result<Self> {
        Ok(match typ {
            1 => Tag::BoolTrue,
            2 => Tag::BoolFalse,
            // 3: i8
            4 => Tag::I16,
            5 => Tag::I32,
            // 6: i64
            // 7: double
            8 => Tag::Binary,
            // 9: list
            // 10: set
            11 => Tag::Map,
            12 => Tag::Struct,
            // 13: float
            _ => {
                return Err(de::Error::custom(format_args!(
                    "invalid or unsupported type tag: {typ:#x}"
                )));
            }
        })
    }
}

struct ValueDeserializer<'de> {
    rest: &'de [u8],
    typ: Tag,
}

impl<'de> ValueDeserializer<'de> {
    fn eat_byte(&mut self) -> Result<u8> {
        let (&fst, rest) = self
            .rest
            .split_first()
            .ok_or_else(|| de::Error::custom("unexpected EOF"))?;
        self.rest = rest;
        Ok(fst)
    }

    fn eat_varint(&mut self) -> Result<u32> {
        let mut x = 0u32;
        for i in 0..5 {
            let b = self.eat_byte()?;
            x += u32::from(b & 0x7F) << (i * 7);
            if b & 0x80 == 0 {
                return Ok(x);
            }
        }
        Err(de::Error::custom("encoded varint is too long"))
    }

    fn eat_zigzag(&mut self) -> Result<i32> {
        let x = self.eat_varint()?;
        Ok((x >> 1) as i32 ^ -(x as i32 & 1))
    }
}

impl<'de> de::Deserializer<'de> for &mut ValueDeserializer<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.typ {
            Tag::UnknownBool => visitor.visit_bool(match self.eat_byte()? {
                1 => true,
                2 => false,
                x => {
                    return Err(de::Error::custom(format_args!(
                        "invalid value for bool: {x:#x}"
                    )));
                }
            }),
            Tag::BoolTrue => visitor.visit_bool(true),
            Tag::BoolFalse => visitor.visit_bool(false),
            Tag::I16 | Tag::I32 => visitor.visit_i32(self.eat_zigzag()?),
            Tag::Binary => {
                let len = self.eat_varint()?;
                // If overflows, it will fail on next slicing anyway.
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                let (data, rest) = self
                    .rest
                    .split_at_checked(len)
                    .ok_or_else(|| de::Error::custom("input data is too short"))?;
                self.rest = rest;
                visitor.visit_borrowed_bytes(data)
            }
            Tag::Map => {
                let len = self.eat_varint()?;
                let (ktype, vtype) = if len == 0 {
                    (Tag::Invalid, Tag::Invalid)
                } else {
                    let typ = self.eat_byte()?;
                    let ktype = Tag::try_from(typ >> 4)?.without_inline_bool();
                    let vtype = Tag::try_from(typ & 0xF)?.without_inline_bool();
                    (ktype, vtype)
                };
                visitor.visit_map(MapDeserializer {
                    de: self,
                    len,
                    ktype,
                    vtype,
                })
            }
            Tag::Struct => visitor.visit_map(StructDeserializer {
                de: self,
                field_id: 0,
                value_type: Tag::Invalid,
            }),

            Tag::Invalid => unreachable!(),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct StructDeserializer<'a, 'de> {
    de: &'a mut ValueDeserializer<'de>,
    field_id: i16,
    value_type: Tag,
}

impl<'de> de::MapAccess<'de> for StructDeserializer<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        let b = self.de.eat_byte()?;
        if b == 0 {
            return Ok(None);
        }

        let id_delta = i16::from(b >> 4);
        self.field_id = if id_delta != 0 {
            self.field_id.checked_add(id_delta)
        } else {
            i16::try_from(self.de.eat_zigzag()?).ok()
        }
        .ok_or_else(|| de::Error::custom("field id overflow"))?;

        self.value_type = Tag::try_from(b & 0xF)?;

        // Map range 1.. to 0.. for serde.
        let field_id = (self.field_id - 1) as i64 as u64;
        seed.deserialize(de::value::U64Deserializer::new(field_id))
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        let prev_typ = std::mem::replace(&mut self.de.typ, self.value_type);
        let v = seed.deserialize(&mut *self.de);
        self.de.typ = prev_typ;
        v
    }
}

struct MapDeserializer<'a, 'de> {
    de: &'a mut ValueDeserializer<'de>,
    len: u32,
    ktype: Tag,
    vtype: Tag,
}

impl<'de> de::MapAccess<'de> for MapDeserializer<'_, 'de> {
    type Error = Error;

    fn size_hint(&self) -> Option<usize> {
        usize::try_from(self.len).ok()
    }

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        if self.len == 0 {
            return Ok(None);
        }
        self.len -= 1;

        let prev_typ = std::mem::replace(&mut self.de.typ, self.ktype);
        let k = seed.deserialize(&mut *self.de);
        self.de.typ = prev_typ;
        k.map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        let prev_typ = std::mem::replace(&mut self.de.typ, self.vtype);
        let v = seed.deserialize(&mut *self.de);
        self.de.typ = prev_typ;
        v
    }
}

pub(crate) struct ValueSerializer<'w> {
    w: &'w mut Vec<u8>,
    inline_bool: bool,
}

impl ValueSerializer<'_> {
    fn write_varint(&mut self, mut v: u32) {
        loop {
            let more = v >> 7;
            let has_more = more > 0;
            self.w.push((v as u8 & 0x7F) | ((has_more as u8) << 7));
            v = more;
            if !has_more {
                break;
            }
        }
    }

    fn write_zigzag(&mut self, v: i32) {
        self.write_varint((v << 1 ^ (v >> 31)) as u32);
    }
}

impl<'w> ser::Serializer for ValueSerializer<'w> {
    type Ok = Tag;
    type Error = Error;
    type SerializeSeq = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeMap = MapSerializer<'w>;
    type SerializeStruct = StructSerializer<'w>;
    type SerializeStructVariant = ser::Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        let tag = if v { Tag::BoolTrue } else { Tag::BoolFalse };
        if self.inline_bool {
            Ok(tag)
        } else {
            self.w.push(tag as u8);
            // TODO: Check behavior of fbthrift on this.
            Ok(Tag::BoolTrue)
        }
    }

    fn serialize_i16(mut self, v: i16) -> Result<Self::Ok> {
        self.write_zigzag(v.into());
        Ok(Tag::I16)
    }

    fn serialize_i32(mut self, v: i32) -> Result<Self::Ok> {
        self.write_zigzag(v);
        Ok(Tag::I32)
    }

    fn serialize_str(mut self, s: &str) -> Result<Self::Ok> {
        let len = u32::try_from(s.len())
            .map_err(|_| ser::Error::custom("string length exceeds u32 range"))?;
        self.write_varint(len);
        self.w.extend_from_slice(s.as_bytes());
        Ok(Tag::Binary)
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(StructSerializer {
            w: self.w,
            field_id_diff_tag: 0x10,
        })
    }

    fn serialize_map(mut self, len: Option<usize>) -> Result<Self::SerializeMap> {
        let len = len
            .and_then(|len| u32::try_from(len).ok())
            .expect("map must have known u32 size");
        self.write_varint(len);
        Ok(MapSerializer {
            type_pos: self.w.len(),
            w: self.w,
            ktype: None,
            vtype: None,
        })
    }

    //// Not needed ////

    fn serialize_i8(self, _: i8) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_i64(self, _: i64) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_u8(self, _: u8) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_u16(self, _: u16) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_u32(self, _: u32) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_u64(self, _: u64) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_f32(self, _: f32) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_none(self) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!()
    }

    fn serialize_unit(self) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!()
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!()
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        unimplemented!()
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        unimplemented!()
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        unimplemented!()
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        unimplemented!()
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        unimplemented!()
    }
}

pub(crate) struct StructSerializer<'w> {
    w: &'w mut Vec<u8>,
    /// 0bxxxx0000 where xxxx is the field_id delta from the previous field.
    field_id_diff_tag: u8,
}

impl ser::SerializeStruct for StructSerializer<'_> {
    type Ok = Tag;
    type Error = Error;

    fn skip_field(&mut self, _key: &'static str) -> Result<()> {
        self.field_id_diff_tag = self
            .field_id_diff_tag
            .checked_add(0x10)
            .expect("field count overflow");
        Ok(())
    }

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        // Field id & type.
        let pos = self.w.len();
        self.w.push(0);

        let tag = value.serialize(ValueSerializer {
            w: self.w,
            inline_bool: true,
        })?;
        self.w[pos] = self.field_id_diff_tag | tag as u8;
        self.field_id_diff_tag = 0x10;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        self.w.push(0);
        Ok(Tag::Struct)
    }
}

pub(crate) struct MapSerializer<'w> {
    w: &'w mut Vec<u8>,
    type_pos: usize,
    ktype: Option<Tag>,
    vtype: Option<Tag>,
}

impl ser::SerializeMap for MapSerializer<'_> {
    type Ok = Tag;
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        if self.ktype.is_none() {
            // Reserve a type byte.
            self.w.push(0);
        }

        let tag = key.serialize(ValueSerializer {
            w: self.w,
            inline_bool: false,
        })?;
        let prev = *self.ktype.get_or_insert(tag);
        debug_assert_eq!(prev, tag);
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        let tag = value.serialize(ValueSerializer {
            w: self.w,
            inline_bool: false,
        })?;
        let prev = *self.vtype.get_or_insert(tag);
        debug_assert_eq!(prev, tag);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        // This condition is false if the map contains zero elements.
        if self.type_pos < self.w.len() {
            self.w[self.type_pos] = (self.ktype.unwrap() as u8) << 4 | self.vtype.unwrap() as u8;
        }
        Ok(Tag::Map)
    }
}
