//! The minimal serialization support for minithrift,
//! specialized for DwarFS schema type only.
//!
//! See [`super::de_thrift`] for more details.
use serde::{de, ser};

use super::de_thrift::Tag;

type Result<T, E = Error> = std::result::Result<T, E>;
type Error = de::value::Error;

pub(crate) fn serialize_struct<T: ser::Serialize>(input: &T) -> Result<Vec<u8>> {
    // TODO: Set a good default capacity here.
    let mut out = Vec::new();
    input.serialize(ValueSerializer {
        w: &mut out,
        inline_bool: false,
    })?;
    Ok(out)
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
    /// 0bxxxx0000 where xxxx is the `field_id` delta from the previous field.
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
