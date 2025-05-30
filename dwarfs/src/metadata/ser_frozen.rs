//! The minimal serialization support for Frozen,
//! specialized for DwarFS [`crate::metadata::Metadata`] only.
//!
//! TODO: Do value-aware bit-packing instead of a fixed layout.
//!
//! See [`super::de_frozen`] for more details.
use indexmap::IndexSet;
use serde::{Serialize, ser};

use crate::metadata::DenseMap;

use super::{Schema, SchemaField, SchemaLayout};

type Error = serde::de::value::Error;
type Result<T, E = Error> = std::result::Result<T, E>;

const MAX_STRUCT_BYTE_SIZE: u16 = i16::MAX as u16 / 8;

fn plan_layout<T: ser::Serialize>(value: &T) -> Result<Layout> {
    let mut layout = Layout::None;
    value.serialize(&mut layout)?;
    layout
        .finish()
        .ok_or_else(|| ser::Error::custom("struct is too large"))?;
    Ok(layout)
}

pub(crate) fn serialize_struct<T: ser::Serialize>(value: &T) -> Result<(Schema, Vec<u8>)> {
    let layout = plan_layout(value)?;
    let schema = {
        let mut set = IndexSet::with_capacity(72);
        let Some(root_id) = cvt_layout(&layout, &mut set)? else {
            return Err(ser::Error::custom("root struct must not be empty"));
        };
        let mut schema = Schema {
            layouts: DenseMap(set.into_iter().map(Some).collect()),
            relax_type_checks: true,
            root_layout: root_id,
            file_version: 1,
        };
        let root_schema = schema.layouts.0[root_id as usize].as_mut().unwrap();
        root_schema.size = (root_schema.bits as i32 + 7) / 8;
        schema
    };

    let mut buf = vec![0u8; usize::from(layout.byte_size())];
    value.serialize(Serializer {
        layout: &layout,
        w: &mut buf,
        base: 0,
        inline_pos: 0,
    })?;

    Ok((schema, buf))
}

fn cvt_layout(layout: &Layout, set: &mut IndexSet<SchemaLayout>) -> Result<Option<i16>> {
    let idx = match layout {
        Layout::None => return Ok(None),
        Layout::Primitive { byte_size } => {
            if *byte_size > i16::MAX as u16 / 8 {
                return Err(ser::Error::custom("primitive type is too large"));
            }
            set.insert_full(SchemaLayout {
                size: 0,
                bits: *byte_size as i16 * 8,
                fields: DenseMap::default(),
                type_name: String::new(),
            })
            .0
        }
        Layout::Struct { fields, .. } => {
            // Field index starts at 1.
            let mut ret_fields = DenseMap(vec![None; 1 + fields.len()]);
            let mut offset = 0i16;
            for (field, idx) in fields.iter().zip(1..) {
                if let Some(layout_id) = cvt_layout(field, set)? {
                    ret_fields.0[idx] = Some(SchemaField { layout_id, offset });
                    // Checked by `Layout::finish` not to overflow.
                    // NB. numbers are negative for bit-offset.
                    offset -= field.byte_size() as i16 * 8;
                }
            }
            debug_assert_ne!(offset, 0, "empty structs are handled by `Layout::finish`");
            set.insert_full(SchemaLayout {
                size: 0,
                bits: -offset,
                fields: ret_fields,
                type_name: String::new(),
            })
            .0
        }
        Layout::Collection { .. } => unreachable!(),
    };
    // Layout id starts at 0.
    let idx = i16::try_from(idx).map_err(|_| ser::Error::custom("layout count overflows i16"))?;
    Ok(Some(idx))
}

#[derive(Default, Debug, PartialEq)]
enum Layout {
    #[default]
    None,
    Primitive {
        byte_size: u16,
    },
    Struct {
        byte_size: u16,
        fields: Vec<Layout>,
    },

    /// Will be converted into `Layout::Struct` after `finish`.
    Collection {
        count_size: u16,
        // TODO(low): Eliminate this Box for Layout::None.
        element: Box<Layout>,
    },
}

type Layouter<'o> = &'o mut Layout;

impl Layout {
    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    fn byte_size(&self) -> u16 {
        match self {
            Layout::None => 0,
            Layout::Primitive { byte_size } | Layout::Struct { byte_size, .. } => *byte_size,
            Layout::Collection { .. } => unreachable!(),
        }
    }

    fn primitive(byte_size: u16) -> Self {
        if byte_size == 0 {
            Self::None
        } else {
            Self::Primitive { byte_size }
        }
    }

    /// Finalize the layout.
    ///
    /// - Remove empty fields and types.
    /// - Relax `distance` fields.
    /// - Normalize collections into structs.
    /// - Fill sizes.
    fn finish(&mut self) -> Option<u16> {
        match self {
            Layout::None => Some(0),
            Layout::Primitive { byte_size } => {
                debug_assert_ne!(*byte_size, 0);
                Some(*byte_size)
            }
            Layout::Struct { byte_size, fields } => {
                *byte_size = fields.iter_mut().try_fold(0u16, |mut size, field| {
                    size += field.finish()?;
                    (size <= MAX_STRUCT_BYTE_SIZE).then_some(size)
                })?;
                if *byte_size != 0 {
                    Some(*byte_size)
                } else {
                    *self = Layout::None;
                    Some(0)
                }
            }
            Layout::Collection {
                count_size,
                element,
            } => {
                if *count_size == 0 {
                    *self = Layout::None;
                    return Some(0);
                }

                let distance_size = if element.finish()? == 0 { 0 } else { 4 };
                let distance_layout = Self::primitive(distance_size);
                let count_layout = Self::primitive(*count_size);
                let byte_size = distance_size + *count_size;

                *self = Layout::Struct {
                    byte_size,
                    fields: vec![
                        distance_layout,
                        count_layout,
                        std::mem::take(&mut **element),
                    ],
                };
                Some(byte_size)
            }
        }
    }

    fn put_primitive_opt(&mut self, byte_size: u16, present: bool) -> Result<()> {
        match (self, present) {
            (Layout::None | Layout::Primitive { .. }, false) => Ok(()),
            (this @ Layout::None, true) => {
                *this = Self::primitive(byte_size);
                Ok(())
            }
            (Layout::Primitive { byte_size: prev }, true) => {
                *prev = (*prev).max(byte_size);
                Ok(())
            }
            (Layout::Struct { .. } | Layout::Collection { .. }, _) => Err(ser::Error::custom(
                "cannot merge a primitive type with an existing aggregate type",
            )),
        }
    }

    fn put_struct(&mut self, field_cnt: usize) -> Result<&mut [Layout]> {
        match self {
            Layout::None => {
                *self = Layout::Struct {
                    byte_size: 0,
                    fields: Vec::new(),
                };
                let Layout::Struct { fields, .. } = self else {
                    unreachable!()
                };
                fields.resize_with(field_cnt, || Layout::None);
                Ok(fields)
            }
            Layout::Struct { fields, .. } if fields.len() == field_cnt => Ok(fields),
            _ => Err(ser::Error::custom("type mismatch")),
        }
    }

    fn put_collection(&mut self, len: usize) -> Result<&mut Layout> {
        let len =
            u32::try_from(len).map_err(|_| ser::Error::custom("collection length overflow"))?;
        let len_size = if len != 0 { 4 } else { 0 };

        match self {
            Layout::None => {
                *self = Layout::Collection {
                    count_size: len_size,
                    element: Box::new(Layout::None),
                };
                let Layout::Collection { element, .. } = self else {
                    unreachable!()
                };
                Ok(element)
            }
            Layout::Collection {
                count_size,
                element,
                ..
            } => {
                *count_size = (*count_size).max(len_size);
                Ok(element)
            }
            _ => Err(ser::Error::custom("type mismatch")),
        }
    }
}

impl<'a> ser::Serializer for Layouter<'a> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Self;
    type SerializeStruct = StructLayouter<'a>;
    type SerializeStructVariant = ser::Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.put_primitive_opt(1, v)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        self.put_primitive_opt(4, v != 0)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.put_primitive_opt(8, v != 0)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        let len =
            u32::try_from(v.len()).map_err(|_| ser::Error::custom("bytes length overflows"))?;
        let has_elem = v.iter().any(|&b| b != 0);
        // Bytes are special cased and distance is relaxed immediately here.
        let fields = self.put_struct(2)?;
        fields[0].put_primitive_opt(4, has_elem)?; // distance
        fields[1].put_primitive_opt(4, len != 0) // count
    }

    fn serialize_none(self) -> Result<Self::Ok> {
        let fields = self.put_struct(2)?;
        fields[0].serialize_bool(false)
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + ser::Serialize,
    {
        let [is_some, inner] = self.put_struct(2)? else {
            unreachable!()
        };
        is_some.serialize_bool(true)?;
        value.serialize(inner)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len = len.expect("collection must have known length");
        self.put_collection(len)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        self.serialize_seq(len)
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        let fields = self.put_struct(len)?;
        Ok(StructLayouter(fields))
    }

    //// Not needed ////

    fn serialize_i8(self, _: i8) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_i16(self, _: i16) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_i32(self, _: i32) -> Result<Self::Ok> {
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

    fn serialize_f32(self, _: f32) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_str(self, _: &str) -> Result<Self::Ok> {
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

struct StructLayouter<'a>(&'a mut [Layout]);

impl<'a> ser::SerializeStruct for StructLayouter<'a> {
    type Ok = ();
    type Error = Error;

    fn skip_field(&mut self, _key: &'static str) -> Result<()> {
        self.0 = &mut std::mem::take(&mut self.0)[1..];
        Ok(())
    }

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        value.serialize(&mut self.0[0])?;
        self.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl ser::SerializeSeq for Layouter<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl ser::SerializeMap for Layouter<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_entry<K, V>(&mut self, key: &K, value: &V) -> Result<()>
    where
        K: ?Sized + ser::Serialize,
        V: ?Sized + ser::Serialize,
    {
        let [key_out, value_out] = self.put_struct(2)? else {
            unreachable!()
        };
        key.serialize(key_out)?;
        value.serialize(value_out)
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }

    //// Not needed ////

    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!()
    }

    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!()
    }
}

struct Serializer<'a, 'w> {
    layout: &'a Layout,

    /// Buffer layout:
    /// |...| previous elements... | current struct in list | .. | outlined data... |
    /// |   ^         serialized              |     0            | serialized       |
    ///     ^(storage) base                   ^inline_pos                    w.len()^
    ///      eg. list start
    w: &'w mut Vec<u8>,
    /// The storage base for 'distance'.
    base: u32,
    /// The next place to serialized inlined fields into.
    inline_pos: u32,
}

impl<'a> Serializer<'a, '_> {
    fn distance(&self) -> u32 {
        self.w.len() as u32 - self.base
    }

    fn reborrow(&mut self) -> Serializer<'a, '_> {
        Serializer {
            layout: self.layout,
            w: self.w,
            base: self.base,
            inline_pos: self.inline_pos,
        }
    }

    fn put_primitive<const N: usize>(self, v: [u8; N]) {
        match self.layout {
            Layout::None => {}
            Layout::Primitive { byte_size } => {
                debug_assert_eq!(usize::from(*byte_size), N, "type mismatch");
                *self.w[self.inline_pos as usize..]
                    .first_chunk_mut::<N>()
                    .unwrap() = v;
            }
            _ => unreachable!(),
        }
    }

    fn as_struct(&self, field_cnt: usize) -> Option<&'a [Layout]> {
        match self.layout {
            Layout::None => None,
            Layout::Struct { fields, .. } => {
                debug_assert_eq!(fields.len(), field_cnt, "type mismatch");
                Some(fields)
            }
            _ => unreachable!(),
        }
    }
}

impl<'a, 'w> ser::Serializer for Serializer<'a, 'w> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeMap = ser::Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = StructSerializer<'a, 'w>;
    type SerializeStructVariant = ser::Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.put_primitive([v.into()]);
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        self.put_primitive(v.to_le_bytes());
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.put_primitive(v.to_le_bytes());
        Ok(())
    }

    fn serialize_bytes(mut self, v: &[u8]) -> Result<Self::Ok> {
        use ser::SerializeStruct as _;

        if self.layout.is_none() {
            return Ok(());
        }

        let distance = self.distance();
        let mut s = self.reborrow().serialize_struct("bytes", 2)?;
        let omit_elements = s.fields[0].is_none();
        s.serialize_field("distance", &distance)?;
        s.serialize_field("count", &(v.len() as u32))?;
        s.end()?;
        if !omit_elements {
            self.w.extend_from_slice(v);
        }
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok> {
        use ser::SerializeStruct as _;

        let mut s = self.serialize_struct("optional", 2)?;
        s.serialize_field("is_some", &false)?;
        s.skip_field("inner")?;
        s.end()
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + ser::Serialize,
    {
        use ser::SerializeStruct as _;

        let mut s = self.serialize_struct("optional", 2)?;
        s.serialize_field("is_some", &true)?;
        s.serialize_field("inner", value)?;
        s.end()
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        let fields = self.as_struct(len).unwrap_or_default();
        Ok(StructSerializer { fields, ser: self })
    }

    fn collect_seq<I>(mut self, iter: I) -> Result<Self::Ok>
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: ser::Serialize,
    {
        use ser::SerializeStruct as _;

        let iter = iter.into_iter();
        let len = iter.size_hint().0 as u32;
        if self.layout.is_none() {
            debug_assert_eq!(len, 0);
            return Ok(());
        }

        let distance = self.distance();
        let mut s = self.reborrow().serialize_struct("seq", 3)?;
        let elem_layout = s.fields.get(2).unwrap_or(&Layout::None);
        s.serialize_field("distance", &distance)?;
        s.serialize_field("count", &len)?;
        s.end()?;

        if !elem_layout.is_none() {
            let elem_size = elem_layout.byte_size();
            let new_base = self.w.len();
            self.w
                .resize(new_base + len as usize * elem_size as usize, 0);
            u32::try_from(self.w.len())
                .map_err(|_| ser::Error::custom("serialization size overflows u32"))?;
            let mut ser_elem = Serializer {
                layout: elem_layout,
                w: self.w,
                base: new_base as u32,
                inline_pos: new_base as u32,
            };

            for elem in iter {
                elem.serialize(ser_elem.reborrow())?;
                ser_elem.inline_pos += u32::from(elem_size);
            }
        }

        Ok(())
    }

    fn collect_map<K, V, I>(self, iter: I) -> std::result::Result<Self::Ok, Self::Error>
    where
        K: Serialize,
        V: Serialize,
        I: IntoIterator<Item = (K, V)>,
    {
        #[derive(Serialize)]
        struct Pair<K, V> {
            lhs: K,
            rhs: V,
        }

        self.collect_seq(iter.into_iter().map(|(lhs, rhs)| Pair { lhs, rhs }))
    }

    //// Not needed ////

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        unimplemented!()
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        unimplemented!()
    }

    fn serialize_i8(self, _: i8) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_i16(self, _: i16) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_i32(self, _: i32) -> Result<Self::Ok> {
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

    fn serialize_f32(self, _: f32) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_f64(self, _: f64) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_char(self, _: char) -> Result<Self::Ok> {
        unimplemented!()
    }

    fn serialize_str(self, _: &str) -> Result<Self::Ok> {
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

struct StructSerializer<'a, 'w> {
    ser: Serializer<'a, 'w>,
    fields: &'a [Layout],
}

impl ser::SerializeStruct for StructSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn skip_field(&mut self, _key: &'static str) -> Result<()> {
        let Some((fst, rest)) = self.fields.split_first() else {
            return Ok(());
        };
        self.fields = rest;
        // Struct size will never overflow, because they are checked to be less
        // than `MAX_STRUCT_BYTE_SIZE` which is in `i16` range.
        self.ser.inline_pos += u32::from(fst.byte_size());
        Ok(())
    }

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + ser::Serialize,
    {
        let Some((fst, rest)) = self.fields.split_first() else {
            return Ok(());
        };
        self.fields = rest;

        if !fst.is_none() {
            self.ser.layout = fst;
            value.serialize(self.ser.reborrow())?;
            // See comments above.
            self.ser.inline_pos += u32::from(fst.byte_size());
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::print_stdout, reason = "allowed in tests")]
    use crate::metadata::*;

    #[test]
    fn smoke() {
        let mut meta = Metadata::default();
        let info = meta.options.get_or_insert_default();
        info.mtime_only = true;
        info.time_resolution_sec = Some(42);

        let (schema, out) = ser_frozen::serialize_struct(&meta).unwrap();
        println!("{schema:#?}");
        println!("len={} {:02x?}", out.len(), out);
        assert_eq!(
            out,
            [
                1, // options.is_some = true
                1, // options.inner.mtime_only = true
                1, // options.inner.time_resolution.is_some = true
                42, 0, 0, 0, // options.inner.time_resolution.inner = 42
            ]
        );

        let meta2 = Metadata::parse(&schema, &out).unwrap();
        assert_eq!(meta, meta2);
    }

    #[test]
    fn bytes() {
        let mut meta = Metadata {
            dwarfs_version: Some("abc".into()),
            ..Default::default()
        };
        let (_schema, out) = ser_frozen::serialize_struct(&meta).unwrap();
        assert_eq!(
            out,
            [
                1, // dwarfs_version.is_some
                9, 0, 0, 0, // dwarfs_version.inner.distance
                3, 0, 0, 0, // dwarfs_version.inner.count
                //// Outlined ////
                b'a', b'b', b'c',
            ]
        );

        meta.dwarfs_version = Some("\0\0".into());
        let (_schema, out) = ser_frozen::serialize_struct(&meta).unwrap();
        assert_eq!(
            out,
            [
                1, // dwarfs_version.is_some
                2, 0, 0, 0, // dwarfs_version.inner.count
            ]
        );
    }

    #[test]
    fn collection() {
        let meta = Metadata {
            chunks: vec![
                Chunk {
                    // Always zero.
                    block: 0,
                    // Sometimes zero.
                    offset: 0,
                    // Never zero.
                    size: 42,
                },
                Chunk {
                    block: 0,
                    offset: 100,
                    size: 42,
                },
            ],
            // All-zero elements with non-zero length.
            symlink_table: vec![0, 0, 0],

            ..Metadata::default()
        };

        let (schema, out) = ser_frozen::serialize_struct(&meta).unwrap();
        println!("{schema:#?}");
        println!("len={} {:02x?}", out.len(), out);
        assert_eq!(
            out,
            [
                12, 0, 0, 0, // chunks.distance = 12
                2, 0, 0, 0, // chunks.count = 2
                3, 0, 0, 0, // symlink_table.count = 3
                //// Outlined ////
                0, 0, 0, 0, // chunks[0].offset = 0
                42, 0, 0, 0, // chunks[0].size = 42
                100, 0, 0, 0, // chunks[1].offset = 100
                42, 0, 0, 0, // chunks[1].size = 42
            ]
        );

        let meta2 = Metadata::parse(&schema, &out).unwrap();
        assert_eq!(meta, meta2);
    }
}
