//! Mini thrift decoder, with fbthrift flavor.
//!
//! <https://github.com/apache/thrift/blob/master/doc/specs/thrift-compact-protocol.md>
use std::fmt;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Eof,
    VarintTooLong,
    Overflow,
    InvalidFieldTag,
    UnexpectedType,
    InvalidUtf8,

    UnknownField,
    MissingField,

    InvalidVersion,
}

struct Decoder<'a> {
    rest: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn next_byte(&mut self) -> Result<u8> {
        let (&fst, rest) = self.rest.split_first().ok_or(Error::Eof)?;
        self.rest = rest;
        Ok(fst)
    }

    fn next_take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (fst, rest) = self.rest.split_at_checked(len).ok_or(Error::Eof)?;
        self.rest = rest;
        Ok(fst)
    }

    fn decode_varint(&mut self) -> Result<u64> {
        let mut x = 0u64;
        for i in 0..10 {
            let b = self.next_byte()?;
            x += u64::from(b & 0x7F) << (i * 7);
            if b & 0x80 == 0 {
                return Ok(x);
            }
        }
        Err(Error::VarintTooLong)
    }

    fn decode_uint<T: TryFrom<u64>>(&mut self) -> Result<T> {
        let x = self.decode_varint()?;
        x.try_into().map_err(|_| Error::Overflow)
    }

    fn decode_sint<T: TryFrom<i64>>(&mut self) -> Result<T> {
        let x = self.decode_varint()?;
        let x = (x >> 1) as i64 ^ -(x as i64 & 1);
        x.try_into().map_err(|_| Error::Overflow)
    }

    fn decode_string(&mut self) -> Result<String> {
        let size = self.decode_uint::<usize>()?;
        let s = std::str::from_utf8(self.next_take(size)?)
            .ok()
            .ok_or(Error::InvalidUtf8)?;
        Ok(s.to_owned())
    }

    fn decode_field_header(&mut self, field_id: &mut i16) -> Result<Option<(i16, Tag)>> {
        let b = self.next_byte()?;
        if b == 0 {
            return Ok(None);
        }

        let id_delta = i16::from(b >> 4);
        *field_id = if id_delta != 0 {
            field_id.checked_add(id_delta).ok_or(Error::Overflow)?
        } else {
            self.decode_sint::<i16>()?
        };

        let tag = Tag::of(b & 0xF)?;
        Ok(Some((*field_id, tag)))
    }

    fn decode_map_int_struct<V, F>(&mut self, mut de_value: F) -> Result<Vec<Option<V>>>
    where
        F: FnMut(&mut Self) -> Result<V>,
    {
        let size = self.decode_uint::<usize>()?;
        if size == 0 {
            return Ok(Vec::new());
        }

        let b = self.next_byte()?;
        let ktag = Tag::of(b >> 4)?;
        let vtag = Tag::of(b & 0xF)?;
        let (Tag::Int, Tag::Struct) = (ktag, vtag) else {
            return Err(Error::UnexpectedType);
        };

        let cap = self.rest.len() + 1;
        let mut elems = Vec::with_capacity(size.min(cap));
        for _ in 0..size {
            let k = self.decode_sint::<usize>()?;
            let v = de_value(self)?;
            if k >= elems.len() {
                elems.resize_with(k + 1, || None);
            }
            elems[k] = Some(v);
        }
        Ok(elems)
    }
}

#[derive(Debug)]
enum Tag {
    Bool(bool),
    Byte,
    Int,
    Binary,
    List,
    Map,
    Struct,
}

impl Tag {
    fn of(typ: u8) -> Result<Self> {
        Ok(match typ {
            1 => Tag::Bool(true),
            2 => Tag::Bool(false),
            3 => Tag::Byte,
            4..=6 => Tag::Int,
            // 7: double
            8 => Tag::Binary,
            9 => Tag::List,
            // 10: set
            11 => Tag::Map,
            12 => Tag::Struct,
            // 13: float
            _ => return Err(Error::InvalidFieldTag),
        })
    }
}

pub struct Schema {
    pub file_version: i32,
    pub relax_type_checks: bool,
    pub layouts: Vec<Option<SchemaLayout>>,
    pub root_layout: u16,
}

struct DebugVecMap<'a, T>(&'a Vec<Option<T>>);

impl<'a, T: fmt::Debug> fmt::Debug for DebugVecMap<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl fmt::Debug for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Schema")
            .field("file_version", &self.file_version)
            .field("relax_type_checks", &self.relax_type_checks)
            .field("layouts", &DebugVecMap(&self.layouts))
            .field("root_layout", &self.root_layout)
            .finish()
    }
}

impl Schema {
    pub fn get_layout(&self, idx: u16) -> Option<&SchemaLayout> {
        self.layouts.get(usize::from(idx))?.as_ref()
    }
}

pub struct SchemaLayout {
    pub size: u32,
    pub bits: u16,
    pub fields: Vec<Option<SchemaField>>,
    pub type_name: String,
}

impl fmt::Debug for SchemaLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaLayout")
            .field("size", &self.size)
            .field("bits", &self.bits)
            .field("fields", &DebugVecMap(&self.fields))
            .field("type_name", &self.type_name)
            .finish()
    }
}

impl SchemaLayout {
    pub fn get_field(&self, idx: u16) -> Option<SchemaField> {
        *self.fields.get(usize::from(idx))?
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SchemaField {
    pub layout_id: u16,
    pub offset: i16,
}

impl SchemaField {
    pub fn offset_bits(self) -> u64 {
        let o = self.offset;
        if o >= 0 { o as u64 * 8 } else { -o as u64 }
    }
}

/// Parse and validate field ranges.
///
/// <https://github.com/facebook/fbthrift/blob/4375e4b08135d06fd56399b86ef93f3e6d43017c/thrift/lib/thrift/frozen.thrift#L42-L51>
pub fn parse_schema(src: &[u8]) -> Result<Schema> {
    const FILE_VERSION: i32 = 1;

    let mut de = Decoder { rest: src };
    let schema = de_schema(&mut de)?;

    if schema.file_version != FILE_VERSION
        || !schema.relax_type_checks
        || schema.get_layout(schema.root_layout).is_none()
    {
        return Err(Error::InvalidVersion);
    }
    for layout in schema.layouts.iter().flatten() {
        for field in layout.fields.iter().flatten() {
            if schema.get_layout(field.layout_id).is_none() {
                return Err(Error::InvalidVersion);
            }
        }
    }

    Ok(schema)
}

fn de_schema(de: &mut Decoder) -> Result<Schema> {
    let mut id = 0i16;
    let mut file_version = 0i32;
    let mut relax_type_checks = false;
    let mut layouts = None;
    let mut root_layout = 0;
    while let Some((id, tag)) = de.decode_field_header(&mut id)? {
        match (id, tag) {
            // 4: i32 fileVersion
            (4, Tag::Int) => file_version = de.decode_sint()?,
            // 1: bool relax_type_checks
            (1, Tag::Bool(x)) => relax_type_checks = x,
            // 3: i16 root_layout
            (3, Tag::Int) => root_layout = de.decode_sint()?,
            // 2: map<i16, Layout> layouts
            (2, Tag::Map) => layouts = Some(de.decode_map_int_struct(de_layout)?),
            _ => return Err(Error::UnknownField),
        }
    }

    Ok(Schema {
        file_version,
        relax_type_checks,
        root_layout,
        layouts: layouts.ok_or(Error::MissingField)?,
    })
}

fn de_layout(de: &mut Decoder) -> Result<SchemaLayout> {
    let mut id = 0;
    let mut size = 0;
    let mut bits = 0;
    let mut fields = None;
    let mut type_name = None;
    while let Some((id, tag)) = de.decode_field_header(&mut id)? {
        match (id, tag) {
            (1, Tag::Int) => size = de.decode_sint()?,
            (2, Tag::Int) => bits = de.decode_sint()?,
            (4, Tag::Binary) => type_name = Some(de.decode_string()?),
            (3, Tag::Map) => fields = Some(de.decode_map_int_struct(de_field)?),
            _ => return Err(Error::UnknownField),
        }
    }

    Ok(SchemaLayout {
        size,
        bits,
        fields: fields.ok_or(Error::MissingField)?,
        type_name: type_name.ok_or(Error::MissingField)?,
    })
}

fn de_field(de: &mut Decoder) -> Result<SchemaField> {
    let mut id = 0;
    let mut layout_id = None;
    let mut offset = 0;
    while let Some((id, tag)) = de.decode_field_header(&mut id)? {
        match (id, tag) {
            (1, Tag::Int) => layout_id = Some(de.decode_sint()?),
            (2, Tag::Int) => offset = de.decode_sint()?,
            _ => return Err(Error::UnknownField),
        }
    }
    Ok(SchemaField {
        layout_id: layout_id.ok_or(Error::MissingField)?,
        offset,
    })
}
