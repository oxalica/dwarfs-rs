use std::marker::PhantomData;

use self::sealed::FieldType;
use crate::{
    Error, Result,
    metadata::schema::{SchemaField, SchemaLayout},
};

mod schema;

#[derive(Debug)]
pub struct Schema(schema::Schema);

impl Schema {
    pub fn parse(src: &[u8]) -> Result<Self> {
        schema::parse_schema(src)
            .map(Self)
            .map_err(|_| Error::InvalidSchema)
    }

    fn layout(&self, idx: u16) -> &SchemaLayout {
        self.0.get_layout(idx).expect("layout index out of bound")
    }
}

// FIXME: Do not print the whole bytes in Debug.
#[derive(Debug, Clone, Copy)]
pub struct RawMetadata<'m> {
    schema: &'m Schema,
    bytes: &'m [u8],
}

impl<'m> RawMetadata<'m> {
    pub fn new(schema: &'m Schema, bytes: &'m [u8]) -> Self {
        Self { schema, bytes }
    }

    fn load_bits(&self, mut base: u64, bits: u16) -> u64 {
        // FIXME: Optimize this.
        let mut ret = 0u64;
        for i in 0..bits {
            let bit = (self.bytes[base as usize / 8] >> (base % 8)) & 1;
            ret |= (bit as u64) << i;
            base += 1;
        }
        ret
    }

    fn load_field_bits(&self, base_bit: u64, field: Option<SchemaField>) -> u64 {
        if let Some(f) = field {
            let base_bit = base_bit + f.offset_bits();
            let layout = self.schema.layout(f.layout_id);
            debug_assert!(layout.fields.is_empty());
            self.load_bits(base_bit, layout.bits)
        } else {
            0
        }
    }

    fn load_field_list(&self, base_bit: u64, field: Option<SchemaField>) -> RawList {
        if let Some(f) = field {
            let base_bit = base_bit + f.offset_bits();
            let list_layout = self.schema.layout(f.layout_id);
            let dist = self.load_field_bits(base_bit, list_layout.get_field(1));
            let len = self.load_field_bits(base_bit, list_layout.get_field(2));
            let elem_layout = list_layout.get_field(3).map(|f| f.layout_id);
            let elem_bits = elem_layout.map_or(0, |lid| self.schema.layout(lid).bits);
            RawList {
                len,
                base_bit: base_bit + dist * 8,
                elem_layout,
                elem_bits,
            }
        } else {
            RawList::default()
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RawList {
    len: u64,
    base_bit: u64,
    elem_layout: Option<u16>,
    elem_bits: u16,
}

#[derive(Debug)]
pub struct Metadata<'m, 'a> {
    meta: &'m RawMetadata<'a>,

    chunks: RawList,
}

impl<'m, 'a> Metadata<'m, 'a> {
    // FIXME: Validate this.
    pub fn parse(meta: &'m RawMetadata<'a>) -> Self {
        let layout = meta.schema.layout(meta.schema.0.root_layout);
        let base = 0;

        let chunks = meta.load_field_list(base, layout.get_field(1));

        Self { meta, chunks }
    }

    pub fn chunks(&self) -> List<'_, 'a, Chunk> {
        List {
            meta: self.meta,
            raw: self.chunks,
            _marker: PhantomData,
        }
    }
}

mod sealed {
    use super::*;
    pub trait FieldType<'a>: Sized {
        fn load_from(
            meta: &RawMetadata<'a>,
            layout: Option<&'a SchemaLayout>,
            base_bit: u64,
        ) -> Self;
    }
}

#[derive(Debug, Clone)]
pub struct List<'m, 'a, T> {
    meta: &'m RawMetadata<'a>,
    raw: RawList,
    _marker: PhantomData<T>,
}

impl<'a, T: FieldType<'a>> List<'_, 'a, T> {
    pub fn len(&self) -> usize {
        self.raw.len as _
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn at(&self, i: usize) -> T {
        assert!(i < self.len());
        let base_bit = self.raw.base_bit + i as u64 * self.raw.elem_bits as u64;
        let layout = self.raw.elem_layout.map(|lid| self.meta.schema.layout(lid));
        T::load_from(self.meta, layout, base_bit)
    }
}

impl<'a, T: FieldType<'a>> Iterator for List<'_, 'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.is_empty() {
            let v = self.at(0);
            self.raw.len -= 1;
            self.raw.base_bit += u64::from(self.raw.elem_bits);
            Some(v)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Chunk {
    pub block: u32,
    pub offset: u32,
    pub size: u32,
}

impl<'a> FieldType<'a> for Chunk {
    fn load_from(data: &RawMetadata<'a>, layout: Option<&'a SchemaLayout>, base_bit: u64) -> Self {
        let Some(layout) = layout else {
            return Self::default();
        };
        Self {
            block: data.load_field_bits(base_bit, layout.get_field(1)) as u32,
            offset: data.load_field_bits(base_bit, layout.get_field(2)) as u32,
            size: data.load_field_bits(base_bit, layout.get_field(3)) as u32,
        }
    }
}
