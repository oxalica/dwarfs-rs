use crate::{Error, Result};

mod schema;

#[derive(Debug)]
pub struct Schema(schema::Schema);

impl Schema {
    pub fn parse(src: &[u8]) -> Result<Self> {
        schema::parse_schema(src)
            .map(Self)
            .map_err(|_| Error::InvalidSchema)
    }
}

#[derive(Debug)]
pub struct Metadata {}
