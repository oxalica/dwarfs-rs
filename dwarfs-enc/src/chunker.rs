use std::io::{Read, Write};

use dwarfs::section::SectionType;

use crate::{
    Result,
    metadata::Chunk,
    section::{self, CompressParam},
};

pub type Chunks = Vec<Chunk>;

/// Algorithm to slice and/or deduplicate file content.
pub trait Chunker {
    /// Add a file reader into the archive, and return the chunking result.
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks>;
}

/// The simplest chunker to concat all files and slice data at block size.
///
/// This does no deduplication.
#[derive(Debug)]
pub struct ConcatChunker<W> {
    buf: Box<[u8]>,
    buf_len: usize,
    compression: CompressParam,
    w: section::Writer<W>,
}

impl<W> ConcatChunker<W> {
    // FIXME: Reuse `metadata::Config`
    pub fn new(w: section::Writer<W>, block_size: u32, compression: CompressParam) -> Self {
        Self {
            buf: vec![0u8; block_size as usize].into_boxed_slice(),
            buf_len: 0,
            compression,
            w,
        }
    }

    pub fn finish(mut self) -> Result<section::Writer<W>>
    where
        W: Write,
    {
        if self.buf_len != 0 {
            self.w.write_section(
                SectionType::BLOCK,
                self.compression,
                &self.buf[..self.buf_len],
            )?;
            self.buf_len = 0;
        }
        Ok(self.w)
    }

    fn put_reader_inner(&mut self, rdr: &mut dyn Read) -> Result<SeqChunks>
    where
        W: Write,
    {
        let mut chunks = SeqChunks {
            start_section_idx: self.w.section_count(),
            start_offset: self.buf_len as u32,
            len: 0,
        };
        loop {
            while self.buf_len < self.buf.len() {
                match rdr.read(&mut self.buf[self.buf_len..]) {
                    Ok(0) => return Ok(chunks),
                    Ok(n) => {
                        self.buf_len += n;
                        chunks.len += n as u64;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err.into()),
                }
            }

            debug_assert_eq!(self.buf_len, self.buf.len());
            self.w
                .write_section(SectionType::BLOCK, self.compression, &self.buf)?;
            self.buf_len = 0;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SeqChunks {
    start_section_idx: u32,
    start_offset: u32,
    len: u64,
}

impl SeqChunks {
    fn to_chunks(mut self, block_size: u32) -> impl Iterator<Item = Chunk> {
        std::iter::from_fn(move || {
            let rest_len = block_size - self.start_offset;
            if self.len == 0 {
                None
            } else if self.len <= u64::from(rest_len) {
                let c = Chunk {
                    section_idx: self.start_section_idx,
                    offset: self.start_offset,
                    size: self.len as u32,
                };
                self.len = 0;
                Some(c)
            } else {
                let c = Chunk {
                    section_idx: self.start_section_idx,
                    offset: self.start_offset,
                    size: rest_len,
                };
                self.len -= u64::from(rest_len);
                self.start_section_idx += 1;
                self.start_offset = 0;
                Some(c)
            }
        })
    }
}

impl<W: Write> Chunker for ConcatChunker<W> {
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks> {
        let seq = self.put_reader_inner(rdr)?;
        Ok(seq.to_chunks(self.buf.len() as u32).collect())
    }
}
