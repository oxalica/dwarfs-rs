use std::{
    collections::{HashMap, hash_map::Entry},
    io::{Read, Write},
};

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

pub struct FastCdcChunker<W> {
    inner: ConcatChunker<W>,
    table: HashMap<u64, CdcChunk>,
    min_size: u32,
    avg_size: u32,
    max_size: u32,
    deduplicated_bytes: u64,
}

struct CdcChunk {
    sha256_suffix: [u8; 24],
    start_section_idx: u32,
    start_offset: u32,
}

impl<W> FastCdcChunker<W> {
    pub fn new(inner: ConcatChunker<W>, min_size: u32, avg_size: u32, max_size: u32) -> Self {
        FastCdcChunker {
            inner,
            table: HashMap::new(),
            min_size,
            avg_size,
            max_size,
            deduplicated_bytes: 0,
        }
    }

    pub fn deduplicated_bytes(&self) -> u64 {
        self.deduplicated_bytes
    }

    pub fn into_inner(self) -> ConcatChunker<W>
    where
        W: Write,
    {
        self.inner
    }
}

impl<W: Write> Chunker for FastCdcChunker<W> {
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks> {
        use fastcdc::v2020::{Error as CdcError, StreamCDC};
        use sha2::Digest;

        let block_size = self.inner.buf.len() as u32;

        // FIXME: `fastcdc`'s API is too hard to be efficient. It is heavy to construct
        // and does not support allocation-less chunking.
        let cdc = StreamCDC::new(rdr, self.min_size, self.avg_size, self.max_size);
        let mut chunks = Chunks::new();
        for ret in cdc {
            let chunk = match ret {
                Ok(chunk) => chunk.data,
                Err(CdcError::IoError(err)) => return Err(err.into()),
                Err(_) => unreachable!(),
            };

            let hash = sha2::Sha512_256::new_with_prefix(&chunk).finalize();
            let (&hash_prefix, hash_suffix) = hash.split_first_chunk::<8>().unwrap();
            let seq = match self.table.entry(u64::from_ne_bytes(hash_prefix)) {
                Entry::Vacant(ent) => {
                    let seq = self.inner.put_reader_inner(&mut chunk.as_slice()).unwrap();
                    ent.insert(CdcChunk {
                        sha256_suffix: hash_suffix.try_into().unwrap(),
                        start_section_idx: seq.start_section_idx,
                        start_offset: seq.start_offset,
                    });
                    seq
                }
                Entry::Occupied(ent) if ent.get().sha256_suffix == hash_suffix => {
                    self.deduplicated_bytes += chunk.len() as u64;
                    SeqChunks {
                        start_section_idx: ent.get().start_section_idx,
                        start_offset: ent.get().start_offset,
                        len: chunk.len() as u64,
                    }
                }
                // Hash prefix collision.
                Entry::Occupied(_) => self.inner.put_reader_inner(&mut chunk.as_slice()).unwrap(),
            };

            // Merge chunks if possible.
            for c in seq.to_chunks(block_size) {
                if let Some(p) = chunks
                    .last_mut()
                    .filter(|p| (p.section_idx, p.offset + p.size) == (c.section_idx, c.offset))
                {
                    p.size += c.size;
                } else {
                    chunks.push(c);
                }
            }
        }

        Ok(chunks)
    }
}
