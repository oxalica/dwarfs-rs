//! File data slicing and/or deduplication.
use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    io::{Read, Write},
    num::NonZero,
};

use dwarfs::section::SectionType;
use rustic_cdc::{Rabin64, RollingHash64};
use sha2::{Digest, Sha512_256};

use crate::{
    Error, Result,
    metadata::Chunk,
    section::{self, CompressParam},
};

type Chunks = Vec<Chunk>;

/// Algorithm to slice and/or deduplicate file content.
pub trait Chunker {
    /// Put data via a [`Read`] instance into the archive, and return the
    /// chunking result ready for [`crate::metadata::Builder::put_file`].
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks>;

    /// Put in-memory data into the archive.
    ///
    /// This is a shortcut to [`Chunker::put_reader`].
    fn put_bytes(&mut self, mut bytes: &[u8]) -> Result<Chunks> {
        self.put_reader(&mut bytes)
    }
}

/// The simplest chunker to concat all files and slice data at block size.
///
/// This does no deduplication.
pub struct BasicChunker<W> {
    buf: Box<[u8]>,
    buf_len: usize,
    compression: CompressParam,
    w: section::Writer<W>,
}

impl<W: fmt::Debug> fmt::Debug for BasicChunker<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicChunker")
            .field("buf", &format_args!("{}/{}", self.buf_len, self.buf.len()))
            .field("compression", &self.compression)
            .field("w", &self.w)
            .finish()
    }
}

impl<W> BasicChunker<W> {
    /// Create a basic chunker with given section writer and parameters.
    ///
    /// Note: `block_size` must match the block size configured for
    /// [`crate::metadata::Builder`]. You should always get it from
    /// [`crate::metadata::Builder::block_size`].
    pub fn new(
        w: section::Writer<W>,
        block_size: NonZero<u32>,
        compression: CompressParam,
    ) -> Self {
        Self {
            buf: vec![0u8; block_size.get() as usize].into_boxed_slice(),
            buf_len: 0,
            compression,
            w,
        }
    }

    /// Finalize data chunks and get back the underlying section writer.
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

impl<W: Write> Chunker for BasicChunker<W> {
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks> {
        let seq = self.put_reader_inner(rdr)?;
        Ok(seq.to_chunks(self.buf.len() as u32).collect())
    }
}

/// The deduplicating chunker using Content Defined Chunking (CDC).
///
/// The exact algorithm used may change. Currently it uses [rustic_cdc].
pub struct CdcChunker<W> {
    inner: BasicChunker<W>,
    // TODO: This struct is too large.
    rabin: Rabin64,
    chunk_buf: Box<[u8]>,

    table: HashMap<u64, CdcChunk>,
    deduplicated_bytes: u64,
}

impl<W: fmt::Debug> fmt::Debug for CdcChunker<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdcChunker")
            .field("inner", &self.inner)
            .field("table_size", &self.table.len())
            .field("deduplicated_bytes", &self.deduplicated_bytes)
            .finish_non_exhaustive()
    }
}

struct CdcChunk {
    sha256_suffix: [u8; 24],
    start_section_idx: u32,
    start_offset: u32,
}

impl<W> CdcChunker<W> {
    const WINDOW_SIZE_BITS: u32 = 6;
    const WINDOW_SIZE: usize = 1usize << Self::WINDOW_SIZE_BITS;
    const CUT_MASK: u64 = (1u64 << 11) - 1;
    const MIN_CHUNK_SIZE: usize = Self::WINDOW_SIZE;
    const MAX_CHUNK_SIZE: usize = 64 << 10;

    /// Create the deduplicating chunker on top of a [`BasicChunker`].
    pub fn new(inner: BasicChunker<W>) -> Self {
        let rabin = Rabin64::new(Self::WINDOW_SIZE_BITS);
        CdcChunker {
            inner,
            rabin,
            chunk_buf: vec![0u8; Self::MAX_CHUNK_SIZE].into_boxed_slice(),
            table: HashMap::new(),
            deduplicated_bytes: 0,
        }
    }

    /// Get the total deduplicated bytes.
    pub fn deduplicated_bytes(&self) -> u64 {
        self.deduplicated_bytes
    }

    /// Finalize data chunks and get back the underlying section writer.
    pub fn finish(self) -> Result<section::Writer<W>>
    where
        W: Write,
    {
        self.inner.finish()
    }
}

impl<W: Write> Chunker for CdcChunker<W> {
    fn put_reader(&mut self, rdr: &mut dyn Read) -> Result<Chunks> {
        let block_size = self.inner.buf.len() as u32;

        let mut chunks = Chunks::new();
        let mut record_chunk = |cdchunk: &[u8]| {
            debug_assert_ne!(cdchunk.len(), 0);

            let hash = Sha512_256::new_with_prefix(cdchunk).finalize();
            let (&hash_prefix, hash_suffix) = hash.split_first_chunk::<8>().expect("hash is 32B");
            let hash_suffix: [u8; 24] = hash_suffix.try_into().expect("hash is 32B");

            let seq = match self.table.entry(u64::from_ne_bytes(hash_prefix)) {
                Entry::Vacant(ent) => {
                    let seq = self.inner.put_reader_inner(&mut { cdchunk })?;
                    ent.insert(CdcChunk {
                        sha256_suffix: hash_suffix,
                        start_section_idx: seq.start_section_idx,
                        start_offset: seq.start_offset,
                    });
                    seq
                }
                Entry::Occupied(ent) if ent.get().sha256_suffix == hash_suffix => {
                    self.deduplicated_bytes += cdchunk.len() as u64;
                    SeqChunks {
                        start_section_idx: ent.get().start_section_idx,
                        start_offset: ent.get().start_offset,
                        len: cdchunk.len() as u64,
                    }
                }
                // Hash prefix collision.
                Entry::Occupied(_) => self.inner.put_reader_inner(&mut { cdchunk })?,
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

            Ok::<_, Error>(())
        };

        self.rabin.reset();

        // |               chunk_buf                            |
        // | ...chunk | chunk | partial chunk | next read | ... |
        //                    ^cut_pos        ^end_pos
        //                                     ~~~~~~~~~~~ read_len
        let mut cut_pos = 0usize;
        let mut end_pos = 0usize;
        loop {
            assert_ne!(end_pos, self.chunk_buf.len());
            let read_len = match rdr.read(&mut self.chunk_buf[end_pos..]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            };

            for (&b, pos) in self.chunk_buf[end_pos..end_pos + read_len]
                .iter()
                .zip(end_pos..)
            {
                self.rabin.slide(b);
                // This is the length of the whole chunk, including previous partial data.
                // NB. the current byte at `pos` is included, hereby `+1`.
                let len = pos - cut_pos + 1;

                // The `MIN_CHUNK_SIZE` guarantees the sliding window is always filled.
                if len >= Self::MIN_CHUNK_SIZE && self.rabin.hash & Self::CUT_MASK == Self::CUT_MASK
                    || len >= Self::MAX_CHUNK_SIZE
                {
                    let cdchunk = &self.chunk_buf[cut_pos..pos];
                    cut_pos = pos;
                    record_chunk(cdchunk)?;
                }
            }
            end_pos += read_len;

            // Shift-down the last partial chunk if we reached the end of buffer.
            // For files smaller than `MAX_CHUNK_SIZE`, this path is never entered.
            if end_pos >= self.chunk_buf.len() {
                debug_assert_eq!(end_pos, self.chunk_buf.len());
                self.chunk_buf.copy_within(cut_pos.., 0);
                end_pos -= cut_pos;
                cut_pos = 0;
            }
        }

        if cut_pos < end_pos {
            record_chunk(&self.chunk_buf[cut_pos..end_pos])?;
        }

        Ok(chunks)
    }
}
