//! DwarFS section writer.
use std::io::Write;
use std::num::NonZero;

use dwarfs::section::{CompressAlgo, Header, MagicVersion, SectionIndexEntry, SectionType};
use dwarfs::zerocopy::IntoBytes;
use zerocopy::FromBytes;

use crate::ordered_parallel::OrderedParallel;
use crate::{ErrorInner, Result};

/// The section compression parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressParam {
    /// No compression.
    None,
    /// Compress with a given ZSTD level. Requires feature `zstd`.
    #[cfg(feature = "zstd")]
    Zstd(zstd_safe::CompressionLevel),
    /// Compress with a given LZMA (aka. xz) level. Requires feature `lzma`.
    #[cfg(feature = "lzma")]
    Lzma(u32),
}

/// DwarFS section writer.
#[derive(Debug)]
pub struct Writer<W: ?Sized> {
    workers: OrderedParallel<Result<Vec<u8>>>,
    /// The total number of sections initiated, including ones that are not written yet.
    initiated_section_count: u32,
    index: IndexBuilder,

    w: W,
}

#[derive(Debug, Default)]
struct IndexBuilder {
    index: Vec<SectionIndexEntry>,
    next_offset: u64,
}

impl IndexBuilder {
    fn push(&mut self, typ: SectionType, sec_raw_len: usize) -> Result<()> {
        let ent = SectionIndexEntry::new(typ, self.next_offset).expect("checked by last write");
        self.next_offset = u64::try_from(sec_raw_len)
            .ok()
            .and_then(|l| l.checked_add(self.next_offset))
            .filter(|&n| n < 1u64 << 48)
            .ok_or(ErrorInner::Limit("archive size exceeds 2^48 bytes"))?;
        self.index.push(ent);
        Ok(())
    }
}

impl<W> Writer<W> {
    /// Create a default multi-threaded section writer.
    pub fn new(w: W) -> std::io::Result<Self> {
        let thread_cnt = std::thread::available_parallelism()?;
        Self::new_with_threads(w, thread_cnt)
    }

    /// Create a section writer with specific parallelism.
    pub fn new_with_threads(w: W, thread_cnt: NonZero<usize>) -> std::io::Result<Self> {
        let workers = OrderedParallel::new("compressor", thread_cnt)?;
        Ok(Self {
            workers,
            initiated_section_count: 0,
            index: IndexBuilder::default(),
            w,
        })
    }
}

impl<W: ?Sized> Writer<W> {
    /// Get a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    /// Get a mutable reference tothe underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.w
    }

    /// Retrieve the ownership of the underlying reader.
    pub fn into_inner(self) -> W
    where
        W: Sized,
    {
        self.w
    }
}

impl<W: Write> Writer<W> {
    /// Number of sections of initiated via `write_section`.
    #[must_use]
    pub fn section_count(&self) -> u32 {
        // Checked by `write_section` not to overflow u32.
        self.initiated_section_count
    }

    /// Finalize and seal the DwarFS archive.
    pub fn finish(mut self) -> Result<W> {
        // Wait for all proceeding sections to complete, so their offsets are recorded.
        self.workers.stop();
        while let Some(iter) = self.workers.wait_and_get() {
            Self::commit_completed(iter, &mut self.w, &mut self.index)?;
        }

        // The last length is unused.
        let index_byte_len = self.index.index.as_bytes().len() + size_of::<SectionIndexEntry>();
        self.index
            .push(SectionType::SECTION_INDEX, index_byte_len)?;
        let sec = Self::seal_section(
            self.section_count(),
            SectionType::SECTION_INDEX,
            CompressParam::None,
            self.index.index.as_bytes(),
        )?;
        self.w.write_all(&sec)?;

        Ok(self.w)
    }

    fn commit_completed(
        completed: impl Iterator<Item = Result<Vec<u8>>>,
        w: &mut W,
        index: &mut IndexBuilder,
    ) -> Result<()> {
        for ret in completed {
            let sec = ret?;
            let off = std::mem::offset_of!(Header, section_type);
            let typ = SectionType::read_from_prefix(&sec[off..]).unwrap().0;
            w.write_all(&sec)?;
            index.push(typ, sec.len())?;
        }
        Ok(())
    }

    /// Write a section with given (uncompressed) payload.
    pub fn write_section(
        &mut self,
        section_type: SectionType,
        compression: CompressParam,
        payload: &[u8],
    ) -> Result<()> {
        // Should not happen for current machines.
        assert!(u64::try_from(size_of::<Header>() + payload.len()).is_ok());

        let section_number = self.section_count();
        self.initiated_section_count = self
            .initiated_section_count
            .checked_add(1)
            .ok_or(ErrorInner::Limit("section count exceeds 2^32"))?;

        let payload = payload.to_vec();
        Self::commit_completed(
            self.workers.submit_and_get(move || {
                Self::seal_section(section_number, section_type, compression, &payload)
            }),
            &mut self.w,
            &mut self.index,
        )
    }

    /// Compress payload if possible, calculate hashes and fill the section header.
    fn seal_section(
        section_number: u32,
        section_type: SectionType,
        compression: CompressParam,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size_of::<Header>() + payload.len()];
        #[cfg_attr(not(feature = "default"), allow(unused_labels))]
        let (compress_algo, compressed_len) = 'compressed: {
            let compressed_buf = &mut buf[size_of::<Header>()..];
            match compression {
                CompressParam::None => {}

                #[cfg(feature = "zstd")]
                #[expect(non_upper_case_globals, reason = "name from C")]
                CompressParam::Zstd(lvl) => {
                    // See: <https://github.com/gyscos/zstd-rs/issues/276>
                    const ZSTD_error_dstSize_tooSmall: zstd_safe::ErrorCode = -70isize as usize;

                    match zstd_safe::compress(compressed_buf, payload, lvl) {
                        Ok(compressed_len) => {
                            assert!(compressed_len <= payload.len());
                            break 'compressed (CompressAlgo::ZSTD, compressed_len);
                        }
                        Err(ZSTD_error_dstSize_tooSmall) => {}
                        Err(code) => {
                            let err = std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!(
                                    "ZSTD compression failed (code={}): {}",
                                    code,
                                    zstd_safe::get_error_name(code),
                                ),
                            );
                            return Err(ErrorInner::Compress(err).into());
                        }
                    }
                }

                #[cfg(feature = "lzma")]
                CompressParam::Lzma(lvl) => {
                    if let Some(compressed_len) = (|| {
                        use liblzma::stream::{Action, Check, Status, Stream};

                        // The default parameters used by `liblzma::bufread::XzEncoder::new`.
                        // See: <https://docs.rs/liblzma/0.4.1/src/liblzma/bufread.rs.html#35>
                        let mut encoder = Stream::new_easy_encoder(lvl, Check::Crc64)?;

                        match encoder.process(payload, compressed_buf, Action::Run)? {
                            // Treat partial consumption as buffer-too-small.
                            Status::Ok if encoder.total_in() == payload.len() as u64 => {}
                            Status::Ok | Status::MemNeeded => return Ok(None),
                            Status::StreamEnd | Status::GetCheck => unreachable!(),
                        }
                        match encoder.process(
                            &[],
                            &mut compressed_buf[encoder.total_out() as usize..],
                            Action::Finish,
                        )? {
                            Status::StreamEnd => {}
                            Status::MemNeeded => return Ok(None),
                            Status::Ok | Status::GetCheck => unreachable!(),
                        }

                        Ok::<_, std::io::Error>(Some(encoder.total_out() as usize))
                    })()
                    .map_err(ErrorInner::Compress)?
                    {
                        break 'compressed (CompressAlgo::LZMA, compressed_len);
                    }
                }
            }
            compressed_buf.copy_from_slice(payload);
            (CompressAlgo::NONE, payload.len())
        };
        buf.truncate(size_of::<Header>() + compressed_len);
        let (header_buf, compressed_buf) = buf.split_at_mut(size_of::<Header>());

        let mut header = Header {
            magic_version: MagicVersion::LATEST,
            slow_hash: [0u8; 32],
            fast_hash: [0u8; 8],
            section_number: section_number.into(),
            section_type,
            compress_algo,
            payload_size: 0.into(),
        };
        header.update_size_and_checksum(compressed_buf);
        header_buf.copy_from_slice(header.as_bytes());

        Ok(buf)
    }

    /// Write metadata sections `METADATA_V2_{,_SCHEMA}`.
    pub fn write_metadata_sections(
        &mut self,
        metadata: &dwarfs::metadata::Metadata,
        compression: CompressParam,
    ) -> Result<()> {
        let (schema, metadata_bytes) = metadata.to_schema_and_bytes()?;
        let schema_bytes = schema.to_bytes()?;
        self.write_section(SectionType::METADATA_V2_SCHEMA, compression, &schema_bytes)?;
        self.write_section(SectionType::METADATA_V2, compression, &metadata_bytes)
    }
}
