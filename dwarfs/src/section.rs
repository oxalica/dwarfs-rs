//! The low-level module for accessing sections in a DwarFS archive.
//!
//! A DwarFS archive consists of several sections. Sections for storing raw file
//! data are also called blocks. Each section consists of a [`Header`] and
//! maybe-compressed section payload bytes. The maximum uncompressed payload
//! length of each data section is the block-size, which is by default 16MiB.
//! Other non-block sections may be smaller or larger, but should still be
//! small enough to store in memory.
//!
//! See [`SectionReader`] for APIs to read sections. In general, functions
//! returning section headers will always validate the DwarFS version marked in
//! the header is supported, and functions returning section payloads will
//! always validate the fast XXH3 checksum against the header before return.
//!
//! See also:
//! [DwarFS File System Format v2.5](https://github.com/mhx/dwarfs/blob/66b80efd0f47209c2d85c95c8af9f078436b6554/doc/dwarfs-format.md)
use std::{fmt, mem::offset_of};

use positioned_io::ReadAt;
use xxhash_rust::xxh3::Xxh3Default;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, little_endian as le};

type Result<T> = std::result::Result<T, Error>;

/// An error raised from reading, validating, or decompressiong sections.
pub struct Error(Box<ErrorInner>);

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
#[non_exhaustive]
enum ErrorInner {
    // Header.
    InvalidMagic([u8; 6]),
    UnsupportedVersion(u8, u8),
    LengthMismatch,
    ChecksumMismatch,
    OffsetOverflow,

    // Payload.
    UnsupportedCompressAlgo(CompressAlgo),
    TypeMismatch {
        expect: SectionType,
        got: SectionType,
    },
    PayloadTooLong {
        limit: usize,
        got: u64,
    },
    Decompress(std::io::Error),

    // Other.
    MalformedSectionIndex(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            ErrorInner::InvalidMagic(magic) => {
                write!(f, "invalid section magic: b\"{}\"", magic.escape_ascii())
            }
            ErrorInner::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported section version: DWARFS{maj}.{min}")
            }
            ErrorInner::LengthMismatch => f.pad("section payload length mismatch"),
            ErrorInner::ChecksumMismatch => f.pad("section checksum mismatch"),
            ErrorInner::OffsetOverflow => f.pad("section offset overflow"),

            ErrorInner::UnsupportedCompressAlgo(algo) => {
                write!(f, "unsupported section compress algorithm {algo:?}")
            }
            ErrorInner::TypeMismatch { expect, got } => {
                write!(
                    f,
                    "section type mismatch, expect {expect:?} but got {got:?}"
                )
            }
            ErrorInner::PayloadTooLong { limit, got } => {
                write!(
                    f,
                    "section payload has {got} bytes, exceeding the limit of {limit} bytes"
                )
            }
            ErrorInner::Decompress(err) => write!(f, "failed to decompress section payload: {err}"),

            ErrorInner::MalformedSectionIndex(msg) => {
                write!(f, "malformed section index: {msg}")
            }
            ErrorInner::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.0 {
            ErrorInner::Decompress(err) | ErrorInner::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    #[cold]
    fn from(err: std::io::Error) -> Self {
        Self(Box::new(ErrorInner::Io(err)))
    }
}

impl From<ErrorInner> for Error {
    #[cold]
    fn from(err: ErrorInner) -> Self {
        Self(Box::new(err))
    }
}

pub(crate) const HEADER_SIZE: u64 = size_of::<Header>() as u64;

/// The section (aka. block) header.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct Header {
    /// Header magic and format version.
    pub magic_version: MagicVersion,
    /// The "slow" hash digests of SHA-512/256.
    pub slow_hash: [u8; 32],
    /// The "fast" hash digests of XXH3-64.
    pub fast_hash: [u8; 8],
    /// The 0-based index of this section in the DwarFS archive.
    pub section_number: le::U32,
    /// The type of this section.
    pub section_type: SectionType,
    /// The compression algorithm of the section payload.
    pub compress_algo: CompressAlgo,
    /// The length in bytes of the compressed payload following.
    pub payload_size: le::U64,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("magic_version", &self.magic_version)
            .field("slow_hash", &format_args!("{:02x?}", self.slow_hash))
            .field("slow_hash", &format_args!("{:02x?}", self.fast_hash))
            .field("section_number", &self.section_number.get())
            .field("section_type", &self.section_type)
            .field("compress_algo", &self.compress_algo)
            .field("payload_size", &self.payload_size.get())
            .finish()
    }
}

impl Header {
    /// Validate section checksum of header and payload using the "fast" XXH3-64 hash.
    pub fn validate_fast_checksum(&self, payload: &[u8]) -> Result<()> {
        if payload.len() as u64 != self.payload_size.get() {
            bail!(ErrorInner::LengthMismatch);
        }
        let mut h = Xxh3Default::new();
        h.update(&self.as_bytes()[offset_of!(Self, section_number)..]);
        h.update(payload);
        if h.digest() != u64::from_le_bytes(self.fast_hash) {
            bail!(ErrorInner::ChecksumMismatch);
        }
        Ok(())
    }

    /// Validate section checksum of header and payload using the "slow" SHA2-512/256 hash.
    pub fn validate_slow_checksum(&self, payload: &[u8]) -> Result<()> {
        use sha2::Digest;

        if payload.len() as u64 != self.payload_size.get() {
            bail!(ErrorInner::LengthMismatch);
        }
        let mut h = sha2::Sha512_256::new();
        h.update(&self.as_bytes()[offset_of!(Self, fast_hash)..]);
        h.update(payload);
        if h.finalize()[..] != self.slow_hash {
            bail!(ErrorInner::ChecksumMismatch);
        }
        Ok(())
    }

    /// Check if this section header has the expected section type.
    pub(crate) fn check_type(&self, expect: SectionType) -> Result<()> {
        if self.section_type != expect {
            bail!(ErrorInner::TypeMismatch {
                expect,
                got: self.section_type,
            });
        }
        Ok(())
    }

    fn payload_size_limited(&self, limit: usize) -> Result<usize> {
        let size = self.payload_size.get();
        if let Some(size) = usize::try_from(size).ok().filter(|&n| n <= limit) {
            Ok(size)
        } else {
            bail!(ErrorInner::PayloadTooLong { limit, got: size })
        }
    }
}

/// Section magic and format version.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MagicVersion {
    /// The section magic that should match [MagicVersion::MAGIC].
    pub magic: [u8; 6],
    /// The format major version.
    pub major: u8,
    /// The format minor version.
    pub minor: u8,
}

impl fmt::Debug for MagicVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicVersion")
            .field("magic", &format_args!("b\"{}\"", self.magic.escape_ascii()))
            .field("major", &self.major)
            .field("minor", &self.minor)
            .finish()
    }
}

impl MagicVersion {
    /// The expected magic.
    pub const MAGIC: [u8; 6] = *b"DWARFS";

    /// Validate if the magic matches and the format version is supported by this library.
    pub fn validate(self) -> Result<()> {
        let ver = (self.major, self.minor);
        if self.magic != Self::MAGIC {
            bail!(ErrorInner::InvalidMagic(self.magic));
        }
        if crate::DWARFS_VERSION_MIN <= ver && ver <= crate::DWARFS_VERSION_MAX {
            Ok(())
        } else {
            bail!(ErrorInner::UnsupportedVersion(ver.0, ver.1))
        }
    }
}

/// The type of a section.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(2))]
pub struct SectionType(pub le::U16);

macro_rules! impl_open_enum {
    ($name:ident; $ctor:path; $($(#[$meta:meta])* $variant:ident = $value:expr,)*) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(match *self {
                    $(Self::$variant => stringify!($variant),)*
                    _ => return f
                        .debug_tuple(stringify!($name))
                        .field(&self.0.get())
                        .finish(),
                })
            }
        }

        impl $name {
            $(
                $(#[$meta])*
                pub const $variant: Self = Self($ctor($value));
            )*
        }
    };
}

impl_open_enum! {
    SectionType; le::U16::new;

    /// A block of data.
    BLOCK = 0,
    /// The schema used to layout on-disk format of Metadata, see [`crate::metadata::Schema`].
    METADATA_V2_SCHEMA = 7,
    /// The bulk of the root metadata, see [`crate::metadata::Metadata`].
    METADATA_V2 = 8,
    /// The index of all sections. This must be the last section if present.
    /// It must not be compressed.
    SECTION_INDEX = 9,
    /// File system history information.
    HISTORY = 10,
}

/// Compression algorithm used for section payloads.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(2))]
pub struct CompressAlgo(pub le::U16);

impl_open_enum! {
    CompressAlgo; le::U16::new;

    /// Not compressed.
    NONE = 0,
    /// LZMA, aka `.xz` compression. Supported via feature `lzma`.
    LZMA = 1,
    /// Zstd compression. Supported via feature `zstd`.
    ZSTD = 2,
    /// LZ4 compression. Supported via feature `lz4`.
    LZ4 = 3,
    /// LZ4 compression in HC (high-compression) mode. It can be decompressed as normal LZ4.
    /// Supported via feature `lz4`.
    LZ4HC = 4,
    /// Brotli compression. Supported via feature `brotli`.
    BROTLI = 5,
    /// FLAC compression. Not supported.
    FLAC = 6,
    /// Rice++ compression. Not supported.
    RICEPP = 7,
}

/// An entry in the section index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct SectionIndexEntry(pub le::U64);

impl fmt::Debug for SectionIndexEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SectionIndexEntry")
            .field("section_type", &self.section_type())
            .field("offset", &self.offset())
            .finish()
    }
}

impl SectionIndexEntry {
    /// The type of the section this entry is referring to.
    #[must_use]
    #[inline]
    pub fn section_type(self) -> SectionType {
        SectionType((self.0 >> 48).try_into().expect("must not overflow u16"))
    }

    /// The offset of the section this entry is referring to,
    /// relative to the first section.
    #[must_use]
    #[inline]
    pub fn offset(self) -> u64 {
        self.0.get() & ((1u64 << 48) - 1)
    }
}

/// The wrapper type for reading sections from a random access reader.
///
/// The inner type should implement [`positioned_io::ReadAt`] to support
/// efficient random access. Typically, [`std::fs::File`] should be used.
/// You do NOT need additional buffering.
///
/// Note: It's *discouraged* to use [`positioned_io::RandomAccessFile`] on *NIX
/// platforms because that would disable readahead which can hurt performance on
/// sequential read inside a several MiB section.
/// On Windows, however, `RandomAccessFile` is several times faster than `File`.
pub struct SectionReader<R: ?Sized> {
    /// The offset of the start of the DwarFS archive in `rdr`, which is added to all
    /// operation offsets.
    archive_start: u64,
    /// The temporary buffer for raw compressed section payload.
    /// It is stored only for allocation reuse. This struct is still state-less.
    raw_buf: Vec<u8>,
    rdr: R,
}

impl<R: fmt::Debug + ?Sized> fmt::Debug for SectionReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SectionReader")
            .field("archive_start", &self.archive_start)
            .field(
                "raw_buf",
                &format_args!("{}/{}", self.raw_buf.len(), self.raw_buf.capacity()),
            )
            .field("rdr", &&self.rdr)
            .finish()
    }
}

impl<R> SectionReader<R> {
    /// Create a new section reader wrapping an existing random access stream,
    /// typically, [`std::fs::File`].
    ///
    /// You should NOT use [`BufReader`][std::io::BufReader] because sections
    /// are large enough and high-level abstractions like
    /// [`Archive`][crate::Archive] already has internal caching.
    pub fn new(rdr: R) -> Self {
        Self::new_with_offset(rdr, 0)
    }

    /// Same as [`Self::new`] but indicates the DwarFS archive is located at
    /// `archive_start` in `rdr` instead of the start. This is also known as
    /// `image_offset`.
    ///
    /// All read methods of [`SectionReader`] will add `archive_start` to its
    /// parameter for the real file offset if necessary.
    pub fn new_with_offset(rdr: R, archive_start: u64) -> Self {
        SectionReader {
            archive_start,
            raw_buf: Vec::new(),
            rdr,
        }
    }
}

impl<R: ?Sized> SectionReader<R> {
    /// Get a reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.rdr
    }

    /// Get a mutable reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.rdr
    }

    /// Retrieve the ownership of the underlying reader.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.rdr
    }
}

impl<R: ReadAt + ?Sized> SectionReader<R> {
    /// Get the `archive_start` set on creation.
    #[inline]
    #[must_use]
    pub fn archive_start(&self) -> u64 {
        self.archive_start
    }

    /// Read and decompress a full section at `offset` into memory.
    ///
    /// This is a combination of [`Self::read_header_at`] and [`Self::read_payload_at`].
    pub fn read_section_at(
        &mut self,
        section_offset: u64,
        payload_size_limit: usize,
    ) -> Result<(Header, Vec<u8>)> {
        let header = self.read_header_at(section_offset)?;
        // The header is read successfully, so the offset after the header will not overflow.
        let payload_offset = section_offset + HEADER_SIZE;
        let payload = self.read_payload_at(&header, payload_offset, payload_size_limit)?;
        Ok((header, payload))
    }

    /// Read a section header at `section_offset`.
    pub fn read_header_at(&mut self, section_offset: u64) -> Result<Header> {
        let file_offset = self
            .archive_start
            .checked_add(section_offset)
            .ok_or(ErrorInner::OffsetOverflow)?;
        let mut header = Header::new_zeroed();
        // For overflowing case, the read must fail because `HEADER_SIZE >= 2`.
        self.rdr.read_exact_at(file_offset, header.as_mut_bytes())?;
        header.magic_version.validate()?;
        Ok(header)
    }

    /// Read and decompress section payload of given header into a owned `Vec<u8>`.
    ///
    /// Same as [`Self::read_payload_at_into`] but return an `Vec<u8>` for
    /// convenience.
    pub fn read_payload_at(
        &mut self,
        header: &Header,
        payload_offset: u64,
        payload_size_limit: usize,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; payload_size_limit];
        let len = self.read_payload_at_into(header, payload_offset, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// Read and decompress section payload of given header into a buffer.
    ///
    /// `payload_offset` is the offset of the body of a section (after the header),
    /// from the start of archive. Both compressed and decompressed size must
    /// be within the `out.len()`, or an error will be emitted.
    pub fn read_payload_at_into(
        &mut self,
        header: &Header,
        payload_offset: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        let file_offset = self
            .archive_start
            .checked_add(payload_offset)
            .ok_or(ErrorInner::OffsetOverflow)?;

        let size_limit = out.len();
        let compressed_size = header.payload_size_limited(size_limit)?;
        let raw_buf = &mut self.raw_buf;
        raw_buf.resize(compressed_size, 0);
        self.rdr.read_exact_at(file_offset, raw_buf)?;
        header.validate_fast_checksum(raw_buf)?;

        match header.compress_algo {
            CompressAlgo::NONE => {
                out[..compressed_size].copy_from_slice(raw_buf);
                Ok(compressed_size)
            }
            #[cfg(feature = "zstd")]
            CompressAlgo::ZSTD => {
                let len = zstd::bulk::decompress_to_buffer(raw_buf, out)
                    .map_err(ErrorInner::Decompress)?;
                Ok(len)
            }
            #[cfg(feature = "lzma")]
            CompressAlgo::LZMA => (|| {
                let mut stream = xz2::stream::Stream::new_stream_decoder(u64::MAX, 0)?;
                let st = stream.process(raw_buf, out, xz2::stream::Action::Run)?;
                if stream.total_in() as usize != raw_buf.len()
                    || st != xz2::stream::Status::StreamEnd
                {
                    bail!(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "LZMA stream did not end cleanly",
                    ));
                }
                Ok(stream.total_out() as usize)
            })()
            .map_err(|err| ErrorInner::Decompress(err).into()),
            #[cfg(feature = "lz4")]
            CompressAlgo::LZ4 | CompressAlgo::LZ4HC => {
                let len = lz4::block::decompress_to_buffer(raw_buf, None, out)
                    .map_err(ErrorInner::Decompress)?;
                Ok(len)
            }
            // Not supported: FLAC (overlay specific), RICEPP (no much information or library).
            algo => Err(ErrorInner::UnsupportedCompressAlgo(algo).into()),
        }
    }

    /// Locate and read the section index, if there is any, with a limited payload size.
    ///
    /// `stream_len` is the total size of the input reader `R`, which is
    /// typically the whole file size.
    ///
    /// Note: Since there are currently no reliable way to ensure non-existent
    /// of the section index, this function will return `Err` for DwarFS archive
    /// without section index. We may change the behavior to return `Ok(None)`
    /// when there is a reliable way to do it.
    ///
    /// See: <https://github.com/mhx/dwarfs/issues/264>
    pub fn read_section_index(
        &mut self,
        stream_len: u64,
        payload_size_limit: usize,
    ) -> Result<Option<(Header, Vec<SectionIndexEntry>)>> {
        const INDEX_ENTRY_SIZE64: u64 = size_of::<SectionIndexEntry>() as u64;

        if stream_len < HEADER_SIZE + INDEX_ENTRY_SIZE64 {
            // TODO: Should this return `Ok(None)` instead?
            bail!(ErrorInner::MalformedSectionIndex(format!(
                "file size {stream_len}B is too small for an index"
            )));
        }

        let mut last_entry = SectionIndexEntry::new_zeroed();
        self.rdr
            .read_exact_at(stream_len - INDEX_ENTRY_SIZE64, last_entry.as_mut_bytes())?;
        let index_offset = last_entry.offset();

        if last_entry.section_type() != SectionType::SECTION_INDEX {
            bail!(ErrorInner::MalformedSectionIndex(format!(
                "wrong section type: {:?}",
                last_entry.section_type(),
            )));
        }
        let Some(payload_size) = (|| {
            stream_len
                .checked_sub(self.archive_start)?
                .checked_sub(index_offset)?
                .checked_sub(HEADER_SIZE)
                .filter(|size| *size > 0)
        })() else {
            bail!(ErrorInner::MalformedSectionIndex(format!(
                "invalid offset {index_offset} with no possible space for payload",
            )));
        };
        if payload_size % INDEX_ENTRY_SIZE64 != 0 {
            bail!(ErrorInner::MalformedSectionIndex(format!(
                "payload size {payload_size}B is not a multiple of index entries"
            )));
        }
        let header = self.read_header_at(index_offset)?;

        let num_sections = payload_size / INDEX_ENTRY_SIZE64;
        if header.section_type != SectionType::SECTION_INDEX
            || header.compress_algo != CompressAlgo::NONE
            || header.payload_size != payload_size
            || u64::from(header.section_number.get()) != num_sections - 1
        {
            bail!(ErrorInner::MalformedSectionIndex(format!(
                "invalid section index header: expect correct type, no compression, \
                payload size {}B, section number {}, got: {:?}",
                payload_size,
                num_sections - 1,
                header,
            )));
        }

        // Header is valid. Now read the index.
        if payload_size > payload_size_limit as u64 {
            bail!(ErrorInner::PayloadTooLong {
                got: payload_size,
                limit: payload_size_limit
            });
        }
        // The payload size does not overflow `usize`, so it / 8 must also does not.
        let mut buf =
            SectionIndexEntry::new_vec_zeroed(num_sections as usize).expect("alloc failed");
        let buf_bytes = buf.as_mut_bytes();
        debug_assert_eq!(buf_bytes.len() as u64, payload_size);
        self.rdr
            .read_exact_at(index_offset + HEADER_SIZE, buf_bytes)?;
        header.validate_fast_checksum(buf_bytes)?;
        Ok(Some((header, buf)))
    }
}
