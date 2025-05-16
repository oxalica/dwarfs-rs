use std::{
    fmt,
    io::{ErrorKind, Read, Seek, SeekFrom},
    mem::offset_of,
};

use xxhash_rust::xxh3::Xxh3Default;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, little_endian as le};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidMagic,
    MalformedSectionIndex,
    LengthMismatch,
    ChecksumMismatch,
    UnknowCompressAlgo(CompressAlgo),
    SectionTypeMismatch {
        expect: SectionType,
        got: SectionType,
    },
    SectionDataTooLong(usize),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Error::InvalidMagic => "invalid section magic",
            Error::MalformedSectionIndex => "malformed section index",
            Error::LengthMismatch => "length mismatch",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::UnknowCompressAlgo(algo) => {
                return write!(f, "unknown section compress algorithm {algo:?}");
            }
            Error::SectionTypeMismatch { expect, got } => {
                return write!(
                    f,
                    "section type mismatch, expect {expect:?} but got {got:?}"
                );
            }
            Error::SectionDataTooLong(cap) => {
                return write!(
                    f,
                    "section data is too long, exceeding the limit of {cap} bytes"
                );
            }

            Error::Io(err) => return err.fmt(f),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Error::Io(err) = self {
            Some(err)
        } else {
            None
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

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
    /// The 0-based index of this section in the DwarFS image.
    pub section_number: le::U32,
    /// The type of this section.
    pub section_type: SectionType,
    /// The compression algorithm of the section data.
    pub compress_algo: CompressAlgo,
    /// The length in bytes of the compressed data following.
    pub data_size: le::U64,
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
            .field("data_size", &self.data_size.get())
            .finish()
    }
}

impl Header {
    /// Validate section checksum of header and data using the "fast" XXH3-64 hash.
    pub fn validate_fast_checksum(&self, data: &[u8]) -> Result<()> {
        if data.len() as u64 != self.data_size.get() {
            return Err(Error::LengthMismatch);
        }
        let mut h = Xxh3Default::new();
        h.update(&self.as_bytes()[offset_of!(Self, section_number)..]);
        h.update(data);
        if h.digest() == u64::from_le_bytes(self.fast_hash) {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Validate section checksum of header and data using the "slow" SHA2-512/256 hash.
    pub fn validate_slow_checksum(&self, data: &[u8]) -> Result<()> {
        use sha2::Digest;

        if data.len() as u64 != self.data_size.get() {
            return Err(Error::LengthMismatch);
        }
        let mut h = sha2::Sha512_256::new();
        h.update(&self.as_bytes()[offset_of!(Self, fast_hash)..]);
        h.update(data);
        if h.finalize()[..] == self.slow_hash {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Check if this section header has the expected section type.
    pub(crate) fn check_type(&self, expect: SectionType) -> Result<()> {
        (self.section_type == expect)
            .then_some(())
            .ok_or(Error::SectionTypeMismatch {
                expect,
                got: self.section_type,
            })
    }

    fn data_size_limited(&self, limit: usize) -> Result<usize> {
        usize::try_from(self.data_size.get())
            .ok()
            .filter(|&n| n <= limit)
            .ok_or(Error::SectionDataTooLong(limit))
    }
}

/// Section magic and format version.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MagicVersion {
    pub magic: [u8; 6],
    pub major: u8,
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

    /// Validate if the magic matches and the format version is compatible with this library.
    pub fn validate(self) -> Result<()> {
        let ver = (self.major, self.minor);
        if self.magic == Self::MAGIC
            && crate::DWARFS_VERSION_MIN <= ver
            && ver <= crate::DWARFS_VERSION_MAX
        {
            Ok(())
        } else {
            Err(Error::InvalidMagic)
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
    /// The schema used to layout the [`Self::METADATA_V2`] block contents.
    METADATA_V2_SCHEMA = 7,
    /// The bulk of the root metadata.
    METADATA_V2 = 8,
    /// The index of all sections. This must be the last section if present.
    SECTION_INDEX = 9,
    /// File system history information.
    HISTORY = 10,
}

/// Compression algorithm used for section data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(2))]
pub struct CompressAlgo(pub le::U16);

impl_open_enum! {
    CompressAlgo; le::U16::new;
    NONE = 0,
    LZMA = 1,
    ZSTD = 2,
    LZ4 = 3,
    LZ4HC = 4,
    BROTLI = 5,
    FLAC = 6,
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
    pub fn section_type(self) -> SectionType {
        SectionType((self.0 >> 48).try_into().unwrap())
    }

    /// The offset of the section this entry is referring to,
    /// relative to the first section.
    pub fn offset(self) -> u64 {
        self.0.get() & ((1u64 << 48) - 1)
    }
}

/// The wrapper type for reading sections from a [`Read`] type.
#[derive(Debug)]
pub struct SectionReader<R: ?Sized> {
    rdr: R,
}

impl<R> SectionReader<R> {
    pub fn new(rdr: R) -> Self {
        Self { rdr }
    }
}

impl<R: ?Sized> SectionReader<R> {
    pub fn get_ref(&self) -> &R {
        &self.rdr
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.rdr
    }

    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.rdr
    }
}

impl<R: Read + ?Sized> SectionReader<R> {
    /// Read a section, limiting data size to `data_size_limit`.
    pub fn read_section(&mut self, data_size_limit: usize) -> Result<(Header, Vec<u8>)> {
        let header = self.read_header()?;
        let data = self.read_data(&header, data_size_limit)?;
        Ok((header, data))
    }

    /// Read a section header.
    pub fn read_header(&mut self) -> Result<Header> {
        let mut header = Header::new_zeroed();
        self.rdr.read_exact(header.as_mut_bytes())?;
        header.magic_version.validate()?;
        Ok(header)
    }

    /// Read an section header, or `None` if EOF is encountered.
    pub fn read_opt_header(&mut self) -> Result<Option<Header>> {
        let mut header = Header::new_zeroed();
        let mut rest = header.as_mut_bytes();
        while !rest.is_empty() {
            match self.rdr.read(rest) {
                Ok(0) => break,
                Ok(n) => {
                    rest = &mut rest[n..];
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => return Err(err.into()),
            }
        }
        if rest.is_empty() {
            header.magic_version.validate()?;
            Ok(Some(header))
        } else if rest.len() == size_of::<Header>() {
            Ok(None)
        } else {
            Err(std::io::Error::from(ErrorKind::UnexpectedEof).into())
        }
    }

    /// Read and decompress section data of given section header.
    ///
    /// Both compressed and decompressed size must be within `data_limit`, or an error is emitted.
    pub fn read_data(&mut self, header: &Header, data_size_limit: usize) -> Result<Vec<u8>> {
        let compressed_size = header.data_size_limited(data_size_limit)?;
        let mut compressed = vec![0u8; compressed_size];
        self.rdr.read_exact(&mut compressed)?;
        header.validate_fast_checksum(&compressed)?;

        match header.compress_algo {
            CompressAlgo::NONE => Ok(compressed),
            #[cfg(feature = "zstd")]
            CompressAlgo::ZSTD => {
                let mut out = vec![0u8; data_size_limit];
                let len = zstd::bulk::decompress_to_buffer(&compressed, &mut out)?;
                out.truncate(len);
                Ok(out)
            }
            #[cfg(feature = "lzma")]
            CompressAlgo::LZMA => {
                let mut out = vec![0u8; data_size_limit];
                (|| {
                    let mut stream = xz2::stream::Stream::new_stream_decoder(u64::MAX, 0)?;
                    let st = stream.process(&compressed, &mut out, xz2::stream::Action::Run)?;
                    if stream.total_in() as usize != compressed.len()
                        || st != xz2::stream::Status::StreamEnd
                    {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "LZMA stream did not end cleanly",
                        ));
                    }
                    out.truncate(stream.total_out() as usize);
                    Ok(())
                })()?;
                Ok(out)
            }
            #[cfg(feature = "lz4")]
            CompressAlgo::LZ4 | CompressAlgo::LZ4HC => {
                let mut out = vec![0u8; data_size_limit];
                let len = lz4::block::decompress_to_buffer(&compressed, None, &mut out)?;
                out.truncate(len);
                Ok(out)
            }
            // Not supported: FLAC (overlay specific), RICEPP (no much information or library).
            algo => Err(Error::UnknowCompressAlgo(algo)),
        }
    }

    /// Seek and read the section index, assuming its existence, with a limited data size.
    pub fn seek_read_section_index(
        &mut self,
        image_offset: u64,
        data_size_limit: usize,
    ) -> Result<(Header, Vec<SectionIndexEntry>)>
    where
        R: Seek,
    {
        let header = self.seek_read_section_index_header(image_offset)?;
        // Checked by header reader. So we can read raw bytes here.
        debug_assert_eq!(header.compress_algo, CompressAlgo::NONE);
        let data_size = header.data_size_limited(data_size_limit)?;

        let num_sections = data_size / size_of::<SectionIndexEntry>();
        let mut buf = SectionIndexEntry::new_vec_zeroed(num_sections).unwrap();
        let buf_bytes = buf.as_mut_bytes();
        debug_assert_eq!(buf_bytes.len(), data_size);

        self.rdr.read_exact(buf_bytes)?;
        header.validate_fast_checksum(buf_bytes)?;
        Ok((header, buf))
    }

    /// Seek and read the section index header, assuming its existence.
    // FIXME: How to handle unknown availability of section index?
    pub fn seek_read_section_index_header(&mut self, image_offset: u64) -> Result<Header>
    where
        R: Seek,
    {
        let last_entry_pos = self
            .rdr
            .seek(SeekFrom::End(-(size_of::<SectionIndexEntry>() as i64)))?;
        let rdr_end_pos = last_entry_pos + size_of::<SectionIndexEntry>() as u64;
        let last_ent = SectionIndexEntry::read_from_io(&mut self.rdr)?;

        if last_ent.section_type() != SectionType::SECTION_INDEX {
            return Err(Error::MalformedSectionIndex);
        }
        let Some(abs_offset) = image_offset.checked_add(last_ent.offset()) else {
            return Err(Error::MalformedSectionIndex);
        };
        self.rdr.seek(SeekFrom::Start(abs_offset))?;
        let header = self.read_header()?;

        let num_sections = header.data_size.get() / size_of::<SectionIndexEntry>() as u64;
        if header.section_type == SectionType::SECTION_INDEX
            && header.compress_algo == CompressAlgo::NONE
            && header.data_size.get() % size_of::<SectionIndexEntry>() as u64 == 0
            && u64::from(header.section_number.get()) + 1 == num_sections
            && abs_offset
                .checked_add(size_of::<Header>() as u64)
                .and_then(|x| x.checked_add(header.data_size.get()))
                == Some(rdr_end_pos)
        {
            Ok(header)
        } else {
            Err(Error::MalformedSectionIndex)
        }
    }
}
