//! The high-level interface for accessing a DwarFS archive.
//!
//! See [`Archive`] and [`ArchiveIndex`].

use std::{
    fmt,
    io::{BufRead, Read},
    iter::FusedIterator,
    num::NonZero,
};

use bstr::BString;
use lru::LruCache;
use positioned_io::{ReadAt, Size};

use crate::{
    fsst,
    metadata::{self, Error as ParserMetadataError, Metadata, Schema, StringTable},
    section::{self, HEADER_SIZE, SectionIndexEntry, SectionReader, SectionType},
};

/// Type alias using [`Error`] as the default error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error raised from parsing or accessing [`Archive`].
pub struct Error(Box<ErrorInner>);

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug)]
enum ErrorInner {
    Section(String, Option<section::Error>),
    MissingSection(SectionType),
    DuplicatedSection(SectionType),
    ParseMetadata(ParserMetadataError),
    SymbolTable(String, fsst::Error),
    UnsupportedFeature(String),
    Validation(&'static str),
    Io(std::io::Error),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            ErrorInner::Section(msg, Some(err)) => write!(f, "{msg}: {err}"),
            ErrorInner::Section(msg, None) => write!(f, "{msg}"),
            ErrorInner::MissingSection(ty) => write!(f, "missing section {ty:?}"),
            ErrorInner::DuplicatedSection(ty) => write!(f, "duplicated sections {ty:?}"),
            ErrorInner::Io(err) => write!(f, "input/outpur error: {err}"),
            ErrorInner::ParseMetadata(err) => write!(f, "failed to parse metadata: {err}"),
            ErrorInner::Validation(err) => write!(f, "malformed metadata: {err}"),
            ErrorInner::SymbolTable(msg, err) => write!(f, "{msg}: {err}"),
            ErrorInner::UnsupportedFeature(msg) => write!(f, "unsupported feature: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.0 {
            ErrorInner::Section(_, Some(err)) => Some(err),
            ErrorInner::Io(err) => Some(err),
            ErrorInner::ParseMetadata(err) => Some(err),
            ErrorInner::SymbolTable(_, err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorInner> for Error {
    #[cold]
    fn from(err: ErrorInner) -> Self {
        Self(Box::new(err))
    }
}

impl From<std::io::Error> for Error {
    #[cold]
    fn from(err: std::io::Error) -> Self {
        Self(Box::new(ErrorInner::Io(err)))
    }
}

// Needed for `Read` impl.
impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err)
    }
}

trait ResultExt<T> {
    fn context(self, msg: impl fmt::Display) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T, section::Error> {
    #[inline]
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(ErrorInner::Section(msg.to_string(), Some(err)).into()),
        }
    }
}
impl<T> ResultExt<T> for Result<T, fsst::Error> {
    #[inline]
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(ErrorInner::SymbolTable(msg.to_string(), err).into()),
        }
    }
}

trait OptionExt<T> {
    fn context(self, msg: &'static str) -> Result<T>;
}
impl<T> OptionExt<T> for Option<T> {
    #[inline]
    fn context(self, msg: &'static str) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => Err(ErrorInner::Validation(msg).into()),
        }
    }
}

trait BoolExt {
    fn or_context(self, msg: &'static str) -> Result<()>;
}
impl BoolExt for bool {
    #[inline]
    fn or_context(self, msg: &'static str) -> Result<()> {
        if self {
            Ok(())
        } else {
            Err(ErrorInner::Validation(msg).into())
        }
    }
}

/// Configurations and parameters for [`Archive`] and [`ArchiveIndex`].
#[derive(Debug, Clone)]
pub struct Config {
    section_index_size_limit: usize,
    metadata_schema_size_limit: usize,
    metadata_size_limit: usize,
    block_cache_size_limit: usize,

    section_index_strategy: SectionIndexStrategy,
}

/// Whether to trust the section index embedded in the archive?
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SectionIndexStrategy {
    /// Always use embedded section index.
    ///
    /// This guarantees consistent archive loading performance.
    /// But it is incompatible with archives without section index.
    UseEmbedded,
    /// Use embedded section index, or build our own if it does not exist.
    ///
    /// The default strategy, balancing between performance and compatibility.
    #[default]
    UseEmbeddedIfExists,
    /// Never use embedded section index but always build our own.
    ///
    /// During archive loading, all section headers will be traversed for
    /// building the index. This is the most defensive strategy which is robust
    /// on corrupted or fishy index that "happens to be like an index but there
    /// is actually none". But it significantly slows down archive
    /// loading due to heavy seeks.
    Build,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Some arbitrarily chosen numbers. Keep in sync with methods docs below!
            section_index_size_limit: 2 << 20,
            metadata_schema_size_limit: 16 << 10,
            metadata_size_limit: 64 << 20,
            // From `dwarfsextract`: 32 x 16MiB (default size) blocks.
            block_cache_size_limit: 512 << 20,
            section_index_strategy: SectionIndexStrategy::default(),
        }
    }
}

impl Config {
    /// Set the size limit for section index [`SECTION_INDEX`](SectionType::SECTION_INDEX).
    ///
    /// The default value is 2MiB. The section index is never compressed,
    /// and will be kept in memory in [`ArchiveIndex`].
    ///
    /// Each section occupies 8bytes in the index. Assuming the default block
    /// size 16MiB and 10% compression ratio, the default limit corresponds to
    /// 40TiB files compressed into an 4TiB archive, which is enough for typical use.
    pub fn section_index_size_limit(&mut self, limit: usize) -> &mut Self {
        self.section_index_size_limit = limit;
        self
    }

    /// Set the size limit for metadata schema section [`METADATA_V2_SCHEMA`](SectionType::METADATA_V2_SCHEMA).
    ///
    /// The default value is 16KiB. It limits both compressed and decompressed size,
    /// and is only used in duration of parsing metadata.
    ///
    /// The size of schema is almost constant and is typically <2KiB in practice.
    pub fn metadata_schema_size_limit(&mut self, limit: usize) -> &mut Self {
        self.metadata_schema_size_limit = limit;
        self
    }

    /// Set the size limit for metadata section [`METADATA_V2`](SectionType::METADATA_V2).
    ///
    /// The default value is 64MiB. It limits both compressed and decompressed size,
    /// and will be kept in memory in [`ArchiveIndex`].
    /// Note that this does NOT count bit-packing and delta-packing. The memory
    /// footprint can be more than 8 times the packed size, though it is hardly
    /// achievable in practice.
    ///
    /// The size of metadata scales linearly with the directory hierarchy,
    /// number of inodes, and the total file name and symlink length.
    /// Packed metadata may be smaller.
    ///
    /// As a reference, the DwarFS archive of Linux 6.7 source tree has metadata
    /// size of 2.2MiB, which is 1.4% of the 152MiB archive.
    /// You may want to increase this limit for larger archive.
    pub fn metadata_size_limit(&mut self, limit: usize) -> &mut Self {
        self.metadata_size_limit = limit;
        self
    }

    /// The size limit for LRU cache of decompressed data blocks.
    ///
    /// The default value is 512MiB. This also serves as a block size limit,
    /// because the cache must be able to contain at least one block.
    ///
    /// Block cache size is highly related with performance. For highly
    /// fragmented files, a too small block cache can severely hurt performance
    /// to more than 10x slower.
    ///
    /// For extraction from archive, sorting file locations
    /// ([`Chunk::section_idx`]) before read can improve locality and mitigate
    /// the drawback of a small cache. But for random access (like FUSE), a
    /// larger cache is always preferred.
    pub fn block_cache_size_limit(&mut self, limit: usize) -> &mut Self {
        self.block_cache_size_limit = limit;
        self
    }

    /// The strategy to use embedded section index.
    ///
    /// The default value is [`SectionIndexStrategy::UseEmbeddedIfExists`].
    /// See [`SectionIndexStrategy`] for details.
    pub fn section_index_strategy(&mut self, strategy: SectionIndexStrategy) -> &mut Self {
        self.section_index_strategy = strategy;
        self
    }
}

/// The index of a DwarFS archive representing the whole hierarchy.
///
/// This struct is immutable, and is separated from [`Archive`] for easier
/// lifetime management.
///
/// Use [`Archive::new`] to parse and create a pair of [`ArchiveIndex`] and
/// [`Archive`].
///
/// You usually start at [`ArchiveIndex::root`] to get the root directory in the
/// archive and walking or searching on the directory tree. [`File`] content can
/// be read via [`AsChunks`], or by manually iterating its [`Chunk`]s and
/// invokes [`Chunk::read_cached`]. You need to supply `&mut Archive`
/// corresponding to this index only when reading file contents.
pub struct ArchiveIndex {
    section_index: Box<[SectionIndexEntry]>,
    metadata: Metadata,

    mtime_only: bool,
    time_resolution: NonZero<u32>,
    timestamp_base_scaled: u64,
    inode_tally: InodeTally,
}

impl fmt::Debug for ArchiveIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alt = f.alternate();
        let mut d = f.debug_struct("ArchiveIndex");
        if alt {
            // NB. Always hide large structs.
            d.field("mtime_only", &self.mtime_only)
                .field("time_resolution", &self.time_resolution)
                .field("timestamp_base_scaled", &self.timestamp_base_scaled)
                .field("inode_tally", &self.inode_tally);
        }
        d.finish_non_exhaustive()
    }
}

/// Pre-calculated sums for type classification.
#[derive(Debug, Default)]
struct InodeTally {
    /// The number of unique files.
    unique_cnt: u32,

    // ..directories..
    symlink_start: u32,
    // ..symlinks..
    unique_start: u32,
    // ..unique regular files..
    shared_start: u32,
    // ..shared regular files..
    device_start: u32,
    // ..device files..
    ipc_start: u32,
    // ..fifo and sockets..
}

impl ArchiveIndex {
    /// Parse and create the index of a DwarFS archive.
    ///
    /// This is a low-level methods. Usually you should use [`Archive::new`] to
    /// get a pair of [`ArchiveIndex`] and [`Archive`] instead.
    pub fn new_with_config<R: ReadAt + Size>(
        rdr: &mut SectionReader<R>,
        config: &Config,
    ) -> Result<Self> {
        let stream_len = rdr.get_ref().size()?.ok_or_else(|| {
            ErrorInner::Section("cannot get the size of the archive reader".into(), None)
        })?;
        Self::new_inner(rdr, stream_len, config)
    }

    fn new_inner(
        rdr: &mut SectionReader<dyn ReadAt + '_>,
        stream_len: u64,
        config: &Config,
    ) -> Result<Self> {
        trace_time!("initialize ArchiveIndex");

        // Load or build the section index.
        let section_index = (|| {
            use SectionIndexStrategy as S;

            let strategy = &config.section_index_strategy;
            if matches!(strategy, S::UseEmbedded | S::UseEmbeddedIfExists) {
                if let Some((_, index)) = rdr
                    .read_section_index(stream_len, config.section_index_size_limit)
                    .context("failed to read section index")?
                {
                    return Ok(index);
                }
                if *strategy == S::UseEmbedded {
                    bail!(ErrorInner::MissingSection(SectionType::SECTION_INDEX))
                }
            }

            trace_time!("build section index");
            rdr.build_section_index(stream_len, config.section_index_size_limit)
                .context("failed to build section index")
        })()?;

        trace!("archive contains {} sections", section_index.len());
        u32::try_from(section_index.len())
            .ok()
            .context("too many sections")?;
        let section_index = section_index.into_boxed_slice();

        // Find metadata sections.
        let find_unique_section = |sec_ty: SectionType| -> Result<u64> {
            let mut iter = section_index
                .iter()
                .rev()
                .filter_map(|ent| (ent.section_type() == sec_ty).then_some(ent.offset()));
            let off = iter.next().ok_or(ErrorInner::MissingSection(sec_ty))?;
            if iter.next().is_some() {
                bail!(ErrorInner::DuplicatedSection(sec_ty));
            }
            Ok(off)
        };
        let schema_offset = find_unique_section(SectionType::METADATA_V2_SCHEMA)?;
        let metadata_offset = find_unique_section(SectionType::METADATA_V2)?;

        // Load and unpack metadata.
        let metadata = {
            trace_time!("parse schema and metadata");

            let (_, raw_schema) = rdr
                .read_section_at(schema_offset, config.metadata_schema_size_limit)
                .context("failed to read metadata schema section")?;
            let schema = Schema::parse(&raw_schema).map_err(ErrorInner::ParseMetadata)?;

            let (_, raw_metadata) = rdr
                .read_section_at(metadata_offset, config.metadata_size_limit)
                .context("failed to read metadata section")?;
            Metadata::parse(&schema, &raw_metadata).map_err(ErrorInner::ParseMetadata)?
        };

        let mut this = Self {
            section_index,
            metadata,

            mtime_only: false,
            time_resolution: NonZero::new(1).expect("1 is non-zero"),
            timestamp_base_scaled: 0,
            inode_tally: Default::default(),
        };
        this.unpack_validate()?;
        Ok(this)
    }

    /// Guard on filesystem features, unpack packed fields, build decoders and validate index ranges.
    fn unpack_validate(&mut self) -> Result<()> {
        trace_time!("unpack and validate full metadata content");
        let m = &mut self.metadata;

        // Explicit future-incompatible features.
        if let Some(feat) = &m.features {
            if !feat.is_empty() {
                bail!(ErrorInner::UnsupportedFeature(format!("{feat:?}")));
            }
        }

        let dir_entries = m
            .dir_entries
            .as_ref()
            // The first entry is for the root directory.
            .filter(|ents| !ents.is_empty())
            .context("dir_entries must be present since DwarFS 2.3")?;

        // Various `FsOptions`.
        if let Some(opts) = &m.options {
            self.mtime_only = opts.mtime_only;
            self.time_resolution = NonZero::new(opts.time_resolution_sec.unwrap_or(1))
                .context("invalid options.time_resolution_sec")?;
            self.timestamp_base_scaled = m
                .timestamp_base
                .checked_mul(self.time_resolution.get().into())
                .context("timestamp_base overflow")?;

            if opts.packed_chunk_table {
                trace_time!("unpack chunk_table");

                let mut sum = 0u32;
                for c in &mut m.chunk_table {
                    sum = c
                        .checked_add(sum)
                        .context("value overflow for packed chunk_table")?;
                    *c = sum;
                }
            }

            if opts.packed_directories {
                trace_time!("unpack directories");

                let mut sum = 0u32;
                for dir in &mut m.directories {
                    sum = sum
                        .checked_add(dir.first_entry)
                        .context("value overflow for packed directories.first_entry")?;
                    dir.first_entry = sum;
                }
            }

            if let Some(shared) = m
                .shared_files_table
                .as_ref()
                .filter(|_| opts.packed_shared_files_table)
            {
                trace_time!("unpack shared files");

                let unpacked_len = std::iter::zip(shared, 2..)
                    .try_fold(0u32, |sum, (&cnt, dups)| {
                        cnt.checked_mul(dups)?.checked_add(sum)
                    })
                    // Use inode count as a loose upper bound, to guard from length exploding.
                    .filter(|&n| n < m.inodes.len() as u32)
                    .context("length overflow for packed shared files")?;
                let mut unpacked = Vec::with_capacity(unpacked_len as usize);
                unpacked.extend(
                    std::iter::zip(shared, 2usize..)
                        .flat_map(|(&cnt, dups)| std::iter::repeat_n(cnt, dups)),
                );
                m.shared_files_table = Some(unpacked);
            }
        }

        // Inode classification ranges.
        {
            trace_time!("classify inode types");

            // NB. Minus the sentinel.
            let dir_cnt = m.directories.len().saturating_sub(1);
            let file_store_cnt = m.chunk_table.len().saturating_sub(1);
            (dir_cnt >= 1).or_context("missing root directory")?;

            // Lengths will not overflow `u32`, checked by metadata parser.
            // And of course they cannot overflow `usize` because they are all in memory.
            let symlink_cnt = m.symlink_table.len();
            let device_cnt = m.devices.as_ref().map_or(0, |t| t.len());
            let inode_cnt = m.inodes.len();
            let shared_cnt = m.shared_files_table.as_ref().map_or(0, |v| v.len());
            let shared_store_cnt = m
                .shared_files_table
                .as_ref()
                .and_then(|v| v.last().copied())
                .map_or(Ok(0), |max_idx| {
                    max_idx
                        .checked_add(1)
                        .context("index out of range in shared_files_table")
                })?;
            let unique_cnt = (file_store_cnt as u32)
                .checked_sub(shared_store_cnt)
                .context("invalid shared file count")?;

            let unique_start = dir_cnt + symlink_cnt;
            let shared_start = unique_start + unique_cnt as usize;
            let device_start = shared_start + shared_cnt;
            let ipc_start = device_start + device_cnt;
            (ipc_start <= inode_cnt).or_context("inodes table too short")?;

            self.inode_tally = InodeTally {
                unique_cnt,
                symlink_start: dir_cnt as u32,
                unique_start: unique_start as u32,
                shared_start: shared_start as u32,
                device_start: device_start as u32,
                ipc_start: ipc_start as u32,
            };
        }

        // Unpack string tables, currently `compact_{names,symlinks}`.
        fn unpack_string_table(
            tbl: &mut Option<StringTable>,
            msg_index: &'static str,
            msg_symtab: &'static str,
            msg_decode: &'static str,
        ) -> Result<()> {
            trace_time!("unpack symtab");

            let Some(tbl) = tbl else { return Ok(()) };
            let len = tbl.buffer.len() as u32;
            if tbl.packed_index {
                let mut sum = 0u32;
                for v in &mut tbl.index {
                    // NB. The packed value starts with the delta between the first two elements.
                    // That is: [0, 3, 7] is packed into [3, 4], with one less element.
                    // Thus during unpacking, the element should be updated to
                    // the sum of all previous elements, excluding itself.
                    let old = *v;
                    *v = sum;
                    sum = sum
                        .checked_add(old)
                        .filter(|&i| i <= len)
                        .context(msg_index)?;
                }
                // Fix the omitted last element.
                tbl.index.push(sum);

            // If symtab is used, the decoding process below will validate index ranges anyway.
            } else if tbl.symtab.is_none() {
                tbl.index.is_sorted().or_context(msg_index)?;
                if let Some(last_idx) = tbl.index.last() {
                    (*last_idx <= len).or_context(msg_index)?;
                }
            }
            if let Some(symtab_bytes) = &tbl.symtab {
                let symtab = fsst::Decoder::parse(symtab_bytes).context(msg_symtab)?;
                let encoded = &tbl.buffer[..];
                // The decoded length must be greater than encoded length to
                // worth it, so 1x is not enough. Pick 2x as the least bound here.
                // Also note that `isize::MAX as usize * 2` never overflows.
                let mut out_buf = Vec::with_capacity(encoded.len() * 2);
                let mut out_index = Vec::with_capacity(tbl.index.len());
                let mut out_len = 0usize;
                out_index.push(0);
                for w in tbl.index.windows(2) {
                    let sym = encoded
                        .get(w[0] as usize..w[1] as usize)
                        .context(msg_index)?;
                    let sym_dec_len = fsst::Decoder::max_decode_len(sym.len());
                    out_buf.resize(out_len + sym_dec_len, 0);
                    let sym_out = &mut out_buf[out_len..out_len + sym_dec_len];
                    let len = symtab.decode_into(sym, sym_out).context(msg_decode)?;
                    // Each decoded symbol must be in UTF-8.
                    str::from_utf8(&sym_out[..len]).ok().context(msg_decode)?;
                    out_len += len;

                    // This is suboptimal, because it *is* possible that the total length of
                    // decoded strings overflows u32, that is 4GiB names compressed into 512MiB.
                    // I don't think it's practically viable without exceeding the whole metadata
                    // size limit. Emitting a decoding error in this case seems acceptable to me.
                    let pos = u32::try_from(out_len).ok().context(msg_decode)?;
                    out_index.push(pos);
                }
                debug_assert_eq!(out_index.len(), tbl.index.len());
                out_buf.truncate(out_len);

                tbl.buffer = out_buf.into();
                tbl.index = out_index;
            }
            Ok(())
        }

        (m.compact_names.is_none() || m.names.is_empty())
            .or_context("names must be empty when compact_names is used")?;
        unpack_string_table(
            &mut m.compact_names,
            "invalid index for compact_names.index",
            "failed to parse compact_names.symtab",
            "failed to decode compact_names.buffer using symtab",
        )?;

        (m.compact_symlinks.is_none() || m.symlinks.is_empty())
            .or_context("symlinks must be empty when compact_symlinks is used")?;
        unpack_string_table(
            &mut m.compact_symlinks,
            "invalid index for compact_symlinks.index",
            "failed to parse compact_symlinks.symtab",
            "failed to decode compact_symlinks.buffer using symtab",
        )?;

        // Validate contents, mostly about indexes.
        // TODO: Maybe just cache the indirection result?
        {
            trace_time!("check index and values are in ranges");

            macro_rules! check {
                ($cond:expr, $msg:literal) => {
                    $cond.or_context(concat!("index out of range in ", $msg))?
                };
            }

            let block_size = m.block_size;
            (usize::try_from(block_size).is_ok() && block_size.is_power_of_two())
                .or_context("invalid block_size")?;

            let sections = self.section_index.len() as u32;
            for c in &m.chunks {
                check!(c.block < sections, "chunks.block");
                c.offset
                    .checked_add(c.size)
                    .filter(|&end| end <= block_size)
                    .context("offset out of range in chunks")?;
            }

            let entries = dir_entries.len() as u32;
            for d in &m.directories {
                check!(d.first_entry <= entries, "directories.first_entry");
                check!(d.parent_entry <= entries, "directories.parent_entry");
                check!(d.self_entry <= entries, "directories.self_entry");
            }

            let uids = m.uids.len() as u32;
            let gids = m.gids.len() as u32;
            let modes = m.modes.len() as u32;
            let check_time = |time_off: u32, msg: &'static str| {
                u64::from(time_off)
                    .checked_mul(self.time_resolution.get().into())
                    .and_then(|x| x.checked_add(m.timestamp_base))
                    .context(msg)
            };
            for ino in &m.inodes {
                check!(ino.owner_index < uids, "inodes.owner_index");
                check!(ino.group_index < gids, "inodes.group_index");
                check!(ino.mode_index < modes, "inodes.mode_index");
                check_time(ino.mtime_offset, "inodes.mtime_offset overflows")?;
                if self.mtime_only {
                    (ino.atime_offset == 0 && ino.ctime_offset == 0).or_context(
                        "inodes.{a,c}time_offset is not zero when options.mtime_only is set",
                    )?;
                } else {
                    check_time(ino.atime_offset, "inodes.atime_offset overflows")?;
                    check_time(ino.ctime_offset, "inodes.ctime_offset overflows")?;
                }
            }

            let chunks = m.chunks.len() as u32;
            for &c in &m.chunk_table {
                check!(c <= chunks, "chunk_table");
            }

            let symlink_targets = m
                .compact_symlinks
                .as_ref()
                .map_or(m.symlinks.len(), |tbl| tbl.index.len().saturating_sub(1))
                as u32;
            for &i in &m.symlink_table {
                check!(i < symlink_targets, "symlink_table");
            }

            let inodes = m.inodes.len() as u32;
            let names = m
                .compact_names
                .as_ref()
                .map_or(m.names.len(), |tbl| tbl.index.len().saturating_sub(1))
                as u32;
            // The root entry's `name_index` is a placeholder and must not be used.
            for ent in &dir_entries[1..] {
                check!(ent.inode_num < inodes, "dir_entries.inode_num");
                check!(ent.name_index < names, "dir_entries.name_index");
            }

            (dir_entries[0].inode_num == 0).or_context("invalid dir_entries[0].inode_num")?;
        }

        Ok(())
    }

    fn get_from_string_table<'a>(
        loose: &'a [BString],
        compact: &'a Option<StringTable>,
        idx: u32,
    ) -> &'a str {
        let s = if let Some(tbl) = compact {
            let idx_start = tbl.index[idx as usize] as usize;
            let idx_end = tbl.index[idx as usize + 1] as usize;
            &tbl.buffer[idx_start..idx_end]
        } else {
            &loose[idx as usize]
        };
        // TODO: Avoid re-validate the whole symbol?
        str::from_utf8(s).expect("validated")
    }

    /// Get the root directory of the archive.
    #[inline]
    #[must_use]
    pub fn root(&self) -> Dir<'_> {
        Dir(Inode {
            index: self,
            inode_num: 0,
        })
    }

    /// Get the inode under the given path from the root directory of the archive.
    ///
    /// ```
    /// use dwarfs::{ArchiveIndex, Inode};
    ///
    /// # fn work() -> Option<()> {
    /// let index: ArchiveIndex;
    /// # index = unimplemented!();
    /// // These two statements are equivalent.
    /// let baz1: Inode<'_> = index.get_path("src/lib.rs".split('/'))?;
    /// let baz2: Inode<'_> = index.root().get("src")?.inode().as_dir()?.get("lib.rs")?.inode();
    /// # None }
    /// ```
    #[must_use]
    pub fn get_path<I>(&self, path: I) -> Option<Inode<'_>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        path.into_iter()
            .try_fold(Inode::from(self.root()), |inode, name| {
                Some(inode.as_dir()?.get(name)?.inode())
            })
    }

    /// Get an iterator over all inodes in the archive, in ascending inode number.
    #[inline]
    #[must_use]
    pub fn inodes(&self) -> impl ExactSizeIterator<Item = Inode<'_>> + DoubleEndedIterator + '_ {
        let cnt = self.metadata().inodes.len() as u32;
        (0..cnt).map(|inode_num| Inode {
            index: self,
            inode_num,
        })
    }

    /// Get an iterator over all directory inodes in the archive, in ascending inode number.
    #[inline]
    #[must_use]
    pub fn directories(&self) -> impl ExactSizeIterator<Item = Dir<'_>> + DoubleEndedIterator + '_ {
        let cnt = self.inode_tally.symlink_start;
        (0..cnt).map(|inode_num| {
            Dir(Inode {
                index: self,
                inode_num,
            })
        })
    }

    /// Lookup an inode by its inode number.
    #[inline]
    #[must_use]
    pub fn get_inode(&self, inode_num: u32) -> Option<Inode<'_>> {
        (inode_num < self.metadata().inodes.len() as u32).then_some(Inode {
            index: self,
            inode_num,
        })
    }

    /// Get the low-level section index.
    #[inline]
    #[must_use]
    pub fn section_index(&self) -> &[SectionIndexEntry] {
        &self.section_index
    }

    // NB. The stored metadata is partly unpacked and/or modified.
    // It may not be a good to expose it.
    #[inline]
    #[must_use]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

/// A DwarFS archive wrapping reader `R`.
///
/// Usually, you create a pair of [`Archive`] and [`ArchiveIndex`] using
/// [`Archive::new`]. Directory hierarchy traversal can be done only on
/// `ArchiveIndex`, and this struct is only needed for reading file content.
///
/// See also [`ArchiveIndex`].
#[derive(Debug)]
pub struct Archive<R: ?Sized> {
    /// LRU cache of block idx -> block content.
    cache: LruCache<u32, Vec<u8>>,
    block_size: u32,

    rdr: SectionReader<R>,
}

impl<R: ReadAt + Size> Archive<R> {
    /// Load a DwarFS archive from a random-access stream,
    /// typically a [`std::fs::File`].
    ///
    /// Note 1: Do not use [`BufReader`][std::io::BufReader], because
    /// [`Archive`] already has internal caches. Use
    /// [`Config::block_cache_size_limit`] to configure its size.
    ///
    /// Note 2: It's *discouraged* to use [`positioned_io::RandomAccessFile`] on *NIX
    /// platforms because that would disable readahead which can hurt performance on
    /// sequential read inside a several MiB section.
    /// On Windows, however, `RandomAccessFile` is several times faster than `File`.
    pub fn new(rdr: R) -> Result<(ArchiveIndex, Self)> {
        Self::new_with_config(rdr, &Config::default())
    }

    /// Same as [`Archive::new`] but with a non-default [`Config`].
    pub fn new_with_config(rdr: R, config: &Config) -> Result<(ArchiveIndex, Self)> {
        let mut rdr = SectionReader::new(rdr);
        let index = ArchiveIndex::new_with_config(&mut rdr, config)?;
        let this = Self::new_with_index_and_config(rdr, &index, config)?;
        Ok((index, this))
    }

    /// The low-level method for creating an `Archive` with already parsed `ArchiveIndex`.
    pub fn new_with_index_and_config(
        rdr: SectionReader<R>,
        index: &ArchiveIndex,
        config: &Config,
    ) -> Result<Self> {
        let block_size = index.metadata().block_size;
        let cache_len = NonZero::new(config.block_cache_size_limit / block_size as usize)
            .ok_or_else(|| {
                let msg = format!(
                    "block size {}B exceeds cache size limit {}B",
                    block_size, config.block_cache_size_limit
                );
                ErrorInner::Section(msg, None)
            })?;
        Ok(Self {
            cache: LruCache::new(cache_len),
            block_size,
            rdr,
        })
    }
}

impl<R: ReadAt + ?Sized> Archive<R> {
    /// Cache a block section's content if it's not available yet.
    ///
    /// Calculates file offset, handles cache miss and out-of-range errors on short read.
    fn cache_block(&mut self, index: &ArchiveIndex, section_idx: u32) -> Result<()> {
        // NB. Use `get` instead of `contains` to promote it to MRU.
        if self.cache.get(&section_idx).is_some() {
            trace!("block {section_idx}: cache hit");
            return Ok(());
        }

        trace_time!("block {section_idx}: cache miss");

        let section_offset = index.section_index()[section_idx as usize].offset();
        let payload_offset = section_offset + HEADER_SIZE;

        (|| {
            let header = self.rdr.read_header_at(section_offset)?;
            header.check_type(SectionType::BLOCK)?;

            // Reuse existing buffer.
            let mut buf = if self.cache.len() == self.cache.cap().get() {
                let (_, mut buf) = self.cache.pop_lru().expect("not empty");
                buf.resize(self.block_size as usize, 0);
                buf
            } else {
                vec![0u8; self.block_size as usize]
            };
            let len = self
                .rdr
                .read_payload_at_into(&header, payload_offset, &mut buf)?;
            buf.truncate(len);
            self.cache.push(section_idx, buf);

            Ok::<_, section::Error>(())
        })()
        .context(format_args!("failed to read block {section_idx}"))
    }

    /// Get a chunk inside the most recently cached block.
    fn get_chunk_in_cache(&self, start: u32, end: u32) -> Result<&[u8]> {
        let (&section_idx, cache) = self.cache.peek_mru().expect("cache is empty");
        let chunk = cache.get(start as usize..end as usize).ok_or_else(
            #[cold]
            || {
                let cache_len = cache.len();
                let msg = format!(
                    "block {section_idx} has only {cache_len} bytes \
                    but is referenced at {start}..{end}",
                );
                ErrorInner::Section(msg, None)
            },
        )?;
        Ok(chunk)
    }
}

impl<R> Archive<R> {
    /// Retrieve the ownership of the underlying reader.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.rdr.into_inner()
    }

    /// Get a reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &R {
        self.rdr.get_ref()
    }

    /// Get a mutable reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self) -> &mut R {
        self.rdr.get_mut()
    }
}

/// The trait for [`Inode`] sub-types.
pub trait IsInode<'a>: Sized + sealed::Sealed {
    /// Convert into a generic [`Inode`].
    #[must_use]
    fn to_inode(&self) -> Inode<'a>;

    /// Get the inode number in the DwarFS archive.
    #[must_use]
    fn inode_num(&self) -> u32 {
        self.to_inode().inode_num
    }

    /// Get the metadata of this inode.
    #[inline]
    #[must_use]
    fn metadata(&self) -> InodeMetadata<'a> {
        self.to_inode().metadata()
    }
}

macro_rules! impl_inode_subtype {
    ($name:ident) => {
        impl_inode_subtype!($name, self, { self.0 });
    };
    ($name:ident, $self_:tt, $to_inode:block) => {
        impl sealed::Sealed for $name<'_> {}
        impl<'a> IsInode<'a> for $name<'a> {
            #[inline]
            fn to_inode(&$self_) -> Inode<'a> $to_inode
        }
        impl<'a> From<$name<'a>> for Inode<'a> {
            fn from(this: $name<'a>) -> Inode<'a> {
                this.to_inode()
            }
        }
    };
}

/// A generic inode.
#[derive(Debug, Clone, Copy)]
pub struct Inode<'a> {
    index: &'a ArchiveIndex,
    inode_num: u32,
}

// This implementation is specialized. No need to generate `From` impls.
impl sealed::Sealed for Inode<'_> {}
impl<'a> IsInode<'a> for Inode<'a> {
    #[inline]
    fn to_inode(&self) -> Inode<'a> {
        *self
    }

    #[inline]
    fn inode_num(&self) -> u32 {
        self.inode_num
    }

    #[inline]
    fn metadata(&self) -> InodeMetadata<'a> {
        self.metadata()
    }
}

impl<'a> Inode<'a> {
    /// Classify this generic inode to an enum of inode kinds.
    #[must_use]
    pub fn classify(self) -> InodeKind<'a> {
        let Self { index, inode_num } = self;
        let t = &index.inode_tally;
        if inode_num < t.symlink_start {
            InodeKind::Directory(Dir(self))
        } else if inode_num < t.unique_start {
            InodeKind::Symlink(Symlink(self))
        } else if inode_num < t.device_start {
            InodeKind::File(File(self))
        } else if inode_num < t.ipc_start {
            InodeKind::Device(Device(self))
        } else {
            InodeKind::Ipc(Ipc(self))
        }
    }

    /// Shortcut method to check if this is a directory inode.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.classify(), InodeKind::Directory(_))
    }

    /// Shortcut method to check if this is a regular file inode.
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self.classify(), InodeKind::File(_))
    }

    /// Shortcut method to convert to [`Dir`] if it is a directory.
    #[must_use]
    pub fn as_dir(&self) -> Option<Dir<'a>> {
        if let InodeKind::Directory(dir) = self.classify() {
            Some(dir)
        } else {
            None
        }
    }

    /// Shortcut method to convert to [`File`] if it is a regular file.
    #[must_use]
    pub fn as_file(&self) -> Option<File<'a>> {
        if let InodeKind::File(file) = self.classify() {
            Some(file)
        } else {
            None
        }
    }

    /// Get the metadata of this inode.
    #[must_use]
    pub fn metadata(&self) -> InodeMetadata<'a> {
        InodeMetadata::new(self.index, self.inode_num)
    }
}

/// An inode, classified by its kind.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum InodeKind<'a> {
    /// A directory inode.
    Directory(Dir<'a>),
    /// A symlink inode.
    Symlink(Symlink<'a>),
    /// A regular file inode.
    File(File<'a>),
    /// A block or character device inode.
    Device(Device<'a>),
    /// A pipe or socket inode.
    Ipc(Ipc<'a>),
}

impl_inode_subtype!(InodeKind, self, {
    match self {
        InodeKind::Directory(i) => i.0,
        InodeKind::Symlink(i) => i.0,
        InodeKind::File(i) => i.0,
        InodeKind::Device(i) => i.0,
        InodeKind::Ipc(i) => i.0,
    }
});

/// The minimal wrapper of DwarFS "mode", with `Debug` and `Display` impl.
///
/// In DwarFS, a "mode" encodes both file type (`S_IFMT`) and
/// permission bits, like `stat.st_mode` field from `stat(2)`.
/// This type is named so instead of `Mode` to avoid ambiguaity.
///
/// See: <https://man.archlinux.org/man/inode.7.en#The_file_type_and_mode>
///
/// For high-level wrappers, check
/// [`rustix::fs::Mode`](https://docs.rs/rustix/1/rustix/fs/struct.Mode.html)
/// and
/// [`rustix::fs::FileType`](https://docs.rs/rustix/1/rustix/fs/enum.FileType.html).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileTypeMode(pub u32);

impl fmt::Debug for FileTypeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0o{:04o}/{}", self.0, self)
    }
}

impl fmt::Octal for FileTypeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for FileTypeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Magic numbers are from:
        // <https://man.archlinux.org/man/inode.7.en#The_file_type_and_mode>
        let mut s = [0u8; 10];
        s[0] = match self.type_bits() {
            0o140000 => b's',
            0o120000 => b'l',
            0o100000 => b'-',
            0o060000 => b'b',
            0o040000 => b'd',
            0o020000 => b'c',
            0o010000 => b'p',
            _ => b'?',
        };
        let fmt_perm = |s: &mut [u8], m: u32, alt: u32, altch: u8| {
            s[0] = if m & 4 != 0 { b'r' } else { b'-' };
            s[1] = if m & 2 != 0 { b'w' } else { b'-' };
            let (xset, xunset) = if alt != 0 {
                (altch, altch.to_ascii_uppercase())
            } else {
                (b'x', b'-')
            };
            s[2] = if m & 1 != 0 { xset } else { xunset };
        };
        let m = self.0;
        fmt_perm(&mut s[1..4], m >> 6, m & 0o4000, b's');
        fmt_perm(&mut s[4..7], m >> 3, m & 0o2000, b's');
        fmt_perm(&mut s[7..10], m, m & 0o1000, b't');

        f.pad(str::from_utf8(&s).expect("all ASCII"))
    }
}

impl FileTypeMode {
    /// Get the bits representing the file type (`S_IFMT`).
    #[inline]
    #[must_use]
    pub fn type_bits(self) -> u32 {
        self.0 & 0o170000
    }

    /// Get the bits representing the file mode (`0o7777`).
    #[inline]
    #[must_use]
    pub fn mode_bits(self) -> u32 {
        self.0 & 0o7777
    }

    /// Get the bits representing the file permissions (`0o777`).
    #[inline]
    #[must_use]
    pub fn permission_bits(self) -> u32 {
        self.0 & 0o777
    }
}

/// The metadata of an inode.
#[derive(Debug, Clone, Copy)]
pub struct InodeMetadata<'a> {
    index: &'a ArchiveIndex,
    // Use reference to minimize size.
    data: &'a metadata::InodeData,
}

impl<'a> InodeMetadata<'a> {
    fn new(index: &'a ArchiveIndex, inode_num: u32) -> Self {
        let data = &index.metadata().inodes[inode_num as usize];
        Self { index, data }
    }

    /// The DwarFS mode of the inode, including file type and permissions.
    #[inline]
    #[must_use]
    pub fn file_type_mode(&self) -> FileTypeMode {
        FileTypeMode(self.index.metadata().modes[self.data.mode_index as usize])
    }

    /// The owner user id (uid) of the inode.
    #[inline]
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.index.metadata().uids[self.data.owner_index as usize]
    }

    /// The owner group id (gid) of the inode.
    #[inline]
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.index.metadata().gids[self.data.group_index as usize]
    }

    #[inline]
    fn cvt_time(&self, time_offset: u32) -> u64 {
        self.index.timestamp_base_scaled
            + u64::from(time_offset) * u64::from(self.index.time_resolution.get())
    }

    /// The last modified time, in the seconds since UNIX epoch.
    #[inline]
    #[must_use]
    pub fn mtime(&self) -> u64 {
        self.cvt_time(self.data.mtime_offset)
    }

    /// The last accessed time, in the seconds since UNIX epoch.
    ///
    /// Returns `None` if the archive stores no such information.
    #[inline]
    #[must_use]
    pub fn atime(&self) -> Option<u64> {
        (!self.index.mtime_only).then(|| self.cvt_time(self.data.atime_offset))
    }

    /// The last changed time, in the seconds since UNIX epoch.
    ///
    /// Returns `None` if the archive stores no such information.
    #[inline]
    #[must_use]
    pub fn ctime(&self) -> Option<u64> {
        (!self.index.mtime_only).then(|| self.cvt_time(self.data.ctime_offset))
    }
}

/// A directory inode.
#[derive(Debug, Clone, Copy)]
pub struct Dir<'a>(Inode<'a>);

impl_inode_subtype!(Dir);

impl<'a> Dir<'a> {
    /// Iterate all entries in this directory, in ascending order of names.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> DirEntryIter<'a> {
        let ino = self.0.inode_num as usize;
        let dirs = &self.0.index.metadata().directories;
        DirEntryIter {
            index: self.0.index,
            start: dirs[ino].first_entry,
            end: dirs[ino + 1].first_entry,
        }
    }

    /// Find the entry of given name in this directory.
    ///
    /// In DwarFS, directory entries are listed in ascending order of names.
    /// So `get` performs a binary search and the time complexity is
    /// `O(min(L, L0) log N)` where `L` is the max length of entry names, `L0`
    /// is the `name.len()` and `N` is the number of entries in this directory.
    #[inline]
    #[must_use]
    pub fn get(&self, name: impl AsRef<[u8]>) -> Option<DirEntry<'a>> {
        // Manually outline.
        self.get_inner(name.as_ref())
    }

    fn get_inner(&self, name: &[u8]) -> Option<DirEntry<'a>> {
        let DirEntryIter { start, end, .. } = self.entries();
        let m = self.0.index.metadata();
        let entries = &m.dir_entries.as_ref().expect("validated")[start as usize..end as usize];
        let idx = entries
            .binary_search_by_key(&name, |ent| {
                ArchiveIndex::get_from_string_table(&m.names, &m.compact_names, ent.name_index)
                    .as_bytes()
            })
            .ok()?;
        Some(DirEntry::new(self.0.index, &entries[idx]))
    }
}

/// The iterator of directory entries.
#[derive(Debug, Clone)]
pub struct DirEntryIter<'a> {
    index: &'a ArchiveIndex,
    start: u32,
    end: u32,
}

macro_rules! impl_range_iterator {
    ($iter:ident, $item:ident) => {
        impl<'a> Iterator for $iter<'a> {
            type Item = $item<'a>;

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.len(), Some(self.len()))
            }

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                if self.start < self.end {
                    let ent = $item::new_idx(self.index, self.start);
                    self.start += 1;
                    Some(ent)
                } else {
                    None
                }
            }

            #[inline]
            fn nth(&mut self, n: usize) -> Option<Self::Item> {
                if n < self.len() {
                    self.start += n as u32 + 1;
                    Some($item::new_idx(self.index, self.start - 1))
                } else {
                    self.start = self.end;
                    None
                }
            }

            #[inline]
            fn count(self) -> usize
            where
                Self: Sized,
            {
                self.len()
            }
        }

        impl DoubleEndedIterator for $iter<'_> {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                if self.start < self.end {
                    self.end -= 1;
                    let ent = $item::new_idx(self.index, self.end);
                    Some(ent)
                } else {
                    None
                }
            }

            #[inline]
            fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                if n < self.len() {
                    self.end -= n as u32 + 1;
                    Some($item::new_idx(self.index, self.end))
                } else {
                    self.end = self.start;
                    None
                }
            }
        }

        impl ExactSizeIterator for $iter<'_> {
            #[inline]
            fn len(&self) -> usize {
                // Never overflows because it's in memory.
                (self.end - self.start) as usize
            }
        }

        impl FusedIterator for $iter<'_> {}
    };
}

impl_range_iterator!(DirEntryIter, DirEntry);

/// An entry in a directory.
#[derive(Debug, Clone, Copy)]
pub struct DirEntry<'a> {
    index: &'a ArchiveIndex,
    // Inline `metadata::DirEntry` for `Copy`.
    name_index: u32,
    inode_num: u32,
}

impl<'a> DirEntry<'a> {
    fn new(index: &'a ArchiveIndex, ent: &metadata::DirEntry) -> Self {
        Self {
            index,
            name_index: ent.name_index,
            inode_num: ent.inode_num,
        }
    }

    fn new_idx(index: &'a ArchiveIndex, idx: u32) -> Self {
        let entries = index.metadata().dir_entries.as_deref().expect("validated");
        Self::new(index, &entries[idx as usize])
    }

    /// Get the name of this entry.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &'a str {
        let m = self.index.metadata();
        ArchiveIndex::get_from_string_table(&m.names, &m.compact_names, self.name_index)
    }

    /// Get the inode of this entry.
    #[inline]
    #[must_use]
    pub fn inode(&self) -> Inode<'a> {
        Inode {
            index: self.index,
            inode_num: self.inode_num,
        }
    }
}

/// A symlink inode.
#[derive(Debug, Clone, Copy)]
pub struct Symlink<'a>(Inode<'a>);

impl_inode_subtype!(Symlink);

impl<'a> Symlink<'a> {
    /// Get the target of this symlink.
    #[inline]
    #[must_use]
    pub fn target(&self) -> &'a str {
        let m = self.0.index.metadata();
        let symlink_idx = self.0.inode_num - self.0.index.inode_tally.symlink_start;
        let tgt_idx = m.symlink_table[symlink_idx as usize];
        ArchiveIndex::get_from_string_table(&m.symlinks, &m.compact_symlinks, tgt_idx)
    }
}

/// A character or block device inode.
///
/// To distinguish from block device and character device, you can call
/// [`metadata()`][IsInode::metadata] and check
/// [`file_type_mode()`][InodeMetadata::file_type_mode] for its file type.
#[derive(Debug, Clone, Copy)]
pub struct Device<'a>(Inode<'a>);

impl_inode_subtype!(Device);

impl Device<'_> {
    /// Get the device id this special inode represents.
    #[inline]
    #[must_use]
    pub fn device_id(&self) -> u64 {
        let device_idx = self.0.inode_num - self.0.index.inode_tally.device_start;
        self.0.index.metadata().devices.as_ref().expect("validated")[device_idx as usize]
    }
}

/// A pipe or socket inode.
///
/// To distinguish from pipe and socket inodes, you can call
/// [`metadata()`][IsInode::metadata] and check
/// [`file_type_mode()`][InodeMetadata::file_type_mode] for its file type.
#[derive(Debug, Clone, Copy)]
pub struct Ipc<'a>(Inode<'a>);

impl_inode_subtype!(Ipc);

/// A regular file inode.
///
/// This type implements [`AsChunks`], you can call
/// [`as_chunks`][AsChunks::as_chunks] or [`read_to_vec`][AsChunks::read_to_vec]
/// to read its content.
#[derive(Debug, Clone, Copy)]
pub struct File<'a>(Inode<'a>);

impl_inode_subtype!(File);

impl<'a> AsChunks<'a> for File<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        let tally = &self.0.index.inode_tally;
        let m = self.0.index.metadata();
        let file_idx = if let Some(shared_idx) = self.0.inode_num.checked_sub(tally.shared_start) {
            m.shared_files_table.as_ref().expect("validated")[shared_idx as usize]
                + tally.unique_cnt
        } else {
            self.0.inode_num - tally.unique_start
        };
        ChunkIter {
            index: self.0.index,
            start: m.chunk_table[file_idx as usize],
            end: m.chunk_table[file_idx as usize + 1],
        }
    }
}

/// Iterator of file content chunks.
#[derive(Debug, Clone)]
pub struct ChunkIter<'a> {
    index: &'a ArchiveIndex,
    start: u32,
    end: u32,
}

impl ChunkIter<'_> {
    /// Iterate over all chunks and return the sum of all chunks' byte length.
    pub fn total_size(&self) -> u64 {
        self.clone().map(|c| u64::from(c.size())).sum::<u64>()
    }
}

impl sealed::Sealed for ChunkIter<'_> {}
impl<'a> AsChunks<'a> for ChunkIter<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        self.clone()
    }
}

impl_range_iterator!(ChunkIter, Chunk);

/// The description of a chunk of bytes.
#[derive(Debug, Clone, Copy)]
pub struct Chunk<'a> {
    index: &'a ArchiveIndex,
    // Inline `metadata::Chunk` for `Copy`.
    block: u32,
    offset: u32,
    size: u32,
    // For `HasChunks` impl.
    chunk_idx: u32,
}

impl<'a> Chunk<'a> {
    fn new_idx(index: &'a ArchiveIndex, chunk_idx: u32) -> Self {
        let metadata::Chunk {
            block,
            offset,
            size,
        } = index.metadata().chunks[chunk_idx as usize].clone();
        Self {
            index,
            block,
            offset,
            size,
            chunk_idx,
        }
    }

    /// Get the number (0-based) of section this chunk resides in.
    #[inline]
    #[must_use]
    pub fn section_idx(&self) -> u32 {
        self.block
    }

    /// Get the start offset of chunk data in the decompressed section payload.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Get the byte size of this chunk.
    #[inline]
    #[must_use]
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Read this chunk into [`Archive`]'s cache if needed and return the bytes.
    ///
    /// If the section (block) containing this chunk is already in cache, this
    /// function performs no read on the underlying stream.
    pub fn read_cached<'b, R: ReadAt>(&self, archive: &'b mut Archive<R>) -> Result<&'b [u8]> {
        archive.cache_block(self.index, self.section_idx())?;
        // Chunk offsets will not overflow, checked by `unpack_validate`.
        archive.get_chunk_in_cache(self.offset(), self.offset() + self.size())
    }
}

impl sealed::Sealed for Chunk<'_> {}
impl<'a> AsChunks<'a> for Chunk<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        ChunkIter {
            index: self.index,
            start: self.chunk_idx,
            end: self.chunk_idx + 1,
        }
    }
}

/// Trait for data-bearing objects, notably [`File`]s and [`Chunk`]s.
///
/// In DwarFS, regular files consist of multiple chunks of data concatenated for
/// deduplication. You can iterate over these chunks and locate section index
/// and offsets in order to retrieve the actual bytes.
///
/// This trait provides some convenient methods to access all these bytes as a
/// [`Read`] instance via [`AsChunks::as_reader`] so you can easily
/// [`std::io::copy`] it as a whole to the destination.
///
/// [`AsChunks::read_to_vec`] can also be used to efficiently read all data into
/// memory.
pub trait AsChunks<'a>: Sized + sealed::Sealed {
    /// Iterate over all chunks this object consists of.
    fn as_chunks(&self) -> ChunkIter<'a>;

    /// Get a [`Read`] instance representing the concatenation of all chunks
    /// this object consists of.
    ///
    /// The user must guarantee the owning [`ArchiveIndex`] of `self` and
    /// `archive` must come from the same DwarFS archive, or the behavior is
    /// unspecified: it may return garbage data, panic, or fail.
    fn as_reader<'b, R: ?Sized>(&self, archive: &'b mut Archive<R>) -> ChunksReader<'a, 'b, R> {
        ChunksReader {
            archive,
            chunks: self.as_chunks(),
            in_section_offset: 0,
            chunk_rest_size: 0,
        }
    }

    /// Read all data from this object into a `Vec`.
    ///
    /// This is a convenient shortcut method wrapping [`AsChunks::as_reader`]
    /// and [`Read::read_to_end`].
    ///
    /// See [`AsChunks::as_reader`] for the validity requirement on `archive`.
    fn read_to_vec<R: ReadAt + ?Sized>(
        &self,
        archive: &mut Archive<R>,
    ) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.as_reader(archive).read_to_end(&mut out)?;
        Ok(out)
    }
}

fn read_to_end_via_buf_read(
    rdr: &mut dyn BufRead,
    out: &mut Vec<u8>,
    size: usize,
) -> std::io::Result<()> {
    out.reserve(size);
    let mut total_size = 0usize;
    loop {
        let chunk = rdr.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(chunk);
        let len = chunk.len();
        total_size += len;
        rdr.consume(len);
    }
    assert_eq!(total_size, size, "short read should fail in Read impl");
    Ok(())
}

/// A reader returned from [`AsChunks::as_reader`].
///
/// - This implements [`Read`] and [`BufRead`] thus can be used as a source for
///   [`std::io::copy`].
/// - This implements [`Iterator`] to read in chunks.
#[derive(Debug)]
pub struct ChunksReader<'a, 'b, R: ?Sized> {
    chunks: ChunkIter<'a>,
    in_section_offset: u32,
    chunk_rest_size: u32,
    archive: &'b mut Archive<R>,
}

impl<R: ?Sized> ChunksReader<'_, '_, R> {
    /// Iterate over all chunks and return the sum of all chunks' byte length.
    ///
    /// This number is exact, unless the DwarFS archive is changed during access
    /// or some underlying I/O failure occurs.
    pub fn total_size(&self) -> u64 {
        self.chunks.total_size() + u64::from(self.chunk_rest_size)
    }
}

impl<R: ReadAt + ?Sized> Read for ChunksReader<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cache = self.fill_buf()?;
        let len = cache.len().min(buf.len());
        buf[..len].copy_from_slice(&cache[..len]);
        self.consume(len);
        Ok(len)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        // `usize::MAX` will trigger a `reserve` panic in `read_to_end_via_buf_read`.
        let size = usize::try_from(self.total_size()).unwrap_or(usize::MAX);
        read_to_end_via_buf_read(self, buf, size)?;
        Ok(size)
    }
}

impl<R: ReadAt + ?Sized> BufRead for ChunksReader<'_, '_, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.chunk_rest_size == 0 {
            let Some(chunk) = self.chunks.next() else {
                return Ok(&[]);
            };
            self.in_section_offset = chunk.offset();
            self.chunk_rest_size = chunk.size();
            self.archive.cache_block(chunk.index, chunk.section_idx())?;
        }
        let chunk = self.archive.get_chunk_in_cache(
            self.in_section_offset,
            // Chunk offsets will not overflow, checked by `unpack_validate`.
            self.in_section_offset + self.chunk_rest_size,
        )?;
        Ok(chunk)
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        assert!(amt <= self.chunk_rest_size as usize);
        self.in_section_offset += amt as u32;
        self.chunk_rest_size -= amt as u32;
    }
}
