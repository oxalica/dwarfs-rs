//! The high-level interface for accessing a dwarfs archive.

use std::{
    fmt,
    io::{BufRead, Read, Seek, SeekFrom},
    iter::FusedIterator,
    num::NonZero,
};

use bstr::{BStr, BString, ByteSlice};

use crate::{
    bisect_range_by,
    fsst::Decoder as FsstDecoder,
    metadata::{Metadata, MetadataError, Schema, SchemaError, unpacked},
    section::{SectionIndexEntry, SectionReader, SectionType},
};

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Error(Box<ErrorInner>);

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug)]
enum ErrorInner {
    Section(String, crate::section::Error),
    MissingSection(SectionType),
    DuplicatedSection(SectionType),
    Schema(SchemaError),
    Metadata(MetadataError),
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
            ErrorInner::Section(msg, err) => write!(f, "{msg}: {err}"),
            ErrorInner::MissingSection(ty) => write!(f, "missing section {ty:?}"),
            ErrorInner::DuplicatedSection(ty) => write!(f, "duplicated sections {ty:?}"),
            ErrorInner::Io(err) => write!(f, "input/outpur error: {err}"),
            ErrorInner::Schema(err) => write!(f, "invalid metadata schema: {err}"),
            ErrorInner::Metadata(err) => write!(f, "failed to parse metadata: {err}"),
            ErrorInner::Validation(err) => write!(f, "malformed metadata: {err}"),
            ErrorInner::UnsupportedFeature(msg) => write!(f, "unsupported feature: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.0 {
            ErrorInner::Section(_, err) => Some(err),
            ErrorInner::Io(err) => Some(err),
            ErrorInner::Schema(err) => Some(err),
            ErrorInner::Metadata(err) => Some(err),
            ErrorInner::MissingSection(_)
            | ErrorInner::DuplicatedSection(_)
            | ErrorInner::Validation(_)
            | ErrorInner::UnsupportedFeature(_) => None,
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

impl<T> ResultExt<T> for Result<T, crate::section::Error> {
    #[inline]
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(ErrorInner::Section(msg.to_string(), err).into()),
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

#[derive(Debug)]
pub struct Config {
    image_offset: u64,
    section_index_size_limit: usize,
    metadata_schema_size_limit: usize,
    metadata_size_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            image_offset: 0,
            // Some arbitrarily chosen numbers.
            section_index_size_limit: 64 << 20,
            metadata_schema_size_limit: 1 << 20,
            metadata_size_limit: 16 << 20,
        }
    }
}

impl Config {
    pub fn image_offset(&mut self, offset: u64) -> &mut Self {
        self.image_offset = offset;
        self
    }

    pub fn section_index_size_limit(&mut self, limit: usize) -> &mut Self {
        self.section_index_size_limit = limit;
        self
    }

    pub fn metadata_schema_size_limit(&mut self, limit: usize) -> &mut Self {
        self.metadata_schema_size_limit = limit;
        self
    }

    pub fn metadata_size_limit(&mut self, limit: usize) -> &mut Self {
        self.metadata_size_limit = limit;
        self
    }
}

pub struct ArchiveIndex {
    section_index: Box<[SectionIndexEntry]>,
    metadata: unpacked::Metadata,

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
    unique_files: u32,

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
    pub fn new<R: Read + Seek>(rdr: &mut SectionReader<R>) -> Result<Self> {
        Self::new_with_config(rdr, &Config::default())
    }

    pub fn new_with_config<R: Read + Seek>(
        rdr: &mut SectionReader<R>,
        config: &Config,
    ) -> Result<Self> {
        let image_offset = config.image_offset;

        // Load section index.
        let (_, section_index) = rdr
            .seek_read_section_index(image_offset, config.section_index_size_limit)
            .context("failed to load section index")?;
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
                return Err(ErrorInner::DuplicatedSection(sec_ty).into());
            }
            Ok(off)
        };
        let schema_offset =
            find_unique_section(SectionType::METADATA_V2_SCHEMA)?.saturating_add(image_offset);
        let metadata_offset =
            find_unique_section(SectionType::METADATA_V2)?.saturating_add(image_offset);

        // Load and unpack metadata.
        let metadata = {
            rdr.get_mut().seek(SeekFrom::Start(schema_offset))?;
            let (_, raw_schema) = rdr
                .read_section(config.metadata_schema_size_limit)
                .context("failed to read metadata schema section")?;
            let schema = Schema::parse(&raw_schema).map_err(ErrorInner::Schema)?;

            rdr.get_mut().seek(SeekFrom::Start(metadata_offset))?;
            let (_, raw_metadata) = rdr
                .read_section(config.metadata_size_limit)
                .context("failed to read metadata section")?;
            let meta = Metadata::parse(&schema, &raw_metadata).map_err(ErrorInner::Metadata)?;
            unpacked::Metadata::from(meta)
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
        let m = &mut self.metadata;

        // Explicit future-incompatible features.
        if let Some(feat) = &m.features {
            if !feat.is_empty() {
                return Err(ErrorInner::UnsupportedFeature(format!("{feat:?}")).into());
            }
        }
        if m.dir_entries.is_none() {
            todo!();
        }

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
                let mut sum = 0u32;
                for c in &mut m.chunk_table {
                    sum = c
                        .checked_add(sum)
                        .context("value overflow for packed chunk_table")?;
                    *c = sum;
                }
            }

            if opts.packed_directories {
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
                let unpacked_len = std::iter::zip(shared, 2..)
                    .try_fold(0u32, |sum, (&cnt, dups)| {
                        cnt.checked_mul(dups)?.checked_add(sum)
                    })
                    // Use inode count as a loose upper bound, to guard from length exploding.
                    .filter(|&n| n < m.inodes.len() as u32)
                    .context("loosy this")?;
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
                unique_files: 0,
                symlink_start: dir_cnt as u32,
                unique_start: unique_start as u32,
                shared_start: shared_start as u32,
                device_start: device_start as u32,
                ipc_start: ipc_start as u32,
            };
        }

        // Unpack string tables, currently `compact_{names,symlinks}`.
        fn unpack_string_table(
            tbl: &mut Option<unpacked::StringTable>,
            msg_index: &'static str,
            msg_symtab: &'static str,
            msg_decode: &'static str,
        ) -> Result<()> {
            let Some(tbl) = tbl else { return Ok(()) };
            let len = tbl.buffer.len() as u32;
            if tbl.packed_index {
                let mut sum = 0u32;
                for v in &mut tbl.index {
                    sum = sum
                        .checked_add(*v)
                        .filter(|&i| i <= len)
                        .context(msg_index)?;
                    *v = sum;
                }
            // If symtab is used, the decoding process below will validate index ranges anyway.
            } else if tbl.symtab.is_none() {
                tbl.index.is_sorted().or_context(msg_index)?;
                if let Some(last_idx) = tbl.index.last() {
                    (*last_idx <= len).or_context(msg_index)?;
                }
            }
            if let Some(symtab_bytes) = &tbl.symtab {
                let decoder = FsstDecoder::parse_symtab(symtab_bytes).context(msg_symtab)?;
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
                    let sym_dec_len = FsstDecoder::max_decode_len(sym.len());
                    out_buf.resize(out_len + sym_dec_len, 0);
                    let sym_out = &mut out_buf[out_len..out_len + sym_dec_len];
                    out_len += decoder.decode_into(sym, sym_out).context(msg_decode)?;

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

            let entries = m.dir_entries.as_ref().expect("validated").len() as u32;
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
            for ent in m.dir_entries.as_ref().expect("validated") {
                check!(ent.inode_num < inodes, "dir_entries.inode_num");
                check!(ent.name_index < names, "dir_entries.name_index");
            }
        }

        Ok(())
    }

    fn get_from_string_table<'a>(
        loose: &'a [BString],
        compact: &'a Option<unpacked::StringTable>,
        idx: u32,
    ) -> &'a BStr {
        if let Some(tbl) = compact {
            let idx_start = tbl.index[idx as usize] as usize;
            let idx_end = tbl.index[idx as usize + 1] as usize;
            tbl.buffer[idx_start..idx_end].as_bstr()
        } else {
            loose[idx as usize].as_bstr()
        }
    }

    /// Get the root directory of the archive.
    pub fn root(&self) -> Dir<'_> {
        Dir {
            index: self,
            inode_num: 0,
        }
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
}

/// Low-level methods.
impl ArchiveIndex {
    pub fn section_index(&self) -> &[SectionIndexEntry] {
        &self.section_index
    }

    pub fn metadata(&self) -> &unpacked::Metadata {
        &self.metadata
    }

    pub fn get_inode(&self, inode_num: u32) -> Option<Inode<'_>> {
        (inode_num < self.metadata().inodes.len() as u32).then_some(Inode {
            index: self,
            inode_num,
        })
    }
}

#[derive(Debug)]
pub struct Archive<R: ?Sized> {
    // TODO: LRU cache.
    cache: Option<(u64, Vec<u8>)>,
    block_size: u32,
    image_offset: u64,

    rdr: SectionReader<R>,
}

impl<R: Read + Seek + ?Sized> Archive<R> {
    pub fn new(rdr: R) -> Result<(ArchiveIndex, Self)>
    where
        R: Sized,
    {
        let mut rdr = SectionReader::new(rdr);
        let index = ArchiveIndex::new(&mut rdr)?;
        let this = Self::new_with_index_and_config(rdr, &index, &Config::default());
        Ok((index, this))
    }

    pub fn new_with_index_and_config(
        rdr: SectionReader<R>,
        index: &ArchiveIndex,
        config: &Config,
    ) -> Self
    where
        R: Sized,
    {
        Self {
            cache: None,
            block_size: index.metadata().block_size,
            image_offset: config.image_offset,
            rdr,
        }
    }

    fn get_cache(&self) -> (u64, &[u8]) {
        match &self.cache {
            Some((archive_offset, cache)) => (*archive_offset, cache),
            None => (!0, &[]),
        }
    }

    fn cache_section(&mut self, archive_offset: u64) -> Result<()> {
        if self
            .cache
            .as_ref()
            .is_some_and(|(cache_offset, _)| *cache_offset == archive_offset)
        {
            return Ok(());
        }

        self.rdr.get_mut().seek(SeekFrom::Start(
            archive_offset.saturating_add(self.image_offset),
        ))?;
        let data = (|| {
            let header = self.rdr.read_header()?;
            header.check_type(SectionType::BLOCK)?;
            // `block_size` is checked to be in `usize` range by `validate_post`.
            self.rdr.read_data(&header, self.block_size as usize)
        })()
        .context(format_args!(
            "failed to read section at archive offset {} + image offset {}",
            archive_offset, self.image_offset,
        ))?;
        self.cache = Some((archive_offset, data));
        Ok(())
    }
}

impl<R> Archive<R> {
    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.rdr.into_inner()
    }

    pub fn get_ref(&self) -> &R {
        self.rdr.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut R {
        self.rdr.get_mut()
    }
}

/// An inode.
#[derive(Debug, Clone, Copy)]
pub struct Inode<'a> {
    index: &'a ArchiveIndex,
    inode_num: u32,
}

impl<'a> Inode<'a> {
    /// Classify this inode to an enum according to its kind.
    pub fn classify(&self) -> InodeKind<'a> {
        let Self { index, inode_num } = *self;
        let t = &index.inode_tally;
        if inode_num < t.symlink_start {
            InodeKind::Directory(Dir { index, inode_num })
        } else if inode_num < t.unique_start {
            let symlink_idx = inode_num - t.symlink_start;
            InodeKind::Symlink(Symlink { index, symlink_idx })
        } else if inode_num < t.shared_start {
            let file_idx = inode_num - t.unique_start;
            InodeKind::File(File::Unique(UniqueFile { index, file_idx }))
        } else if inode_num < t.device_start {
            let shared_idx = inode_num - t.shared_start;
            InodeKind::File(File::Shared(SharedFile { index, shared_idx }))
        } else if inode_num < t.ipc_start {
            let device_idx = inode_num - t.device_start;
            InodeKind::Device(Device { index, device_idx })
        } else {
            InodeKind::Ipc(Ipc { index, inode_num })
        }
    }

    pub fn is_dir(&self) -> bool {
        self.classify().is_dir()
    }

    pub fn is_file(&self) -> bool {
        self.classify().is_file()
    }

    pub fn as_dir(&self) -> Option<Dir<'a>> {
        self.classify().as_dir()
    }

    pub fn as_file(&self) -> Option<File<'a>> {
        self.classify().as_file()
    }

    /// Get the metadata of this inode.
    pub fn metadata(&self) -> InodeMetadata<'a> {
        InodeMetadata::new(self.index, self.inode_num)
    }
}

/// An inode, classified by its kind.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum InodeKind<'a> {
    Directory(Dir<'a>),
    Symlink(Symlink<'a>),
    File(File<'a>),
    Device(Device<'a>),
    Ipc(Ipc<'a>),
}

impl<'a> From<InodeKind<'a>> for Inode<'a> {
    fn from(i: InodeKind<'a>) -> Self {
        match i {
            InodeKind::Directory(i) => i.into(),
            InodeKind::Symlink(i) => i.into(),
            InodeKind::File(i) => i.into(),
            InodeKind::Device(i) => i.into(),
            InodeKind::Ipc(i) => i.into(),
        }
    }
}

impl<'a> InodeKind<'a> {
    pub fn as_dir(&self) -> Option<Dir<'a>> {
        if let Self::Directory(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    pub fn as_file(&self) -> Option<File<'a>> {
        if let Self::File(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Returns `true` if the inode kind is [`Directory`].
    ///
    /// [`Directory`]: InodeKind::Directory
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(..))
    }

    /// Returns `true` if the inode kind is [`File`].
    ///
    /// [`File`]: InodeKind::File
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(..))
    }
}

#[derive(Debug)]
pub struct InodeMetadata<'a> {
    index: &'a ArchiveIndex,
    data: unpacked::InodeData,
}

impl<'a> InodeMetadata<'a> {
    fn new(index: &'a ArchiveIndex, inode_num: u32) -> Self {
        let data = index.metadata().inodes[inode_num as usize].clone();
        Self { index, data }
    }

    /// The mode of the inode, including file types and permissions.
    pub fn mode(&self) -> u32 {
        self.index.metadata().modes[self.data.mode_index as usize]
    }

    /// The owner user id (uid) of the inode.
    pub fn owner(&self) -> u32 {
        self.index.metadata().uids[self.data.owner_index as usize]
    }

    /// The owner group id (gid) of the inode.
    pub fn group(&self) -> u32 {
        self.index.metadata().gids[self.data.group_index as usize]
    }

    fn cvt_time(&self, time_offset: u32) -> u64 {
        self.index.timestamp_base_scaled
            + u64::from(time_offset) * u64::from(self.index.time_resolution.get())
    }

    /// The last modified time, in the seconds since UNIX epoch.
    pub fn mtime(&self) -> u64 {
        self.cvt_time(self.data.mtime_offset)
    }

    /// The last accessed time, in the seconds since UNIX epoch.
    pub fn atime(&self) -> Option<u64> {
        (!self.index.mtime_only).then(|| self.cvt_time(self.data.atime_offset))
    }

    /// The last changed time, in the seconds since UNIX epoch.
    pub fn ctime(&self) -> Option<u64> {
        (!self.index.mtime_only).then(|| self.cvt_time(self.data.ctime_offset))
    }
}

/// A directory inode.
#[derive(Debug, Clone, Copy)]
pub struct Dir<'a> {
    index: &'a ArchiveIndex,
    inode_num: u32,
}

impl<'a> From<Dir<'a>> for Inode<'a> {
    fn from(Dir { index, inode_num }: Dir<'a>) -> Self {
        Self { index, inode_num }
    }
}

impl<'a> Dir<'a> {
    /// Iterate all entries in this directory, in ascending order of names.
    pub fn entries(&self) -> DirEntryIter<'a> {
        let ino = self.inode_num as usize;
        let dirs = &self.index.metadata().directories;
        DirEntryIter {
            index: self.index,
            ent_start: dirs[ino].first_entry,
            ent_end: dirs[ino + 1].first_entry,
        }
    }

    /// Find the entry of given name in this directory.
    ///
    /// In dwarfs, directory entries are listed in ascending order of names.
    /// So `get` performs a binary search and the time complexity is
    /// `O(min(L, L0) log N)` where `L` is the max length of entry names, `L0`
    /// is the `name.len()` and `N` is the number of entries in this directory.
    pub fn get(&self, name: impl AsRef<[u8]>) -> Option<DirEntry<'a>> {
        self.get_inner(name.as_ref())
    }

    fn get_inner(&self, name: &[u8]) -> Option<DirEntry<'a>> {
        let iter = self.entries();
        let range = iter.ent_start as usize..iter.ent_end as usize;
        let idx = bisect_range_by(range, |idx| {
            <[u8] as Ord>::cmp(DirEntry::new(self.index, idx as u32).name(), name)
        })?;
        Some(DirEntry::new(self.index, idx as u32))
    }
}

#[derive(Debug, Clone)]
pub struct DirEntryIter<'a> {
    index: &'a ArchiveIndex,
    ent_start: u32,
    ent_end: u32,
}

// TODO: More Iterator methods.
impl<'a> Iterator for DirEntryIter<'a> {
    type Item = DirEntry<'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.ent_end - self.ent_start) as usize;
        (len, Some(len))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.ent_start < self.ent_end {
            let ent = DirEntry::new(self.index, self.ent_start);
            self.ent_start += 1;
            Some(ent)
        } else {
            None
        }
    }
}

impl DoubleEndedIterator for DirEntryIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.ent_start < self.ent_end {
            let ent = DirEntry::new(self.index, self.ent_end - 1);
            self.ent_end -= 1;
            Some(ent)
        } else {
            None
        }
    }
}

impl ExactSizeIterator for DirEntryIter<'_> {}
impl FusedIterator for DirEntryIter<'_> {}

/// An entry in a directory.
#[derive(Debug)]
pub struct DirEntry<'a> {
    index: &'a ArchiveIndex,
    data: unpacked::DirEntry,
}

impl<'a> DirEntry<'a> {
    fn new(index: &'a ArchiveIndex, ent_idx: u32) -> Self {
        let data =
            index.metadata().dir_entries.as_ref().expect("validated")[ent_idx as usize].clone();
        Self { index, data }
    }

    pub fn name(&self) -> &'a BStr {
        let m = self.index.metadata();
        ArchiveIndex::get_from_string_table(&m.names, &m.compact_names, self.data.name_index)
    }

    pub fn inode(&self) -> Inode<'a> {
        Inode {
            index: self.index,
            inode_num: self.data.inode_num,
        }
    }
}

/// A symlink inode.
#[derive(Debug, Clone, Copy)]
pub struct Symlink<'a> {
    index: &'a ArchiveIndex,
    symlink_idx: u32,
}

impl<'a> From<Symlink<'a>> for Inode<'a> {
    fn from(i: Symlink<'a>) -> Self {
        Self {
            index: i.index,
            inode_num: i.index.inode_tally.symlink_start + i.symlink_idx,
        }
    }
}

impl<'a> Symlink<'a> {
    pub fn target(&self) -> &'a BStr {
        let m = self.index.metadata();
        let tgt_idx = m.symlink_table[self.symlink_idx as usize];
        ArchiveIndex::get_from_string_table(&m.symlinks, &m.compact_symlinks, tgt_idx)
    }
}

/// A character or block device inode.
#[derive(Debug, Clone, Copy)]
pub struct Device<'a> {
    index: &'a ArchiveIndex,
    device_idx: u32,
}

impl<'a> From<Device<'a>> for Inode<'a> {
    fn from(i: Device<'a>) -> Self {
        Self {
            index: i.index,
            inode_num: i.index.inode_tally.device_start + i.device_idx,
        }
    }
}

impl Device<'_> {
    pub fn device_id(&self) -> u64 {
        self.index.metadata().devices.as_ref().expect("validated")[self.device_idx as usize]
    }
}

/// A pipe or socket inode.
#[derive(Debug, Clone, Copy)]
pub struct Ipc<'a> {
    index: &'a ArchiveIndex,
    inode_num: u32,
}

impl<'a> From<Ipc<'a>> for Inode<'a> {
    fn from(Ipc { index, inode_num }: Ipc<'a>) -> Self {
        Self { index, inode_num }
    }
}

/// A regular file inode.
#[derive(Debug, Clone, Copy)]
pub enum File<'a> {
    Unique(UniqueFile<'a>),
    Shared(SharedFile<'a>),
}

impl<'a> From<File<'a>> for Inode<'a> {
    fn from(f: File<'a>) -> Self {
        match f {
            File::Unique(f) => f.into(),
            File::Shared(f) => f.into(),
        }
    }
}

impl sealed::Sealed for File<'_> {}
impl<'a> AsChunks<'a> for File<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        match self {
            File::Unique(f) => f.as_chunks(),
            File::Shared(f) => f.as_chunks(),
        }
    }
}

/// A unique regular file inode.
#[derive(Debug, Clone, Copy)]
pub struct UniqueFile<'a> {
    index: &'a ArchiveIndex,
    file_idx: u32,
}

impl<'a> From<UniqueFile<'a>> for Inode<'a> {
    fn from(i: UniqueFile<'a>) -> Self {
        Self {
            index: i.index,
            inode_num: i.index.inode_tally.unique_start + i.file_idx,
        }
    }
}

impl sealed::Sealed for UniqueFile<'_> {}
impl<'a> AsChunks<'a> for UniqueFile<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        let tbl = &self.index.metadata().chunk_table;
        let chunk_start = tbl[self.file_idx as usize];
        let chunk_end = tbl[self.file_idx as usize + 1];
        ChunkIter {
            index: self.index,
            chunk_start,
            chunk_end,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChunkIter<'a> {
    index: &'a ArchiveIndex,
    chunk_start: u32,
    chunk_end: u32,
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

impl<'a> Iterator for ChunkIter<'a> {
    type Item = Chunk<'a>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.chunk_end - self.chunk_start) as usize;
        (len, Some(len))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_start < self.chunk_end {
            let c = Chunk::new(self.index, self.chunk_start);
            self.chunk_start += 1;
            Some(c)
        } else {
            None
        }
    }
}

impl DoubleEndedIterator for ChunkIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.chunk_start < self.chunk_end {
            let c = Chunk::new(self.index, self.chunk_end - 1);
            self.chunk_end += 1;
            Some(c)
        } else {
            None
        }
    }
}

impl ExactSizeIterator for ChunkIter<'_> {}
impl FusedIterator for ChunkIter<'_> {}

/// A shared regular file inode.
#[derive(Debug, Clone, Copy)]
pub struct SharedFile<'a> {
    index: &'a ArchiveIndex,
    shared_idx: u32,
}

impl<'a> From<SharedFile<'a>> for Inode<'a> {
    fn from(i: SharedFile<'a>) -> Self {
        Self {
            index: i.index,
            inode_num: i.index.inode_tally.shared_start + i.shared_idx,
        }
    }
}

impl sealed::Sealed for SharedFile<'_> {}
impl<'a> AsChunks<'a> for SharedFile<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        let m = self.index.metadata();
        let file_idx = self.index.inode_tally.unique_files
            + m.shared_files_table.as_ref().expect("validated")[self.shared_idx as usize];
        let chunk_start = m.chunk_table[file_idx as usize];
        let chunk_end = m.chunk_table[file_idx as usize + 1];
        ChunkIter {
            index: self.index,
            chunk_start,
            chunk_end,
        }
    }
}

/// The description of a chunk of bytes.
#[derive(Debug, Clone)]
pub struct Chunk<'a> {
    index: &'a ArchiveIndex,
    data: unpacked::Chunk,
    // For `HasChunks` impl.
    chunk_idx: u32,
}

impl<'a> Chunk<'a> {
    fn new(index: &'a ArchiveIndex, chunk_idx: u32) -> Self {
        let data = index.metadata().chunks[chunk_idx as usize].clone();
        Self {
            data,
            index,
            chunk_idx,
        }
    }

    pub fn section_idx(&self) -> u32 {
        self.data.block
    }

    pub fn offset(&self) -> u32 {
        self.data.offset
    }

    pub fn size(&self) -> u32 {
        self.data.size
    }
}

impl sealed::Sealed for Chunk<'_> {}
impl<'a> AsChunks<'a> for Chunk<'a> {
    fn as_chunks(&self) -> ChunkIter<'a> {
        ChunkIter {
            index: self.index,
            chunk_start: self.chunk_idx,
            chunk_end: self.chunk_idx + 1,
        }
    }
}

/// Trait for data-bearing objects, notibly [`File`]s and [`Chunk`]s.
///
/// In dwarfs, regular files consist of multiple chunks of data concatenated for
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
    /// `archive` must come from the same dwarfs archive, or the behavior is
    /// unspecified: it may return garbage data, panic, or fail.
    fn as_reader<'b, R>(&self, archive: &'b mut Archive<R>) -> ChunksReader<'a, 'b, R> {
        ChunksReader {
            archive,
            chunks: self.as_chunks(),
            in_section_offset: 0,
            chunk_rest_size: 0,
        }
    }

    /// Read all data of this object into memory.
    ///
    /// The user must guarantee the owning [`ArchiveIndex`] of `self` and
    /// `archive` must come from the same dwarfs archive, or the behavior is
    /// unspecified: it may return garbage data, panic, or fail.
    fn read_to_vec<R: Read + Seek>(&self, archive: &mut Archive<R>) -> std::io::Result<Vec<u8>> {
        let cap = usize::try_from(self.as_chunks().total_size()).unwrap_or(usize::MAX);
        let mut rdr = self.as_reader(archive);
        read_to_vec_via_buf_read(&mut rdr, cap)
    }
}

fn read_to_vec_via_buf_read(rdr: &mut dyn BufRead, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(cap);
    loop {
        let chunk = rdr.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        buf.extend_from_slice(chunk);
        let len = chunk.len();
        rdr.consume(len);
    }
    Ok(buf)
}

/// A [`Read`] instance returned from [`AsChunks::as_reader`].
#[derive(Debug)]
pub struct ChunksReader<'a, 'b, R> {
    archive: &'b mut Archive<R>,
    chunks: ChunkIter<'a>,
    in_section_offset: u32,
    chunk_rest_size: u32,
}

impl<R> ChunksReader<'_, '_, R> {
    /// Iterate over all chunks and return the sum of all chunks' byte length.
    ///
    /// This number is exact, unless the dwarfs archive is changed during access
    /// or some underlying I/O failure occurs.
    pub fn total_size(&self) -> u64 {
        self.chunks.total_size() + u64::from(self.chunk_rest_size)
    }
}

impl<R: Read + Seek> Read for ChunksReader<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cache = self.fill_buf()?;
        let len = cache.len().min(buf.len());
        buf[..len].copy_from_slice(&cache[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<R: Read + Seek> BufRead for ChunksReader<'_, '_, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.chunk_rest_size == 0 {
            let Some(chunk) = self.chunks.next() else {
                return Ok(&[]);
            };
            self.in_section_offset = chunk.offset();
            self.chunk_rest_size = chunk.size();
            let archive_offset =
                self.chunks.index.section_index[chunk.section_idx() as usize].offset();
            self.archive.cache_section(archive_offset)?;
        }

        let (archive_offset, cache) = self.archive.get_cache();
        let start = self.in_section_offset as usize;
        let end = start + self.chunk_rest_size as usize;
        cache.get(start..end).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid section data at archive offset {} + image offset {}, \
                    expecting a chunk at {}..{}, but decompressed data length is {}",
                    archive_offset,
                    self.archive.image_offset,
                    start,
                    end,
                    cache.len(),
                ),
            )
        })
    }

    fn consume(&mut self, amt: usize) {
        assert!(amt <= self.chunk_rest_size as usize);
        self.in_section_offset += amt as u32;
        self.chunk_rest_size -= amt as u32;
    }
}
