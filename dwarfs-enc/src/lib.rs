//! A library for writing [DwarFS][dwarfs] archives (aka. images),
//! building on top of [`dwarfs` crate][::dwarfs].
//!
//! For reading archives only, check [`dwarfs` crate][::dwarfs] instead.
//!
//! [dwarfs]: https://github.com/mhx/dwarfs
//!
//! Currently, this crate writes DwarFS archive with filesystem version v2.5,
//! which should be compatible with upstream dwarfs v0.7.0..=v0.12.4 (latest at
//! the time of writing).
//!
//! ## Examples
//!
//! ```
//! use dwarfs_enc::{
//!     chunker::{Chunker, BasicChunker, CdcChunker},
//!     metadata::{Builder as MetaBuilder, InodeMetadata},
//!     section::{Writer as SectionWriter, CompressParam},
//! };
//! use std::{fs, time::SystemTime};
//!
//! # fn work() -> dwarfs_enc::Result<()> {
//! let f = fs::File::create("out.dwarfs")?;
//!
//! // Create inode metadata.
//! let mut dir_meta = InodeMetadata::new(0o755);
//! dir_meta.uid(1000).gid(1000).atime(SystemTime::now());
//! // ... or initialize from OS metadata.
//! let file_meta = InodeMetadata::from(&fs::metadata("./bar")?);
//!
//! // Create a hierarchy builder initialized with a root inode.
//! let mut meta = MetaBuilder::new(&dir_meta);
//!
//! // Use ZSTD compression level 22, Content Defined Chunking (CDC) for deduplication.
//! let compress = CompressParam::Zstd(22);
//! let writer = SectionWriter::new(f)?;
//! let chunker = BasicChunker::new(writer, meta.block_size(), compress);
//! let mut chunker = CdcChunker::new(chunker);
//!
//! // Put a directories and a symlink.
//! let root = meta.root();
//! let subdir = meta.put_dir(root, "subdir", &dir_meta)?;
//! meta.put_symlink(subdir, "symlink", &file_meta, "./subdir")?;
//!
//! // Put a regular file, using in-memory data.
//! meta.put_file(root, "foo", &file_meta, chunker.put_bytes(b"hello world")?)?;
//! // Put a regular file, reading from an OS File.
//! let chunks = chunker.put_reader(&mut fs::File::open("bar")?)?;
//! let bar = meta.put_file(root, "bar", &file_meta, chunks)?;
//!
//! // Hard links are also supported.
//! meta.put_hard_link(root, "hardlink", bar)?;
//!
//! // Finalizing data chunks, metadata, and section writer in order.
//! let mut writer = chunker.finish()?;
//! writer.write_metadata_sections(&meta.finish()?, compress)?;
//! writer.finish()?;
//!
//! # Ok(()) }
//! ```
//!
//! See also the simple `mkdwarfs` impl at `./examples/mkdwarfs.rs`.
//!
//! ## Cargo features
//!
//! - `zstd`, `lzma` *(Only `zstd` is enabled by default)*
//!
//!   Enable relevant compression algorithm support. `zstd` is the default
//!   compression algorithm `mkdwarfs` uses and it should be enough for most cases.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
mod error;

pub mod chunker;
pub mod metadata;
mod ordered_parallel;
pub mod section;

use self::error::ErrorInner;
pub use self::error::{Error, Result};
