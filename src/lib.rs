use std::fmt;

use crate::section::CompressAlgo;

pub mod metadata;
pub mod section;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidMagic,
    MalformedSectionIndex,
    LengthMismatch,
    ChecksumMismatch,
    IntegerOverflow,
    UnknowCompressAlgo(CompressAlgo),
    InvalidSchema,
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Error::InvalidMagic => "invalid section magic",
            Error::MalformedSectionIndex => "malformed section index",
            Error::LengthMismatch => "length mismatch",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::IntegerOverflow => "integer overflow",
            Error::UnknowCompressAlgo(algo) => {
                return write!(f, "unknown section compress algorithm {algo:?}");
            }

            Error::InvalidSchema => "invalid metadata schema",

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
