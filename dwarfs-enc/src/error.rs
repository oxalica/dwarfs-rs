use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Error(Box<ErrorInner>);

#[derive(Debug)]
pub(crate) enum ErrorInner {
    Limit(&'static str),
    SerializeMetadata(dwarfs::metadata::Error),
    DuplicatedEntry,
    UnlinkedInode,

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
            ErrorInner::DuplicatedEntry => f.pad("duplicated entry names in a directory"),
            ErrorInner::Limit(msg) => write!(f, "{msg}"),
            ErrorInner::SerializeMetadata(err) => err.fmt(f),
            ErrorInner::UnlinkedInode => f.pad("an inode is unreachable from root"),
            ErrorInner::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.0 {
            ErrorInner::Io(err) => Some(err),
            ErrorInner::SerializeMetadata(err) => Some(err),
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

impl From<dwarfs::metadata::Error> for Error {
    #[cold]
    fn from(err: dwarfs::metadata::Error) -> Self {
        Self(Box::new(ErrorInner::SerializeMetadata(err)))
    }
}
