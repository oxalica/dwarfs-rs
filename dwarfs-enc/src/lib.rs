//! A library for writing [DwarFS][dwarfs] archives (aka. images),
//! building on top of [`dwarfs` crate][::dwarfs].
//!
//! For reading archives only, check [`dwarfs` crate][::dwarfs] instead.
//!
//! [dwarfs]: https://github.com/mhx/dwarfs
mod error;

pub mod chunker;
pub mod metadata;
pub mod section;

use self::error::ErrorInner;
pub use self::error::{Error, Result};
