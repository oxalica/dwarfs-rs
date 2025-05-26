//! The [Fast Static Symbol Table (FSST)][fsst] decoder for compressed string
//! tables [`StringTable::symtab`][crate::metadata::StringTable::symtab].
//!
//! [fsst]: https://github.com/cwida/fsst

use std::fmt;

use bstr::{BStr, BString};
use zerocopy::IntoBytes;

type Sym = u64;

const VERSION: u32 = 2019_0218;
const SYM_CORRUPT: Sym = u64::from_ne_bytes(*b"corrupt\0");

/// The max length of one symbol.
pub const MAX_SYMBOL_LEN: usize = 8;

type Result<T, E = Error> = std::result::Result<T, E>;

/// A symbol table decoding error.
pub struct Error(ErrorInner);

#[derive(Debug)]
enum ErrorInner {
    InputEof,
    InvalidMagic,
    NulMode,
    CodeOverflow,

    BufTooSmall,
    InvalidEscape,
    InvalidSymbol,

    #[cfg(feature = "serialize")]
    IncorrectSymbolOrder,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self.0 {
            ErrorInner::InputEof => "unexpected end of input",
            ErrorInner::InvalidMagic => "missing header magic",
            ErrorInner::NulMode => "unsupported null-terminated mode",
            ErrorInner::CodeOverflow => "too many symbols",
            ErrorInner::BufTooSmall => "output buffer is too small",
            ErrorInner::InvalidEscape => "invalid escape byte at the end of input",
            ErrorInner::InvalidSymbol => "invalid symbol",
            #[cfg(feature = "serialize")]
            ErrorInner::IncorrectSymbolOrder => "symbols must be ordered in length 2,3,4,5,6,7,8,1",
        })
    }
}

impl std::error::Error for Error {}

impl From<ErrorInner> for Error {
    #[cold]
    #[inline]
    fn from(err: ErrorInner) -> Self {
        Self(err)
    }
}

/// The Fast Static Symbol Table (FSST) decoder.
///
/// See [module level documentations](self). Note that this struct contains a
/// ~2KiB large array, and you may want to box it for fast moving.
pub struct Decoder {
    /// Code -> symbol mapping, stored in native-endian, with trailing bytes filled by NUL.
    symbols: [Sym; 255],
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct SymbolMap<'a>(&'a Decoder);

        impl fmt::Debug for SymbolMap<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map()
                    .entries(self.0.symbols.iter().enumerate().map(|(i, sym)| {
                        let len = Decoder::symbol_len(*sym);
                        let sym = &sym.as_bytes()[..len];
                        (i, BStr::new(sym))
                    }))
                    .finish()
            }
        }

        f.debug_struct("Decoder")
            .field("symbols", &SymbolMap(self))
            .finish()
    }
}

impl Decoder {
    /// The max length of one symbol.
    pub const MAX_SYMBOL_LEN: usize = MAX_SYMBOL_LEN;

    const ALL_CORRUPT: Self = Decoder {
        symbols: [SYM_CORRUPT; 255],
    };

    /// Iterate over `len_histo` for (symbol_length, count).
    fn len_histo_iter(histo: &[u8; 8]) -> impl Iterator<Item = (usize, u8)> {
        // Semantically: zip([2,3,4,5,6,7,8,1], histo[...[1,2,3,4,5,6,7,0]])
        (1..=8).map(|i| ((i & 7) + 1, histo[i & 7]))
    }

    /// Parse the symbol table `symtab`, from the serialization format from libfstt.
    ///
    /// This is re-implemented in Rust with the reference of
    /// [libfstt's `fsst_import`](https://github.com/cwida/fsst/blob/b228af6356196095eaf9f8f5654b0635f969661e/libfsst.cpp#L555).
    ///
    /// Some notable differences:
    /// - More error checking on short inputs, no buffer overflow, because we're Rust.
    /// - More permissive on version endianness. Allow both little and big endian versions.
    ///   Symbols are still always little-endian, as upstream.
    /// - Zero-terminated mode (NUL as the first symbol) is unsupported and rejected.
    /// - Encoder state bytes are ignored.
    /// - Trailing bytes are allowed but ignored.
    ///
    /// License of libfstt: MIT License, Copyright 2018-2020, CWI, TU Munich, FSU Jena
    ///
    /// # Errors
    ///
    /// Returns `None` if the input cannot be successfully parsed.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut this = Self::ALL_CORRUPT;

        let (&version_bytes, rest) = bytes.split_first_chunk::<8>().ok_or(ErrorInner::InputEof)?;
        let (&zero_terminated, rest) = rest.split_first().ok_or(ErrorInner::InputEof)?;
        let (&len_histo, rest) = rest.split_first_chunk::<8>().ok_or(ErrorInner::InputEof)?;

        // FIXME: This is in native endian, thus is non-portable and non-deterministic!
        // Here we use little-endian first, detect and fix the endianness by
        // using the fact the most-significant byte is always zero while the
        // least-significant byte is always non-zero.
        // Need further discussion with upstream.
        let mut version = u64::from_le_bytes(version_bytes);
        #[allow(clippy::verbose_bit_mask, reason = "less clear")]
        if version & 0xFF == 0 {
            version = version.swap_bytes();
        }
        if version >> 32 != u64::from(VERSION) {
            return Err(ErrorInner::InvalidMagic.into());
        }

        // Zero terminated flag is not supported.
        if zero_terminated & 1 != 0 {
            return Err(ErrorInner::NulMode.into());
        }

        let mut code = 0;
        let mut pos = 0;
        for (sym_len, cnt) in Self::len_histo_iter(&len_histo) {
            for _ in 0..cnt {
                let mut sym = 0u64;
                // TODO: Bound check before?
                sym.as_mut_bytes()[..sym_len]
                    .copy_from_slice(rest.get(pos..pos + sym_len).ok_or(ErrorInner::InputEof)?);
                *this.symbols.get_mut(code).ok_or(ErrorInner::CodeOverflow)? = sym;
                pos += sym_len;
                code += 1;
            }
        }

        Ok(this)
    }

    /// Return the max possible decoded length of `input_len` length input.
    #[inline]
    #[must_use]
    pub fn max_decode_len(input_len: usize) -> usize {
        // `usize::MAX` on overflow will guarantee a OOM on allocation.
        input_len.checked_mul(8).unwrap_or(usize::MAX)
    }

    #[inline]
    fn symbol_len(sym: Sym) -> usize {
        if cfg!(target_endian = "little") {
            8 - sym.leading_zeros() as usize / 8
        } else {
            8 - sym.trailing_zeros() as usize / 8
        }
    }

    /// Decode `input` into `output` and return the number of decoded length.
    ///
    /// # Errors
    ///
    /// If `output.len() < Self::max_decode_len(input.len())`, or an error occurs
    /// during decoding, `None` is returned.
    #[allow(clippy::missing_panics_doc, reason = "never panics")]
    pub fn decode_into(&self, input: &[u8], mut output: &mut [u8]) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if output.len() < Self::max_decode_len(input.len()) {
            return Err(ErrorInner::BufTooSmall.into());
        }
        if input.last() == Some(&0xFF) {
            return Err(ErrorInner::InvalidEscape.into());
        }

        let prev_output_len = output.len();
        let mut i = 0;
        // The second condition is a loop invariant, not an exit condition.
        while i < input.len() && output.len() >= MAX_SYMBOL_LEN {
            let b = input[i];
            if b < 0xFF {
                let sym = self.symbols[b as usize];
                if sym == 0 {
                    return Err(ErrorInner::InvalidSymbol.into());
                }
                // We always use max possible decode length, so output[..8] will never fail.
                *output.first_chunk_mut().expect("loop invariant") = sym.to_ne_bytes();
                output = &mut output[Self::symbol_len(sym)..];
            // This condition is always true due to the initial check,
            // but is here for better codegen.
            } else if i + 1 < input.len() {
                i += 1;
                output[0] = input[i];
                output = &mut output[1..];
            }
            i += 1;
        }
        Ok(prev_output_len - output.len())
    }

    /// Decode `input` into an owned byte string.
    ///
    /// # Errors
    ///
    /// If an error occurs during decoding, `None` is returned.
    pub fn decode(&self, input: &[u8]) -> Result<BString> {
        let mut buf = vec![0u8; Self::max_decode_len(input.len())];
        let len = self.decode_into(input, &mut buf)?;
        buf.truncate(len);
        Ok(buf.into())
    }
}

/// Serialize symbol table consists of given symbols into bytes.
///
/// `symbols` is an iterator of FSST symbols for code `0..`. It must be ordered
/// in length `2,3,4,5,6,7,8,1`.
///
/// # Errors
///
/// Returns `Err` if either:
/// - `symbols` has are more than 255 elements, or not in the expected order.
/// - A symbol has length outside range `1..=8`.
/// - A symbol contains a zero (NUL) byte.
#[cfg(feature = "serialize")]
pub fn to_bytes<I>(symbols: I) -> Result<Vec<u8>>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut tbl = [0u64; 255];
    let mut len_histo = [0u8; 8];
    let mut prev_len_order = 0usize;
    let mut code = 0usize;
    for bytes in symbols {
        if code >= 0xFF {
            return Err(ErrorInner::CodeOverflow.into());
        }
        let bytes = bytes.as_ref();
        let len = bytes.len();
        if !(1..=8).contains(&len) || bytes.contains(&0) {
            return Err(ErrorInner::InvalidSymbol.into());
        }
        // 23456781 => 0123456MAX
        let len_order = len.wrapping_sub(2);
        if prev_len_order > len_order {
            return Err(ErrorInner::IncorrectSymbolOrder.into());
        }
        prev_len_order = len_order;

        let mut sym = 0u64;
        sym.as_mut_bytes()[..len].copy_from_slice(bytes);
        tbl[code] = sym;
        code += 1;
        len_histo[len - 1] += 1;
    }

    let mut out = Vec::with_capacity(8 + 1 + 8 + MAX_SYMBOL_LEN * 255);
    // Magic bytes, with no parameters set.
    let magic = u64::from(VERSION) << 32 | 0xFF;
    out.extend_from_slice(&magic.to_le_bytes());
    // Disable `zero_terminated` mode.
    out.push(0x00);
    // Lengths.
    out.extend_from_slice(&len_histo);

    for sym in &tbl[..code] {
        let len = Decoder::symbol_len(*sym);
        out.extend_from_slice(&sym.as_bytes()[..len]);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::print_stderr)]
    fn smoke() {
        let tbl = Decoder {
            symbols: [u64::from_ne_bytes(*b"hello\0\0\0"); 255],
        };
        let debug = format!("{tbl:#?}");
        eprintln!("{debug}");
        assert!(debug.contains(r#"42: "hello","#));

        assert_eq!(tbl.decode(b"").unwrap(), "");
        assert_eq!(
            tbl.decode(b"\xFF").unwrap_err().to_string(),
            "invalid escape byte at the end of input",
        );
        assert_eq!(
            tbl.decode_into(b"\0", &mut [0u8; 4])
                .unwrap_err()
                .to_string(),
            "output buffer is too small",
        );

        let got = tbl.decode(b"\0\xFF,\0").unwrap();
        assert_eq!(got, "hello,hello");
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn serialize() {
        let bytes = to_bytes([&b"hello"[..], b"world", b"!"]).unwrap();
        let tbl = Decoder::parse(&bytes).unwrap();
        assert_eq!(tbl.decode(b"\0\xFF,\x01\x02").unwrap(), "hello,world!");

        assert_eq!(
            to_bytes([&b"!"[..], b"hello"]).unwrap_err().to_string(),
            "symbols must be ordered in length 2,3,4,5,6,7,8,1",
        );
        assert_eq!(
            to_bytes([b"123456789"]).unwrap_err().to_string(),
            "invalid symbol",
        );
        assert_eq!(
            to_bytes(&[b"a"].repeat(256)).unwrap_err().to_string(),
            "too many symbols",
        );
    }
}
