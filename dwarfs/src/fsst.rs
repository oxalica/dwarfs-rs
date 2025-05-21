//! The [Fast Static Symbol Table (FSST)][fsst] decoder for compressed string
//! tables [`StringTable::symtab`][crate::metadata::StringTable::symtab].
//!
//! [fsst]: https://github.com/cwida/fsst

use std::fmt;

use bstr::BString;
use zerocopy::IntoBytes;

/// FSST decoder.
///
/// See [module level documentations](self). Note that this struct contains a
/// ~2KiB large array, and you may want to box it for fast moving.
pub struct Decoder {
    /// Code -> symbol mapping, stored in native-endian, with trailing bytes filled by NUL.
    symbols: [u64; 255],
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl Decoder {
    /// The max length of one symbol.
    pub const MAX_SYMBOL_LEN: usize = 8;

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
    #[allow(clippy::missing_panics_doc, reason = "never panics")]
    #[must_use]
    pub fn parse_symtab(symtab: &[u8]) -> Option<Self> {
        const VERSION: u32 = 2019_0218;
        const SYM_CORRUPT: u64 = u64::from_ne_bytes(*b"corrupt\0");

        let mut symbols = [0u64; 255];

        let (header, data) = symtab.split_at_checked(17)?;
        // FIXME: This is in native endian, thus is non-portable and non-deterministic!
        // Here we use little-endian first, detect and fix the endianness by
        // using the fact the most-significant byte is always zero while the
        // least-significant byte is always non-zero.
        // Need further discussion with upstream.
        let mut version_field = u64::from_le_bytes(header[..8].try_into().expect("length matches"));
        #[allow(clippy::verbose_bit_mask, reason = "less clear")]
        if version_field & 0xFF == 0 {
            version_field = version_field.to_be();
        }
        (version_field >> 32 == u64::from(VERSION)).then_some(())?;

        // Not supported.
        let zero_terminated = header[8] & 1 != 0;
        (!zero_terminated).then_some(())?;

        let len_histo = <[u8; 8]>::try_from(&header[9..17]).expect("length matches");

        let mut code = 0;
        let mut pos = 0;
        for sym_len in [2, 3, 4, 5, 6, 7, 8, 1] {
            let cnt = len_histo[sym_len - 1];
            for _ in 0..cnt {
                let mut sym = 0u64;
                // TODO: Bound check before?
                sym.as_mut_bytes()[..sym_len].copy_from_slice(data.get(pos..pos + sym_len)?);
                symbols[code] = sym;
                pos += sym_len;
                code += 1;
            }
        }

        symbols[code..].fill(SYM_CORRUPT);

        Some(Self { symbols })
    }

    /// Return the max possible decoded length of `input_len` length input.
    #[inline]
    #[must_use]
    pub fn max_decode_len(input_len: usize) -> usize {
        // `usize::MAX` on overflow will guarantee a OOM on allocation.
        input_len.checked_mul(8).unwrap_or(usize::MAX)
    }

    /// Decode `input` into `output` and return the number of decoded length.
    ///
    /// If `output.len() < Self::max_decode_len(input.len())`, or an error occurs
    /// during decoding, `None` is returned.
    pub fn decode_into(&self, input: &[u8], output: &mut [u8]) -> Option<usize> {
        (output.len() >= Self::max_decode_len(input.len())).then_some(())?;

        let mut i = 0;
        let mut j = 0;
        while i < input.len() && j < output.len() {
            let b = input[i];
            if b < 0xFF {
                let sym = self.symbols[b as usize];
                #[cfg(target_endian = "little")]
                let sym_len = 8 - sym.leading_zeros() / 8;
                #[cfg(target_endian = "big")]
                let sym_len = 8 - sym.trailing_zeros() / 8;
                // We always use max possible decode length, so [..8] will never overflow.
                output[j..][..8].copy_from_slice(sym.as_bytes());
                j += sym_len as usize;
            } else {
                i += 1;
                output[j] = *input.get(i)?;
                j += 1;
            }
            i += 1;
        }
        Some(j)
    }

    /// Decode `input` into an owned byte string.
    ///
    /// # Errors
    ///
    /// If an error occurs during decoding, `None` is returned.
    #[must_use]
    pub fn decode(&self, input: &[u8]) -> Option<BString> {
        let mut buf = vec![0u8; Self::max_decode_len(input.len())];
        let len = self.decode_into(input, &mut buf)?;
        buf.truncate(len);
        Some(buf.into())
    }
}
