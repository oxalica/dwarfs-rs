use std::io::Write;

use dwarfs::section::{CompressAlgo, Header, MagicVersion, SectionIndexEntry, SectionType};
use dwarfs::zerocopy::IntoBytes;

use crate::{ErrorInner, Result};

/// The section compression parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressParam {
    None,
    // TODO
}

#[derive(Debug)]
pub struct Writer<W: ?Sized> {
    next_offset: u64,
    index: Vec<SectionIndexEntry>,
    w: W,
}

impl<W> Writer<W> {
    pub const fn new(w: W) -> Self {
        Self {
            next_offset: 0,
            index: Vec::new(),
            w,
        }
    }
}

impl<W: ?Sized> Writer<W> {
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.w
    }

    pub fn into_inner(self) -> W
    where
        W: Sized,
    {
        self.w
    }
}

impl<W: Write> Writer<W> {
    #[must_use]
    pub fn section_count(&self) -> u32 {
        // Checked by `push_section` not to overflow u32.
        self.index.len() as u32
    }

    pub fn finish(&mut self) -> Result<()> {
        // This is the last section. The next offset is ignored. Put a zero here.
        self.push_section(SectionType::SECTION_INDEX, 0)?;
        let section_number = self.section_count();
        Self::write_section_inner(
            &mut self.w,
            section_number,
            SectionType::SECTION_INDEX,
            CompressParam::None,
            self.index.as_slice().as_bytes(),
        )?;

        // Set to an invalid state so there cannot be more sections.
        std::mem::take(&mut self.index);
        self.next_offset = u64::MAX;

        Ok(())
    }

    fn push_section(&mut self, typ: SectionType, written: usize) -> Result<()> {
        let ent = SectionIndexEntry::new(typ, self.next_offset)
            .ok_or(ErrorInner::Limit("archive size exceeds 2^48 bytes"))?;
        self.index.push(ent);
        // An overflow will be detected by next `push_section`.
        self.next_offset = self
            .next_offset
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        u32::try_from(self.index.len())
            .ok()
            .ok_or(ErrorInner::Limit("section count exceeds 2^32"))?;
        Ok(())
    }

    pub fn write_section(
        &mut self,
        section_type: SectionType,
        compression: CompressParam,
        payload: &[u8],
    ) -> Result<()> {
        let section_number = self.section_count();
        let written = Self::write_section_inner(
            &mut self.w,
            section_number,
            section_type,
            compression,
            payload,
        )?;
        self.push_section(section_type, written)?;
        Ok(())
    }

    fn write_section_inner(
        w: &mut dyn Write,
        section_number: u32,
        section_type: SectionType,
        compression: CompressParam,
        payload: &[u8],
    ) -> Result<usize> {
        let (compress_algo, compressed_payload) = match compression {
            CompressParam::None => (CompressAlgo::NONE, payload),
        };
        let compressed_size = u64::try_from(compressed_payload.len())
            .ok()
            // Should not happen for current machines.
            .ok_or(ErrorInner::Limit("payload size exceeds 2^64 bytes"))?;

        let mut header = Header {
            magic_version: MagicVersion::LATEST,
            slow_hash: [0u8; 32],
            fast_hash: [0u8; 8],
            section_number: section_number.into(),
            section_type,
            compress_algo,
            payload_size: compressed_size.into(),
        };

        // TODO: Multi threading.
        header.update_size_and_checksum(payload);

        // We could use `write_vectored` here.
        // WAIT: <https://github.com/rust-lang/rust/issues/70436>
        w.write_all(header.as_bytes())?;
        w.write_all(compressed_payload)?;

        Ok(size_of_val(&header) + compressed_payload.len())
    }
}
