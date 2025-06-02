use std::{
    fs,
    io::{ErrorKind, Read, Write},
};

use dwarfs::section::SectionType;

use crate::{
    Result, metadata,
    section::{CompressParam, Writer as SectionWriter},
};

pub struct SimpleArchiver<W: ?Sized> {
    meta: Box<metadata::Builder>,
    block_buf: Box<[u8]>,
    block_buf_used: usize,
    w: SectionWriter<W>,
}

impl<W> SimpleArchiver<W> {
    pub fn new(w: W, root_meta: &metadata::InodeMetadata) -> Self {
        Self::new_with_config(w, root_meta, &metadata::Config::default())
    }

    pub fn new_with_config(
        w: W,
        root_meta: &metadata::InodeMetadata,
        config: &metadata::Config,
    ) -> Self {
        Self {
            meta: Box::new(metadata::Builder::new_with_config(config, root_meta)),
            block_buf: vec![0u8; config.get_block_size().get() as usize].into(),
            block_buf_used: 0,
            w: SectionWriter::new(w),
        }
    }
}

impl<W: ?Sized> SimpleArchiver<W> {
    pub fn get_ref(&self) -> &W {
        self.w.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut W {
        self.w.get_mut()
    }
}

impl<W> std::ops::Deref for SimpleArchiver<W> {
    type Target = metadata::Builder;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.meta
    }
}

impl<W> std::ops::DerefMut for SimpleArchiver<W> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.meta
    }
}

impl<W: Write> SimpleArchiver<W> {
    pub fn finish(mut self) -> Result<W> {
        if self.block_buf_used != 0 {
            self.flush_block_buf()?;
        }

        {
            let metadata = self.meta.finish()?;
            let (schema, metadata_bytes) = metadata.to_schema_and_bytes()?;
            let schema_bytes = schema.to_bytes()?;
            self.w.write_section(
                SectionType::METADATA_V2_SCHEMA,
                CompressParam::None,
                &schema_bytes,
            )?;
            self.w.write_section(
                SectionType::METADATA_V2,
                CompressParam::None,
                &metadata_bytes,
            )?;
        }

        self.w.finish()?;

        Ok(self.w.into_inner())
    }

    fn flush_block_buf(&mut self) -> Result<()> {
        let data = &self.block_buf[..self.block_buf_used];
        debug_assert!(!data.is_empty());
        self.w
            .write_section(SectionType::BLOCK, CompressParam::None, data)?;
        self.block_buf_used = 0;
        Ok(())
    }

    pub fn put_data_from_reader<R: Read>(&mut self, mut rdr: R) -> Result<Vec<metadata::Chunk>> {
        let mut chunks = Vec::new();
        let block_size = self.block_buf.len();
        let mut start_offset = self.block_buf_used;
        let mut buf = &mut self.block_buf[start_offset..];
        loop {
            match rdr.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                    self.block_buf_used += n;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
            if buf.is_empty() {
                let sec_idx = self.w.section_count();
                self.flush_block_buf()?;
                chunks.push(metadata::Chunk::new(
                    sec_idx,
                    start_offset as u32,
                    (block_size - start_offset) as u32,
                ));
                start_offset = 0;
                buf = &mut self.block_buf;
            }
        }
        chunks.push(metadata::Chunk::new(
            self.w.section_count(),
            start_offset as u32,
            (self.block_buf_used - start_offset) as u32,
        ));
        Ok(chunks)
    }

    pub fn put_os_dir_at(
        &mut self,
        parent: metadata::DirId,
        name: &str,
        os_meta: &fs::Metadata,
    ) -> Result<metadata::DirId> {
        let inode_meta = metadata::InodeMetadata::try_from(os_meta)?;
        self.put_dir_entry(parent, name, &inode_meta)
    }

    pub fn put_os_file_at(
        &mut self,
        parent: metadata::DirId,
        name: &str,
        os_meta: &fs::Metadata,
        os_file: &fs::File,
    ) -> Result<metadata::FileId> {
        let inode_meta = metadata::InodeMetadata::try_from(os_meta)?;
        let chunks = self.put_data_from_reader(os_file)?;
        let file = self.put_file(&inode_meta, chunks)?;
        self.put_entry(parent, name, file)?;
        Ok(file)
    }
}
