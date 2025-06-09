use dwarfs::{Archive, AsChunks, InodeKind, archive::IsInode};
use dwarfs_enc::{
    chunker::{BasicChunker, Chunker},
    metadata::{Builder, InodeMetadata},
    section::{CompressParam, Writer},
};

const META: InodeMetadata = InodeMetadata::new(0o777);

fn build_with(f: impl FnOnce(&mut Builder, &mut dyn Chunker) -> dwarfs_enc::Result<()>) -> Vec<u8> {
    let buf = Vec::new();
    let writer = Writer::new(buf).unwrap();
    let mut builder = Builder::new(&META);
    let mut chunker = BasicChunker::new(writer, builder.block_size(), CompressParam::Zstd(3));
    f(&mut builder, &mut chunker).unwrap();
    let mut writer = chunker.finish().unwrap();
    writer
        .write_metadata_sections(&builder.finish().unwrap(), CompressParam::Zstd(3))
        .unwrap();
    writer.finish().unwrap()
}

#[test]
fn empty() {
    let b = build_with(|_meta, _chunker| Ok(()));
    let (index, _archive) = Archive::new(b).unwrap();
    assert_eq!(index.root().entries().len(), 0);
    assert_eq!(index.inodes().len(), 1);
    assert_eq!(index.directories().len(), 1);
}

#[test]
fn smoke() {
    let b = build_with(|meta, _chunker| {
        let root = meta.root();
        meta.put_dir(root, "0dir", &META)?;
        let f = meta.put_file(root, "1file", &META, [])?;
        meta.put_symlink(root, "2symlink", &META, "target")?;
        meta.put_block_device(root, "3blkdev", &META, 0xDEAD_BEEF_DEAD_BEEF)?;
        meta.put_char_device(root, "4chardev", &META, 0xBEEF_DEAD_BEEF_DEAD)?;
        meta.put_fifo(root, "5fifo", &META)?;
        meta.put_socket(root, "6socket", &META)?;
        meta.put_hard_link(root, "7hardlink", f)?;
        Ok(())
    });

    let (index, _archive) = Archive::new(b).unwrap();
    let (children, names) = index
        .root()
        .entries()
        .map(|ent| (ent.inode().classify(), ent.name()))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    assert_eq!(
        names,
        vec![
            "0dir",
            "1file",
            "2symlink",
            "3blkdev",
            "4chardev",
            "5fifo",
            "6socket",
            "7hardlink",
        ]
    );

    assert!(matches!(children[0], InodeKind::Directory(_)));
    assert!(matches!(children[1], InodeKind::File(i) if i.as_chunks().len() == 0));
    assert!(matches!(children[2], InodeKind::Symlink(i) if i.target() == "target"));
    assert!(matches!(children[3], InodeKind::Device(i) if i.device_id() == 0xDEAD_BEEF_DEAD_BEEF));
    assert!(matches!(children[4], InodeKind::Device(i) if i.device_id() == 0xBEEF_DEAD_BEEF_DEAD));
    assert!(matches!(children[5], InodeKind::Ipc(_)));
    assert!(matches!(children[6], InodeKind::Ipc(_)));
    assert_eq!(children[7].inode_num(), children[1].inode_num());
}
