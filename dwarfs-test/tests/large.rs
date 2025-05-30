//! Large tests on real production archives.
use std::{
    io::{BufRead, Seek, SeekFrom, Write},
    sync::LazyLock,
    time::Instant,
};

use dwarfs::{
    Archive, AsChunks,
    metadata::{Metadata, Schema},
    positioned_io::ReadAt,
    section::{CompressAlgo, Header, MagicVersion, SectionIndexEntry, SectionReader, SectionType},
};
use tempfile::NamedTempFile;
use xshell::{Shell, cmd};

static TEST_FILES: LazyLock<Vec<String>> = LazyLock::new(|| {
    std::env::var("DWARFS_LARGE_TEST_FILES")
        .expect("DWARFS_LARGE_TEST_FILES is not set")
        .split_ascii_whitespace()
        .map(Into::into)
        .collect()
});

fn with_tests(mut f: impl FnMut(&str, std::fs::File)) {
    for path in &*TEST_FILES {
        eprintln!("Testing {path}");
        let file = std::fs::File::open(path).unwrap();
        f(path, file);
    }
}

fn read_section_by_type(
    rdr: &mut SectionReader<impl ReadAt>,
    sec_index: &[SectionIndexEntry],
    typ: SectionType,
) -> Vec<u8> {
    let offset = sec_index
        .iter()
        .find_map(|i| (i.section_type() == typ).then_some(i.offset()))
        .expect("missing section");
    let (_, bytes) = rdr
        .read_section_at(offset, 16 << 20)
        .expect("failed to read section");
    bytes
}

/// Update the schema and metadata section of an existing DwarFS archive.
fn patch_schema_and_metadata(
    mut orig_file: &std::fs::File,
    index: &[SectionIndexEntry],
    schema_bytes: &[u8],
    metadata_bytes: &[u8],
) -> NamedTempFile {
    // For typical archives, all non-BLOCK sections are at the end, after all BLOCK sections.
    let data_sections = index
        .iter()
        .position(|&ent| ent.section_type() != SectionType::BLOCK)
        .unwrap();
    assert!(
        index[data_sections..]
            .iter()
            .all(|ent| ent.section_type() != SectionType::BLOCK)
    );
    let data_end_pos = index[data_sections].offset();

    let mut patched_file = NamedTempFile::new().unwrap();
    let fout = patched_file.as_file_mut();
    std::io::copy(&mut orig_file, fout).unwrap();
    fout.set_len(data_end_pos).unwrap();
    fout.seek(SeekFrom::End(0)).unwrap();

    for (i, typ, payload) in [
        (0, SectionType::METADATA_V2_SCHEMA, schema_bytes),
        (1, SectionType::METADATA_V2, metadata_bytes),
    ] {
        write_section(fout, data_sections as u32 + i, typ, payload).unwrap();
    }

    patched_file
}

fn write_section(
    w: &mut dyn Write,
    section_num: u32,
    typ: SectionType,
    payload: &[u8],
) -> std::io::Result<()> {
    use dwarfs::zerocopy::IntoBytes;

    let mut header = Header {
        magic_version: MagicVersion::LATEST,
        slow_hash: [0; 32],
        fast_hash: [0; 8],
        section_number: section_num.into(),
        section_type: typ,
        compress_algo: CompressAlgo::NONE,
        payload_size: 0.into(),
    };
    header.update_size_and_checksum(payload);
    w.write_all(header.as_bytes())?;
    w.write_all(payload)
}

fn test_reserialize(schema_only: bool) {
    let sh = Shell::new().unwrap();

    with_tests(|orig_path, file| {
        let dump1 = cmd!(sh, "dwarfsck -i {orig_path} -d metadata_full_dump")
            .read()
            .unwrap();

        let file_size = file.metadata().expect("failed to get file size").len();
        let mut rdr = SectionReader::new(file);
        let (_, sec_index) = rdr
            .read_section_index(file_size, 16 << 20)
            .expect("failed to read section index")
            .expect("missing section index");
        let mut schema_bytes =
            read_section_by_type(&mut rdr, &sec_index, SectionType::METADATA_V2_SCHEMA);
        let mut metadata_bytes =
            read_section_by_type(&mut rdr, &sec_index, SectionType::METADATA_V2);
        let schema = Schema::parse(&schema_bytes).expect("failed to parse schema");

        if schema_only {
            let schema_ser = schema.to_bytes().unwrap();
            let schema2 = Schema::parse(&schema_ser).unwrap();
            assert_eq!(schema, schema2);
            schema_bytes = schema_ser;
        } else {
            let metadata = Metadata::parse(&schema, &metadata_bytes).unwrap();
            let (schema2, metadata_ser) = metadata.to_schema_and_bytes().unwrap();
            let metadata2 = Metadata::parse(&schema2, &metadata_ser).unwrap();
            assert_eq!(metadata, metadata2);
            let schema_ser = schema2.to_bytes().unwrap();
            (schema_bytes, metadata_bytes) = (schema_ser, metadata_ser);
        }

        let patched_file =
            patch_schema_and_metadata(rdr.get_ref(), &sec_index, &schema_bytes, &metadata_bytes);
        let patched_path = patched_file.path();
        let dump2 = cmd!(sh, "dwarfsck -i {patched_path} -d metadata_full_dump")
            .read()
            .unwrap();
        if dump1 != dump2 {
            std::fs::write("./result-metadata-dump-before.txt", &dump1).unwrap();
            std::fs::write("./result-metadata-dump-after.txt", &dump2).unwrap();
            panic!("metadata dump differs, results saved to result-metadata-dump-*.txt");
        }
    });
}

#[test]
#[ignore = "large test"]
fn schema_roundtrip() {
    test_reserialize(true);
}

#[test]
#[ignore = "large test"]
fn metadata_roundtrip() {
    test_reserialize(false);
}

#[test]
#[ignore = "large test"]
fn dump_mtree() {
    let sh = Shell::new().unwrap();
    with_tests(|path, file| {
        let expect = cmd!(sh, "dwarfsextract -i {path} -f mtree --log-level=error")
            .read()
            .unwrap();
        let expect = expect.trim_ascii_end();

        let mut got = Vec::new();
        let (index, _archive) = Archive::new(file).unwrap();
        dwarfs_test::mtree::dump(&mut got, &index).unwrap();
        let actual = str::from_utf8(&got).unwrap().trim_ascii_end();

        if actual != expect {
            std::fs::write("result-actual.mtree", actual).unwrap();
            std::fs::write("result-expect.mtree", expect).unwrap();
            panic!("mtree mismatch");
        }
    });
}

#[test]
#[ignore = "large test"]
fn dump_content() {
    use sha2::{Digest, Sha512_256};
    assert!(
        !cfg!(debug_assertions),
        "requires '--release' or it will be too slow",
    );

    let sh = Shell::new().unwrap();
    with_tests(|archive_path, archive_file| {
        let inst = Instant::now();
        let output = cmd!(
            sh,
            "dwarfsck --checksum=sha512-256 -i {archive_path} --log-level=error"
        )
        .read()
        .unwrap();
        eprintln!("dwarfsck completes in {:?}", inst.elapsed());

        let mut expect = output
            .lines()
            .map(|line| line.split_once("  ").unwrap())
            .collect::<Vec<_>>();
        expect.sort_unstable_by_key(|(_, name)| *name);
        let expect = expect
            .iter()
            .flat_map(|(hash, path)| [hash, "  ", path, "\n"])
            .collect::<String>();

        let inst = Instant::now();
        let (index, mut archive) = Archive::new(archive_file).unwrap();
        let mut actual = Vec::with_capacity(index.inodes().len());
        let mut h = Sha512_256::new();
        let files = dwarfs_test::traverse::traverse_files(&index);
        eprintln!("traversal completes in {:?}", inst.elapsed());
        for (path, file) in files {
            let mut rdr = file.as_reader(&mut archive);
            loop {
                let buf = rdr.fill_buf().unwrap();
                if buf.is_empty() {
                    break;
                }
                h.update(buf);
                let len = buf.len();
                rdr.consume(len);
            }
            let digest = hex::encode(h.finalize_reset().as_slice());
            actual.push((digest, path));
        }
        actual.sort_unstable_by(|(_, lhs), (_, rhs)| Ord::cmp(lhs, rhs));
        let actual = actual
            .iter()
            // Exclude leading `/`.
            .flat_map(|(hash, path)| [hash, "  ", &path[1..], "\n"])
            .collect::<String>();
        eprintln!("traversal+checksum completes in {:?}", inst.elapsed());

        if actual != expect {
            std::fs::write("result-actual.cksum", actual).unwrap();
            std::fs::write("result-expect.cksum", expect).unwrap();
            panic!("results mismatch")
        }
    });
}
