//! Large tests on real production archives.
use std::{io::BufRead, sync::LazyLock, time::Instant};

use dwarfs::{
    Archive, AsChunks,
    metadata::Schema,
    section::{SectionReader, SectionType},
};
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

#[test]
#[ignore = "large test"]
fn schema_roundtrip() {
    with_tests(|_path, file| {
        let file_size = file.metadata().expect("failed to get file size").len();
        let mut rdr = SectionReader::new(file);
        let (_, sec_index) = rdr
            .read_section_index(file_size, 16 << 20)
            .expect("failed to read section index")
            .expect("missing section index");
        let offset = sec_index
            .iter()
            .find_map(|i| {
                (i.section_type() == SectionType::METADATA_V2_SCHEMA).then_some(i.offset())
            })
            .expect("missing schema section");
        let (_, schema_bytes) = rdr
            .read_section_at(offset, 16 << 20)
            .expect("failed to read schema");

        let schema1 = Schema::parse(&schema_bytes).expect("failed to parse schema");
        let schema_ser = schema1.to_bytes().expect("failed to serialize schema");
        let schema2 = Schema::parse(&schema_ser).expect("failed to reparse schema");
        assert_eq!(schema1, schema2);
    });
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
