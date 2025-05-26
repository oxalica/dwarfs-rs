use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use dwarfs::{
    Archive, AsChunks,
    archive::{Config, IsInode, SectionIndexStrategy},
};
use xshell::{Shell, TempDir, cmd};

fn debug_print_mtree(sh: &Shell, archive_path: &Path) {
    let mtree_out = cmd!(
        sh,
        "dwarfsextract -i {archive_path} -f mtree --log-level=error"
    )
    .read()
    .unwrap();
    eprintln!("{mtree_out}");
}

#[track_caller]
fn build_archive(sh: &Shell, out: &str, opts: &str) -> PathBuf {
    let opts = opts.split_ascii_whitespace();
    cmd!(
        sh,
        "mkdwarfs -i ./root -o {out} --no-progress --log-level=error {opts...}"
    )
    .run()
    .unwrap();
    debug_print_mtree(sh, out.as_ref());
    sh.current_dir().join(out)
}

fn new_temp_shell() -> (Shell, TempDir) {
    let sh = Shell::new().unwrap();
    let temp_dir = sh.create_temp_dir().unwrap();
    sh.change_dir(temp_dir.path());
    (sh, temp_dir)
}

#[test]
fn empty() {
    let (sh, _temp_dir) = new_temp_shell();
    sh.create_dir("root").unwrap();
    let archive_path = build_archive(&sh, "img.dwarfs", "--set-time=42");
    let (index, _archive) = Archive::new(fs::File::open(&archive_path).unwrap()).unwrap();

    let root = index.root();
    assert_eq!(root.inode_num(), 0);
    assert_eq!(index.inodes().len(), 1);
    assert_eq!(index.inodes().next().unwrap().inode_num(), root.inode_num());
    assert_eq!(index.directories().len(), 1);
    assert_eq!(
        index.directories().next().unwrap().inode_num(),
        root.inode_num()
    );

    assert_eq!(root.entries().len(), 0);
    assert!(root.get("").is_none());

    assert_eq!(index.get_inode(0).unwrap().inode_num(), 0);

    assert_eq!(
        index
            .get_path(std::iter::empty::<&str>())
            .unwrap()
            .inode_num(),
        root.inode_num()
    );

    let meta = root.metadata();
    assert_eq!(meta.mtime(), 42);
    assert_eq!(meta.atime(), None);
    assert_eq!(meta.ctime(), None);
    #[cfg(unix)]
    assert_eq!(
        meta.file_type_mode().type_bits(),
        rustix::fs::FileType::Directory.as_raw_mode(),
    );
}

#[test]
fn basics() {
    let (sh, _temp_dir) = new_temp_shell();
    sh.create_dir("root").unwrap();
    sh.create_dir("root/dir1").unwrap();
    sh.create_dir("root/dir2").unwrap();
    sh.write_file("root/dir2/foo.txt", "bar").unwrap();
    sh.write_file("root/empty", "").unwrap();
    fs::File::open(sh.current_dir().join("root/dir2/foo.txt"))
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(42))
                .set_accessed(SystemTime::UNIX_EPOCH + Duration::from_secs(666)),
        )
        .unwrap();
    let archive_path = build_archive(&sh, "img.dwarfs", "--keep-all-times");

    let (index, mut archive) = Archive::new(fs::File::open(&archive_path).unwrap()).unwrap();
    let root = index.root();
    assert_eq!(
        root.entries().map(|ent| ent.name()).collect::<Vec<_>>(),
        ["dir1", "dir2", "empty"],
    );

    let dir1 = root.get("dir1").unwrap().inode().as_dir().unwrap();
    assert_eq!(dir1.entries().len(), 0);

    let empty = root.get("empty").unwrap().inode().as_file().unwrap();
    assert_eq!(empty.read_to_vec(&mut archive).unwrap(), []);
    assert_eq!(empty.as_chunks().len(), 0);
    assert_eq!(empty.as_chunks().total_size(), 0);
    assert_eq!(empty.as_reader(&mut archive).total_size(), 0);
    assert_eq!(empty.as_reader(&mut archive).fill_buf().unwrap(), []);

    let dir2 = root.get("dir2").unwrap().inode().as_dir().unwrap();
    let foo = dir2.get("foo.txt").unwrap().inode();
    let foo2 = index.get_path(["dir2", "foo.txt"]).unwrap();
    assert_eq!(foo.inode_num(), foo2.inode_num());
    let foo = foo.as_file().unwrap();

    assert_eq!(foo.as_chunks().len(), 1);
    assert_eq!(foo.as_chunks().total_size(), 3);
    assert_eq!(
        foo.as_chunks()
            .next()
            .unwrap()
            .read_cached(&mut archive)
            .unwrap(),
        b"bar"
    );
    assert_eq!(foo.read_to_vec(&mut archive).unwrap(), b"bar");

    let meta = foo.metadata();
    assert_eq!(meta.mtime(), 42);
    assert_eq!(meta.atime(), Some(666));
    assert!(meta.ctime().is_some());
    #[cfg(unix)]
    assert_eq!(
        meta.file_type_mode().type_bits(),
        rustix::fs::FileType::RegularFile.as_raw_mode(),
    );
}

#[cfg(unix)]
#[test]
fn unix_specials() {
    use dwarfs::InodeKind;
    use rustix::fs::{self as ufs, FileType, Mode};

    let (sh, _temp_dir) = new_temp_shell();
    let src_path = sh.create_dir("root").unwrap();
    ufs::symlink("/absolute/path", src_path.join("abs")).unwrap();
    ufs::symlink("/absolute/path", src_path.join("dup")).unwrap();
    ufs::symlink("../relative/path", src_path.join("rel")).unwrap();

    // Do not mask. We make assertions on permissions below.
    rustix::process::umask(Mode::empty());

    ufs::mkdir(
        src_path.join("sticky"),
        Mode::RWXU | Mode::XOTH | Mode::SVTX,
    )
    .unwrap();
    ufs::mknodat(
        ufs::ABS,
        src_path.join("pipe"),
        FileType::Fifo,
        Mode::RWXU | Mode::SUID,
        0,
    )
    .unwrap();
    ufs::mknodat(
        ufs::ABS,
        src_path.join("sock"),
        FileType::Socket,
        Mode::RWXG | Mode::SGID,
        0,
    )
    .unwrap();

    let archive_path = build_archive(&sh, "img.dwarfs", "--with-specials");
    let (index, _archive) = Archive::new(fs::File::open(&archive_path).unwrap()).unwrap();
    let root = index.root();

    assert!(matches!(root.get("abs").unwrap().inode().classify(),
        InodeKind::Symlink(f) if f.target() == "/absolute/path"));
    assert!(matches!(root.get("dup").unwrap().inode().classify(),
        InodeKind::Symlink(f) if f.target() == "/absolute/path"));
    assert!(matches!(root.get("rel").unwrap().inode().classify(),
        InodeKind::Symlink(f) if f.target() == "../relative/path"));

    let sticky = root.get("sticky").unwrap().inode().as_dir().unwrap();
    let sticky_mode = sticky.metadata().file_type_mode();
    assert_eq!(
        FileType::from_raw_mode(sticky_mode.type_bits()),
        FileType::Directory
    );
    assert_eq!(
        Mode::from_bits(sticky_mode.mode_bits()),
        Some(Mode::RWXU | Mode::XOTH | Mode::SVTX)
    );

    let pipe = root.get("pipe").unwrap().inode();
    let pipe_mode = pipe.metadata().file_type_mode();
    assert!(matches!(pipe.classify(), InodeKind::Ipc(_)));
    assert_eq!(
        FileType::from_raw_mode(pipe_mode.type_bits()),
        FileType::Fifo,
    );
    assert_eq!(
        Mode::from_bits(pipe_mode.mode_bits()),
        Some(Mode::RWXU | Mode::SUID)
    );

    let sock = root.get("sock").unwrap().inode();
    let sock_mode = sock.metadata().file_type_mode();
    assert!(matches!(sock.classify(), InodeKind::Ipc(_)));
    assert_eq!(
        FileType::from_raw_mode(sock_mode.type_bits()),
        FileType::Socket,
    );
    assert_eq!(
        Mode::from_bits(sock_mode.mode_bits()),
        Some(Mode::RWXG | Mode::SGID)
    );
}

#[cfg(unix)]
#[test]
fn unix_devices() {
    use dwarfs::InodeKind;
    use rustix::fs::FileType;

    let (sh, _temp_dir) = new_temp_shell();
    let exe = env!("CARGO_BIN_EXE_dwarfs-test");
    cmd!(
        sh,
        "fakeroot -- {exe} gen-privileged-archive --output img.dwarfs"
    )
    .run()
    .unwrap();
    let archive_path = sh.current_dir().join("img.dwarfs");
    debug_print_mtree(&sh, &archive_path);

    let (index, _archive) = Archive::new(fs::File::open(&archive_path).unwrap()).unwrap();
    let root = index.root();

    let bdev = root.get("bdev").unwrap().inode();
    let InodeKind::Device(bdev) = bdev.classify() else {
        panic!("wrong file type")
    };
    assert_eq!(bdev.device_id(), 0x0123_4567_89AB_CDEF);
    assert_eq!(
        FileType::from_raw_mode(bdev.metadata().file_type_mode().type_bits()),
        FileType::BlockDevice,
    );

    let cdev = root.get("cdev").unwrap().inode();
    let InodeKind::Device(cdev) = cdev.classify() else {
        panic!("wrong file type")
    };
    assert_eq!(cdev.device_id(), 0xFEDC_BA98_7654_3210);
    assert_eq!(
        FileType::from_raw_mode(cdev.metadata().file_type_mode().type_bits()),
        FileType::CharacterDevice,
    );
}

#[test]
fn section_index() {
    let (sh, _temp_dir) = new_temp_shell();
    sh.create_dir("root").unwrap();

    let load = |f: &Path, strategy: SectionIndexStrategy| {
        Archive::new_with_config(
            fs::File::open(f).unwrap(),
            Config::default().section_index_strategy(strategy),
        )
    };

    let with_index = build_archive(&sh, "with_index.dwarfs", "");
    load(&with_index, SectionIndexStrategy::UseEmbeddedIfExists).unwrap();
    load(&with_index, SectionIndexStrategy::Build).unwrap();
    load(&with_index, SectionIndexStrategy::UseEmbedded).unwrap();

    let no_index = build_archive(&sh, "no_index.dwarfs", "--no-section-index");
    load(&no_index, SectionIndexStrategy::UseEmbeddedIfExists).unwrap();
    load(&no_index, SectionIndexStrategy::Build).unwrap();

    let err = load(&no_index, SectionIndexStrategy::UseEmbedded).unwrap_err();
    assert_eq!(err.to_string(), "missing section SECTION_INDEX");
}

#[test]
fn packed_metadata() {
    let (sh, _temp_dir) = new_temp_shell();
    let src_dir = sh.create_dir("root").unwrap();
    sh.create_dir("root/foo/foo/baz").unwrap();
    sh.write_file("root/foo/baz", "hello world").unwrap();
    sh.write_file("root/baz", "").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs as ufs;
        ufs::symlink("foo", src_dir.join("sym1")).unwrap();
        ufs::symlink("foo", src_dir.join("sym2")).unwrap();
        ufs::symlink("bar", src_dir.join("sym3")).unwrap();
    }

    let pack_none = build_archive(&sh, "none.dwarfs", "--pack-metadata=none");
    Archive::new(fs::File::open(pack_none).unwrap()).unwrap();

    let pack_all = build_archive(&sh, "all.dwarfs", "--pack-metadata=all");
    Archive::new(fs::File::open(pack_all).unwrap()).unwrap();
}

#[test]
fn symtab() {
    let (sh, _temp_dir) = new_temp_shell();
    let names = (0..32)
        .map(|i| format!("a_very_common_prefix.{i:02}.txt"))
        .collect::<Vec<_>>();

    for name in &names {
        sh.write_file(format!("root/{name}"), "").unwrap();
    }

    let archive_path = build_archive(&sh, "img.dwarfs", "--pack-metadata=names,force");
    let (index, _) = Archive::new(fs::File::open(archive_path).unwrap()).unwrap();
    let root = index.root();
    assert_eq!(
        root.entries().map(|ent| ent.name()).collect::<Vec<_>>(),
        names,
    );
}

#[test]
fn shared_files() {
    let (sh, _temp_dir) = new_temp_shell();
    let content = (0..1024)
        .map(|i| format!("{i:04}"))
        .collect::<String>()
        .into_bytes();
    sh.write_file("root/a.txt", &content).unwrap();
    sh.write_file("root/b.txt", &content).unwrap();

    let archive_path = build_archive(&sh, "img.dwarfs", "--pack-metadata=shared_files,force");
    let (index, mut archive) = Archive::new(fs::File::open(archive_path).unwrap()).unwrap();
    let root = index.root();
    let a = root.get("a.txt").unwrap().inode().as_file().unwrap();
    let b = root.get("b.txt").unwrap().inode().as_file().unwrap();

    assert_eq!(a.as_chunks().len(), 1);
    assert_eq!(b.as_chunks().len(), 1);
    assert_eq!(
        a.as_chunks().next().unwrap().offset(),
        b.as_chunks().next().unwrap().offset(),
    );

    assert_eq!(a.read_to_vec(&mut archive).unwrap(), content);
    assert_eq!(b.read_to_vec(&mut archive).unwrap(), content);
}
