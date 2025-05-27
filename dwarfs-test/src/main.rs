use xshell::{Shell, cmd};

fn main() {
    env_logger::init();
    let args = std::env::args().collect::<Vec<String>>();
    let output = match &*args {
        [_, cmd, output] if cmd == "gen-privileged-archive" => output,
        _ => panic!("invalid argument"),
    };

    #[cfg(not(unix))]
    {
        let _ = output;
        panic!("only UNIX platform is supported");
    }

    // Used by `../tests/tests/rs`.
    #[cfg(unix)]
    {
        use rustix::fs as ufs;

        assert!(
            rustix::process::geteuid().is_root(),
            "gen-privileged-archive must be executed under root or 'fakeroot'",
        );

        let sh = Shell::new().unwrap();
        let temp_dir = tempfile::tempdir().expect("failed to create tempdir");
        let src_path = temp_dir.path().join("root");
        std::fs::create_dir(&src_path).unwrap();
        ufs::mknodat(
            ufs::ABS,
            src_path.join("bdev"),
            ufs::FileType::BlockDevice,
            ufs::Mode::from_bits_truncate(0o777),
            0x0123_4567_89AB_CDEF,
        )
        .unwrap();
        ufs::mknodat(
            ufs::ABS,
            src_path.join("cdev"),
            ufs::FileType::CharacterDevice,
            ufs::Mode::from_bits_truncate(0o777),
            0xFEDC_BA98_7654_3210,
        )
        .unwrap();

        cmd!(
            sh,
            "mkdwarfs -i {src_path} -o {output} --no-progress --log-level=error --with-devices"
        )
        .run()
        .expect("failed to run 'mkdwarfs'");
    }
}
