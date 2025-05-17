use std::{
    fs::File,
    io::Write,
    process::{Command, Stdio},
    time::Instant,
};

use dwarfs::Archive;

mod check_content;
mod mtree;

#[derive(Debug, clap::Parser)]
enum Cli {
    /// Dump the hierarchy and metadata of a dwarfs archive in "mtree" text format.
    Mtree {
        /// The output file to write. If omitted, stdout is implied.
        #[arg(long, short)]
        output: Option<String>,
        /// The input dwarfs archive path.
        input: String,
        /// Only check equality of the "mtree" output against `dwarfsextract`
        /// output, without printing or writing it.
        #[arg(long, conflicts_with = "output")]
        check: bool,
    },
    /// Read file contents of a dwarfs archive, and optionally compare them
    /// against `dwarfsextract`.
    Read {
        /// The input dwarfs archive path.
        input: String,
        /// Check equality of contents between the results of `dwarfextract`.
        /// If unset, contents are only read and dropped, useful for benchmarks.
        #[arg(long)]
        check: bool,
    },
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    env_logger::init();

    match &cli {
        Cli::Mtree {
            input,
            output,
            check,
        } => {
            let file = File::open(input).expect("failed to open input file");
            let (index, _) = Archive::new(file).expect("failed to load archive");
            let mut got = <Vec<u8>>::new();
            mtree::dump(&mut got, &index).expect("failed to dump mtree");
            let got = String::from_utf8(got).expect("output must be UTF8");
            match output {
                Some(path) => std::fs::write(path, &got).expect("failed to write file"),
                None if !*check => std::io::stdout()
                    .lock()
                    .write_all(got.as_bytes())
                    .expect("failed to write to stdout"),
                _ => {
                    let out = Command::new("dwarfsextract")
                        .args(["-i", input, "-f", "mtree"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .output()
                        .expect("failed to run dwarfsextract");
                    assert!(
                        out.status.success(),
                        "dwarfsextract exited with an error {}",
                        out.status
                    );
                    let expect = String::from_utf8(out.stdout)
                        .expect("dwarfsextract returns a non-UTF8 output");

                    if expect == got {
                        println!("OK");
                    } else {
                        println!("Output differs");
                        println!(
                            "{}",
                            colored_diff::PrettyDifference {
                                expected: &expect,
                                actual: &got,
                            }
                        );
                        std::process::exit(1)
                    }
                }
            }
        }
        Cli::Read { input, check } => {
            if cfg!(debug_assertions) {
                panic!("refuse to run. content dump is too slow without --release");
            }

            let mut tmp_dir = None;
            if *check {
                #[cfg(unix)]
                {
                    tmp_dir = Some({
                        use std::os::unix::fs::PermissionsExt;
                        tempfile::Builder::new()
                            .permissions(std::fs::Permissions::from_mode(0o700))
                            .tempdir()
                            .expect("failed to create tempdir")
                    });
                }
                #[cfg(not(unix))]
                {
                    tmp_dir = Some(tempfile::tempdir().expect("failed to create tempdir"));
                }
                let tmp_path = tmp_dir.as_ref().unwrap().path();

                eprintln!("extracting into temp dir: {}", tmp_path.display());

                let inst = Instant::now();
                let st = Command::new("dwarfsextract")
                    .args(["-i", input, "-o"])
                    .arg(tmp_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .status()
                    .expect("failed to run dwarfsextract");
                assert!(st.success(), "dwarfsextract exited with an error {st}");
                eprintln!("extracted in {:?}", inst.elapsed());
            }
            let path = tmp_dir.as_ref().map_or(String::new(), |p| {
                p.path()
                    .to_str()
                    .expect("temp path is not UTF-8")
                    .to_owned()
            });

            eprintln!("reading contents");
            let file = File::open(input).expect("failed to open input file");
            let (index, mut archive) = Archive::new(file).expect("failed to load archive");
            let mut state = check_content::CheckState {
                files: 0,
                oks: 0,
                inst: Instant::now(),
                path,
                do_check: tmp_dir.is_some(),
            };
            check_content::traverse_dir(&mut archive, index.root(), &mut state);
            let elapsed = state.inst.elapsed();
            eprintln!("completed in {elapsed:?}");

            println!("{}/{} OK", state.oks, state.files);
            if state.files != state.oks {
                std::process::exit(1)
            }
        }
    }
}
