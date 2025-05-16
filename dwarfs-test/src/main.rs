use std::{
    fs::File,
    io::{BufReader, Write},
    process::{Command, Stdio},
};

use dwarfs::Archive;

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
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    match &cli {
        Cli::Mtree {
            input,
            output,
            check,
        } => {
            let file = BufReader::new(File::open(input).expect("failed to open input file"));
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
    }
}
