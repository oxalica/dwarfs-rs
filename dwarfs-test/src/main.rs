use std::{fs::File, io::Write, time::Instant};

use dwarfs::{
    Archive,
    archive::Config,
    metadata::Schema,
    section::{SectionReader, SectionType},
};
use xshell::{Shell, cmd};

mod check_content;
mod mtree;

#[derive(Debug, clap::Parser)]
enum Cli {
    /// Deserialize, serialize, re-deserialize the schema to verify it's the same result.
    SchemaRoundtrip {
        /// The input DwarFS archive path.
        input: String,
    },
    /// Dump the hierarchy and metadata of a DwarFS archive in "mtree" text format.
    Mtree {
        /// The output file to write. If omitted, stdout is implied.
        #[arg(long, short)]
        output: Option<String>,
        /// The input DwarFS archive path.
        input: String,
        /// Only check equality of the "mtree" output against `dwarfsextract`
        /// output, without printing or writing it.
        #[arg(long, conflicts_with = "output")]
        check: bool,
    },
    /// Read file contents of a DwarFS archive, and optionally compare them
    /// against `dwarfsextract`.
    Read {
        /// The input DwarFS archive path.
        input: String,
        /// Check equality of contents between the results of `dwarfextract`.
        /// If unset, contents are only read and dropped, useful for benchmarks.
        #[arg(long)]
        check: bool,
        /// The time limit in seconds for reading.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// The block cache size in MiB.
        #[arg(long, default_value_t = 256)]
        block_cache: usize,
    },
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    env_logger::init();
    let sh = Shell::new().unwrap();

    match &cli {
        Cli::SchemaRoundtrip { input, .. } => {
            let file = File::open(input).expect("failed to open input file");
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
        }
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
                    let expect = cmd!(sh, "dwarfsextract -i {input} -f mtree")
                        .read()
                        .expect("failed to run 'dwarfsextract'");

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
        Cli::Read {
            input,
            check,
            timeout,
            block_cache,
        } => {
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
                cmd!(sh, "dwarfsextract -i {input} -o {tmp_path}")
                    .run()
                    .expect("failed to run 'dwarfsextract'");
                eprintln!("extracted in {:?}", inst.elapsed());
            }
            let check_path = tmp_dir.as_ref().map(|p| {
                p.path()
                    .to_str()
                    .expect("temp path is not UTF-8")
                    .to_owned()
            });

            eprintln!("reading contents");
            let file = File::open(input).expect("failed to open input file");
            let mut config = Config::default();
            config.block_cache_size_limit(*block_cache << 20);
            let (index, mut archive) =
                Archive::new_with_config(file, &config).expect("failed to load archive");
            let inst = Instant::now();
            let check_content::CheckResult { files, oks } = check_content::traverse_dir(
                &mut archive,
                &index,
                inst,
                check_path.as_deref(),
                *timeout,
            );
            let elapsed = inst.elapsed();
            eprintln!("completed in {elapsed:?}");

            println!("{oks}/{files} OK");
            if files != oks {
                std::process::exit(1)
            }
        }
    }
}
