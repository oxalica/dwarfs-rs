use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use dwarfs_enc::{
    chunker::{self, Chunker},
    metadata::{Builder as MetadataBuilder, InodeMetadata},
    section::{self, CompressParam},
};
use indicatif::{HumanBytes, HumanCount, MultiProgress, ProgressBar, ProgressStyle};

#[derive(Debug, clap::Parser)]
struct Cli {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long)]
    output: PathBuf,

    #[arg(short, long)]
    force: bool,

    #[arg(long, short = 'l', default_value_t = 22)]
    compress_level: i32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = clap::Parser::parse();

    let inst = Instant::now();

    let fout = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .create_new(!cli.force)
        .open(&cli.output)?;

    let root_meta = fs::metadata(&cli.input)?;
    let root_meta = InodeMetadata::try_from(&root_meta)?;

    let stat = {
        let progress = ProgressBar::new_spinner();
        let mut stat = Stats::default();
        traverse_stats(&cli.input, &mut stat, &progress)?;
        progress.finish();
        stat
    };

    let compress = if cli.compress_level == 0 {
        CompressParam::None
    } else {
        CompressParam::Zstd(cli.compress_level)
    };
    eprintln!("using compression level: {compress:?}");

    let pb_in_bytes = ProgressBar::new(stat.total_bytes).with_style(
        ProgressStyle::with_template(
            "input : {binary_bytes}/{binary_total_bytes} ({binary_bytes_per_sec}) {wide_bar}",
        )
        .unwrap(),
    );
    let pb_out_bytes = ProgressBar::no_length()
        .with_style(ProgressStyle::with_template("output: {binary_bytes} {spinner}").unwrap());
    let fout_pb = pb_out_bytes.wrap_write(&fout);

    let pbs = MultiProgress::new();
    pbs.add(pb_in_bytes.clone());
    pbs.add(pb_out_bytes.clone());

    // Make bars visible now, or there would be a delay on the second bar,
    // because block compression takes quite some time to finish.
    pb_in_bytes.tick();
    pb_out_bytes.tick();

    let mut builder = MetadataBuilder::new(&root_meta);
    let writer = section::Writer::new(fout_pb).unwrap();
    let chunker = chunker::ConcatChunker::new(writer, 16 << 20, compress);
    let mut chunker = chunker::CdcChunker::new(chunker);

    build_archive(&mut builder, &mut chunker, &cli.input, &pb_in_bytes).unwrap();

    pb_in_bytes.finish();
    pbs.println(format!(
        "deduplicated {}",
        HumanBytes(chunker.deduplicated_bytes()),
    ))?;

    pbs.println("finalizing metadata")?;
    let mut w = chunker.into_inner().finish().unwrap();
    w.write_metadata_sections(&builder.finish().unwrap(), compress)
        .unwrap();

    pbs.println("waiting for compression to finish")?;
    w.finish().unwrap();
    pb_out_bytes.finish();

    let output_len = fout.metadata()?.len();

    let elapsed = inst.elapsed();
    eprintln!(
        "completed in {:?}, with compression ratio {:.2}%",
        elapsed,
        output_len as f32 / stat.total_bytes as f32 * 100.0,
    );

    Ok(())
}

#[derive(Debug, Default)]
struct Stats {
    files: u64,
    total_bytes: u64,
}

fn traverse_stats(
    root_path: &Path,
    stat: &mut Stats,
    progress: &ProgressBar,
) -> std::io::Result<()> {
    for ent in fs::read_dir(root_path)? {
        let ent = ent?;
        let ft = ent.file_type()?;
        if ft.is_dir() {
            traverse_stats(&ent.path(), stat, progress)?;
        } else if ft.is_file() {
            stat.files += 1;
            stat.total_bytes += fs::symlink_metadata(ent.path())?.len();

            if stat.files % 1024 == 0 {
                progress.set_message(format!(
                    "found {} files, total {}",
                    HumanCount(stat.files),
                    HumanBytes(stat.total_bytes),
                ));
            }
        }
    }
    Ok(())
}

fn build_archive(
    meta_builder: &mut MetadataBuilder,
    chunker: &mut dyn Chunker,
    root_path: &Path,
    pb_in_bytes: &ProgressBar,
) -> dwarfs_enc::Result<()> {
    let mut stack = Vec::new();
    stack.push((
        meta_builder.root(),
        root_path.to_owned(),
        fs::read_dir(root_path)?,
    ));

    while let Some(&mut (dir, ref dir_path, ref mut iter)) = stack.last_mut() {
        let Some(ent) = iter.next().transpose()? else {
            stack.pop();
            continue;
        };

        let name = ent.file_name();
        let name_str = name.to_string_lossy();
        if matches!(name_str, Cow::Owned(_)) {
            eprintln!("normalized non-UTF-8 name: {name:?} -> {name_str:?}");
        }
        let subpath = dir_path.join(&name);

        let ft = ent.file_type()?;
        let os_meta = ent.metadata()?;
        let inode_meta = InodeMetadata::try_from(&os_meta)?;

        if ft.is_dir() {
            let subdir = meta_builder.put_entry_dir(dir, &name_str, &inode_meta)?;
            let subiter = fs::read_dir(&subpath)?;
            stack.push((subdir, subpath, subiter));
        } else if ft.is_file() {
            let os_file = fs::File::open(&subpath)?;
            let chunks = chunker.put_reader(&mut pb_in_bytes.wrap_read(os_file))?;
            let f = meta_builder.put_file(&inode_meta, chunks)?;
            meta_builder.put_entry_inode(dir, &name_str, f)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&subpath)?;
            let target_str = target.to_string_lossy();
            if matches!(target_str, Cow::Owned(_)) {
                eprintln!("normalized non-UTF-8 symlink target: {target:?} -> {target_str:?}");
            }
            let symlink = meta_builder.put_symlink(&inode_meta, &target_str)?;
            meta_builder.put_entry_inode(dir, &name_str, symlink)?;
        } else {
            eprintln!(
                "ignore unsupported file type {:?} for path: {}",
                ft,
                subpath.display(),
            );
        }
    }
    Ok(())
}
