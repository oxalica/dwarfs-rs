use std::time::Instant;

use dwarfs::{Archive, ArchiveIndex, AsChunks, positioned_io::ReadAt};

#[derive(Debug)]
pub struct CheckResult {
    pub files: u64,
    pub oks: u64,
}

pub fn traverse_dir(
    archive: &mut Archive<dyn ReadAt>,
    index: &ArchiveIndex,
    inst: Instant,
    check_path: Option<&str>,
    time_limit_sec: u64,
) -> CheckResult {
    let do_check = check_path.is_some();

    let mut files = Vec::with_capacity(index.inodes().len() - index.directories().len());
    let mut queue = Vec::new();
    let init_path = check_path.map_or(String::new(), |s| s.to_owned());
    queue.push((init_path, index.root()));

    while let Some((mut path, dir)) = queue.pop() {
        path.push('/');
        let prev_len = path.len();

        for ent in dir.entries() {
            let name = ent.name();
            let ino = ent.inode();
            path.push_str(name);

            if let Some(d) = ino.as_dir() {
                queue.push((path.clone(), d));
            } else if let Some(f) = ino.as_file() {
                let start_sec_idx = f.as_chunks().next().map_or(0, |c| c.section_idx());
                files.push((start_sec_idx, path.clone(), f));
            }

            path.truncate(prev_len);
        }
    }

    files.sort_by_key(|(sec_idx, ..)| *sec_idx);

    let mut ret = CheckResult { files: 0, oks: 0 };
    for (_, path, f) in &files {
        let data = f.read_to_vec(archive).expect("failed to read DwarFS file");
        ret.files += 1;
        if do_check {
            let expect = std::fs::read(path).expect("failed to read extracted file");
            if data == expect {
                ret.oks += 1;
            } else {
                println!("file differs: {path}");
            }
        } else {
            std::hint::black_box(&data[..]);
            ret.oks += 1;
        }

        if inst.elapsed().as_secs() >= time_limit_sec {
            panic!(
                "check timeout after {}s, with {}/{} ({:.1}%) files processed",
                time_limit_sec,
                ret.files,
                files.len(),
                ret.files as f32 / files.len() as f32 * 100.0
            );
        }
    }
    ret
}
