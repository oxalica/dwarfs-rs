use std::{
    io::{Read, Seek},
    time::Instant,
};

use dwarfs::{Archive, ArchiveIndex, AsChunks};

const TIMEOUT_SEC: u64 = 10;

#[derive(Debug)]
pub struct CheckResult {
    pub files: u64,
    pub oks: u64,
}

pub fn traverse_dir<R: Read + Seek>(
    archive: &mut Archive<R>,
    index: &ArchiveIndex,
    inst: Instant,
    check_path: Option<&str>,
) -> CheckResult {
    let do_check = check_path.is_some();
    let mut files = 0u64;
    let mut oks = 0u64;
    let mut queue = Vec::new();
    let init_path = check_path.map_or(String::new(), |s| s.to_owned());
    queue.push((init_path, index.root()));

    while let Some((mut path, dir)) = queue.pop() {
        path.push('/');
        let prev_len = path.len();

        for ent in dir.entries() {
            let name = str::from_utf8(ent.name()).unwrap();
            let ino = ent.inode();
            path.push_str(name);

            if let Some(d) = ino.as_dir() {
                queue.push((path.clone(), d));
            } else if let Some(f) = ino.as_file() {
                let data = f.read_to_vec(archive).expect("failed to read dwarfs file");
                files += 1;
                if do_check {
                    let expect = std::fs::read(&path).expect("failed to read extracted file");
                    if data == expect {
                        oks += 1;
                    } else {
                        println!("file differs: {path}");
                    }
                } else {
                    std::hint::black_box(&data[..]);
                }

                if inst.elapsed().as_secs() >= TIMEOUT_SEC {
                    panic!("check timeout after processed {files} files");
                }
            }

            path.truncate(prev_len);
        }
    }

    CheckResult { files, oks }
}
