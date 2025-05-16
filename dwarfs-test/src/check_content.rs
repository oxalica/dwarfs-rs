use std::{
    io::{Read, Seek},
    time::Instant,
};

use dwarfs::{Archive, AsChunks, Dir};

const TIMEOUT_SEC: u64 = 10;

#[derive(Debug)]
pub struct CheckState {
    pub files: u64,
    pub oks: u64,
    pub inst: Instant,
    pub path: String,
    pub do_check: bool,
}

pub fn traverse_dir<R: Read + Seek>(
    archive: &mut Archive<R>,
    dir: Dir<'_>,
    state: &mut CheckState,
) {
    for ent in dir.entries() {
        let name = str::from_utf8(ent.name()).unwrap();
        let ino = ent.inode();
        let prev_len = state.path.len();
        state.path.push('/');
        state.path.push_str(name);

        if let Some(d) = ino.as_dir() {
            traverse_dir(archive, d, state);
        } else if let Some(f) = ino.as_file() {
            let data = f.read_to_vec(archive).expect("failed to read dwarfs file");
            state.files += 1;
            if state.do_check {
                let expect = std::fs::read(&state.path).expect("failed to read extracted file");
                if data == expect {
                    state.oks += 1;
                } else {
                    println!("file differs: {}", state.path);
                }
            } else {
                std::hint::black_box(&data[..]);
            }

            if state.inst.elapsed().as_secs() >= TIMEOUT_SEC {
                panic!("check timeout after processed {} files", state.files);
            }
        }

        state.path.truncate(prev_len);
    }
}
