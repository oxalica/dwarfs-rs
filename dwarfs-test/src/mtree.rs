use std::io::{Result, Write};

use dwarfs::{ArchiveIndex, AsChunks, Dir, InodeKind};

pub fn dump(w: &mut dyn Write, index: &ArchiveIndex) -> Result<()> {
    writeln!(w, "#mtree")?;
    dump_dir(w, index.root(), &mut String::from("."))
}

fn dump_dir(w: &mut dyn Write, dir: Dir<'_>, path: &mut String) -> Result<()> {
    for only_dir in [false, true] {
        for ent in dir.entries() {
            let name = ent.name();
            let ino = ent.inode();
            let prev_len = path.len();
            path.push('/');
            path.push_str(name);

            let meta = ino.metadata();
            let mtime = meta.mtime();
            let mode = meta.mode() & 0o777;
            let gid = meta.gid();
            let uid = meta.uid();
            if let Some(d) = ino.as_dir() {
                if only_dir {
                    writeln!(
                        w,
                        "{path} time={mtime}.0 mode={mode:03o} gid={gid} uid={uid} type=dir",
                    )?;
                    dump_dir(w, d, path)?;
                }
            } else if !only_dir {
                if let Some(f) = ino.as_file() {
                    let size = f.as_chunks().total_size();
                    writeln!(
                        w,
                        "{path} time={mtime}.0 mode={mode:03o} gid={gid} uid={uid} type=file size={size}",
                    )?;
                } else {
                    let kind = ino.classify();
                    if let InodeKind::Symlink(sym) = kind {
                        let tgt = sym.target();
                        writeln!(
                            w,
                            "{path} time={mtime}.0 mode={mode:03o} gid={gid} uid={uid} type=link link={tgt}",
                        )?;
                    } else {
                        unimplemented!("{kind:?}");
                    }
                }
            }

            path.truncate(prev_len);
        }
    }
    Ok(())
}
