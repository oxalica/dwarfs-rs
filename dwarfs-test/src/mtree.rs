use std::io::{Result, Write};

use dwarfs::{ArchiveIndex, AsChunks, Dir, InodeKind};

pub fn dump(w: &mut dyn Write, index: &ArchiveIndex) -> Result<()> {
    writeln!(w, "#mtree")?;
    dump_dir(w, index.root(), &mut String::from("."))
}

/// mtree escapes '/' and non-printable chars as `\ooo`.
/// See: <https://man.archlinux.org/man/mtree.5.en>
fn escape_into(buf: &mut String, s: &str) {
    for &b in s.as_bytes() {
        // ASCII printables.
        if (33..=126).contains(&b) && !b"\\/#".contains(&b) {
            buf.push(b as char);
        } else {
            buf.push('\\');
            let digit = |x: u8| (b'0' + x) as char;
            buf.push(digit(b / 64));
            buf.push(digit(b / 8 % 8));
            buf.push(digit(b % 8));
        }
    }
}

fn dump_dir(w: &mut dyn Write, dir: Dir<'_>, path: &mut String) -> Result<()> {
    for only_dir in [false, true] {
        for ent in dir.entries() {
            let name = ent.name();
            let ino = ent.inode();
            let prev_len = path.len();
            path.push('/');
            escape_into(path, name);

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
