use dwarfs::{ArchiveIndex, AsChunks, File};

/// Traverse all files in file offset order, for efficient content access.
pub fn traverse_files(index: &ArchiveIndex) -> Vec<(String, File<'_>)> {
    let mut files = Vec::with_capacity(index.inodes().len() - index.directories().len());
    let mut queue = Vec::new();
    queue.push((String::new(), index.root()));

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

    files.into_iter().map(|(_, path, f)| (path, f)).collect()
}
