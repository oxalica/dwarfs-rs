# dwarfs

[![crates.io](https://img.shields.io/crates/v/dwarfs)](https://crates.io/crates/dwarfs)
[![docs.rs](https://img.shields.io/docsrs/dwarfs)][docs]

Libraries for reading and writing [DwarFS][dwarfs] archives (aka. DwarFS images),
in Rust.

#### License

Short version: We follows the [upstream][dwarfs] licenses, the package for constructing
DwarFS archives (dwarfs-enc) is GPL-3.0. Other code is "(MIT OR Apache-2.0)".

Long version:

All files under directory `dwarfs-enc` are licensed under GNU General Public
License, version 3. Check `./dwarfs-enc/README.md` and `./LICENSE-GPL-3.0` for
details.

Other files in this repository outside `dwarfs-enc`, including `dwarfs` and
`dwarfs-test` packages, are licensed under Apache
License 2.0 or MIT license at your option. Check `./dwarfs/README.md`,
`./LICENSE-APACHE` and `./LICENSE-MIT` for details.

[dwarfs]: https://github.com/mhx/dwarfs
