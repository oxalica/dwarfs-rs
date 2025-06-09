# dwarfs

[![crates.io](https://img.shields.io/crates/v/dwarfs?label=dwarfs
)](https://crates.io/crates/dwarfs)
[![docs.rs](https://img.shields.io/docsrs/dwarfs?label=docs.rs%2Fdwarfs)](https://docs.rs/dwarfs)

Libraries for reading and writing [DwarFS][dwarfs] archives (aka. DwarFS images),
in pure Rust without `unsafe`.

#### License

TL;DR: We mostly follow [upstream][dwarfs]: the package for constructing
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
