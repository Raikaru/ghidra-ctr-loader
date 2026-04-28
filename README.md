# Ghidra CTR Loader

This is a Ghidra loader for Nintendo 3DS executables.

This fork is based on the original
[`Martmists-GH/ghidra-ctr-loader`](https://github.com/Martmists-GH/ghidra-ctr-loader)
by Martmists. Original copyright and BSD-style license terms are preserved in
`LICENSE.txt`; later maintenance and 3DS decomp workflow hardening in this fork
are by Raikaru.

## Features

Currently supports:

- CXI Imports
- CIA Imports (decrypted only)
  - Currently only imports the first container
- CXI/CIA ExeFS `.code` imports with NCCH ExHeader code-set mapping,
  `.bss` mapping, code-set labels, ExHeader metadata, dependency names, and
  SVC comments
- CRO Imports
- CRS Imports (from CXI/CIA only)
- CRO multi-file analysis (i.e. linking imports and exports together)

Planned:

- Deeper relocation validation and SDK/library signature coverage
- Support for multiple .rodata/.data sections in static.crs
- CIA Imports
  - Support for multiple containers
  - Support for encrypted containers

## Known Limits

- Encrypted 3DS containers are not supported.
- CIA imports currently expose the first NCCH content.
- CRO/CRS import/export linking is available, but module-specific validation
  should be done per title before relying on linked externals for naming.
- Private game files, extracted ExeFS/RomFS contents, and local Ghidra projects
  must stay under ignored `.local-test/` paths.
