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
  `.bss` mapping, code-set labels, and ExHeader metadata
- CRO Imports
- CRS Imports (from CXI/CIA only)
- CRO multi-file analysis (i.e. linking imports and exports together)

Planned:

- Relocation validation and richer relocation reporting
- Support for multiple .rodata/.data sections in static.crs
- CIA Imports
  - Support for multiple containers
  - Support for encrypted containers
