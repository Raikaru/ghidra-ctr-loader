# Ghidra CTR Loader

This is a Ghidra loader for Nintendo 3DS executables.

## Features

Currently supports:

- CXI Imports
- CIA Imports (decrypted only)
  - Currently only imports the first container
- CXI/CIA ExeFS `.code` imports with NCCH ExHeader code-set mapping
- CRO Imports
- CRS Imports (from CXI/CIA only)
- CRO multi-file analysis (i.e. linking imports and exports together)

Planned:

- Support for .bss sections and relocations
- Support for multiple .rodata/.data sections in static.crs
- CIA Imports
  - Support for multiple containers
  - Support for encrypted containers
