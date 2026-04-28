# Release Notes

## v1.2.0

- Adds lightweight 3DS SDK metadata: dependency module names become external
  libraries and known ARM SVC calls get repeatable comments.
- Adds a generated synthetic CIA fixture to validate the CIA filesystem offset
  path through `/exefs/code.bin`.
- Adds `tests/create-container-code-set-project.ps1` for creating a persistent
  project directly from a decrypted CXI/CIA container.
- Records CRO relocation patch counts and warnings in Program Info/import logs.
- Keeps local build staging payload-safe while still including safe untracked
  source files during development.

## v1.1.0

- Adds CXI/CIA ExeFS `.code` imports with NCCH ExHeader code-set mapping.
- Maps `.text`, `.rodata`, `.data`, and `.bss` using ExHeader code-set layout.
- Seeds code-set anchors and exports stack, dependency, and section metadata.
- Adds known 3DS dependency names and SVC comments where they can be identified
  without using private payload data.
- Adds payload-safe generated CRO, CRS, CXI, and CIA smoke fixtures.
- Adds local scripts for payload-safe structure exports and persistent Ghidra
  project creation.
- Hardens release packaging so ignored local validation data is never included
  in extension zips.

Original project credit remains with
[`Martmists-GH/ghidra-ctr-loader`](https://github.com/Martmists-GH/ghidra-ctr-loader).
