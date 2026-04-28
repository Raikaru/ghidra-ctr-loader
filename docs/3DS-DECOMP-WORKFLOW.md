# 3DS Decomp Workflow

This repo is the 3DS loader half of a Ghidra decomp/reversing stack. Use it
for decrypted local 3DS executables/modules only.

## Local Flow

1. Build the extension against the local Ghidra container:

   ```powershell
   .\tests\build-extension.ps1
   ```

2. Install the built extension into a Ghidra test environment.
3. Import a decrypted CXI, CIA, CRO, or CRS.
4. Run a payload-free structure export:

   ```powershell
   .\tests\export-structure.ps1 -InputPath "C:\path\to\local\decrypted.cxi"
   ```

5. Compare memory blocks, functions, symbols, and external libraries against
   previous local runs.

## What To Check

- CXI/CIA/CRO/CRS import succeeds on current Ghidra.
- ARM language selection is sane.
- `.text`, `.rodata`, `.data`, and `.bss`-like regions are represented.
- CRO/CRS imports expose useful external libraries and export labels.
- Relocation handling is either correct or clearly reported as missing.
- Outputs under `.local-test/` contain only structure, not game payload.

## Payload Rules

Do not commit decrypted games, NCCH/CXI/CIA/CRO/CRS files, ExeFS/RomFS
contents, decoded text, copied disassembly, graphics, screenshots, audio,
scripts, maps, save data, or raw byte/file ranges.
