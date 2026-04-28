# SMT 3DS Validation Seeds

Use SMT IV, SMT IV Apocalypse, or Strange Journey Redux only as private local
validation targets. They are not committed fixtures.

Record payload-free observations only:

- container/module kind;
- import success/failure;
- language/compiler IDs;
- memory block names, permissions, and counts;
- function/symbol/external-library counts;
- CRO/CRS import/export/linking behavior;
- analyzer exception kinds from local headless logs;
- generic loader improvement needed.

Do not record ROM files, decrypted content, decoded text, copied disassembly,
screenshots, graphics, audio, scripts, maps, save data, or raw byte ranges.

First generic improvement targets:

- Ghidra 12 build compatibility;
- `.bss` region representation;
- relocation validation;
- multiple data/rodata section handling;
- payload-safe CXI/CIA/CRO/CRS structure exports;
- SDK/library signature workflow notes.
