# 3DS Decomp Workflow

This repo is the 3DS loader half of a Ghidra decomp/reversing stack. Use it
for decrypted local 3DS executables/modules only.

## Local Flow

1. Build the extension against the local Ghidra container:

   ```powershell
   .\tests\build-extension.ps1
   ```

2. Run the generated-fixture smoke tests:

   ```powershell
   .\tests\test-generated-fixtures.ps1
   ```

3. Install the built extension into a Ghidra test environment.
4. Import a decrypted CXI, CIA, CRO, or CRS.
5. For games with CRO/CRS modules, import the static CRS first, then import
   related CRO modules and run the CRO linking script against the open project
   programs.
6. For NCCH/CXI/CIA images that Ghidra exposes as a filesystem rather than a
   direct program, import `/exefs/code.bin` directly in the Ghidra UI when you
   want the mapped ARM program. The loader exposes `code.bin` as a friendly
   alias for ExeFS `.code`, reads the parent NCCH ExHeader, maps `.text`,
   `.rodata`, `.data`, and `.bss`, seeds code-set anchors, and writes ExHeader
   metadata to Program Info. Whole-container recursive imports are useful for
   smoke testing but will also walk RomFS assets and can produce harmless
   "no load spec" noise that is not relevant to decomp work.

   If you need payload-free local manifests or want to validate extracted
   private files outside the UI, extract private ExeFS members locally:

   ```powershell
   .\tests\extract-cxi-exefs.ps1 -InputPath "C:\path\to\local\decrypted.cxi"
   ```

   The extractor decompresses `.code` when the NCCH ExHeader marks it
   compressed and writes a payload-free code-set manifest with stack size,
   dependency module IDs, and `.text`/`.rodata`/`.data`/`.bss` layout. Prefer
   the code-set-aware export for `.code` validation:

   ```powershell
   .\tests\export-code-set-structure.ps1 `
     -CodePath ".local-test\exefs\game\.code" `
     -ManifestPath ".local-test\exefs\game\manifest.structure.json" `
     -InitializeBss `
     -DisableSwitchAnalysis
   ```

   `-InitializeBss` maps BSS as zero-filled initialized bytes for analysis
   ergonomics. `-DisableSwitchAnalysis` turns off Ghidra's decompiler switch
   analyzer, which can produce large warning logs from speculative jump-table
   reads on these 3DS binaries.

   The code-set workflow also seeds confirmed anchors before analysis:
   `ctr_entry`, `ctr_text_start`, `ctr_rodata_start`, `ctr_data_start`, and
   `ctr_bss_start`.

   For a quick raw baseline, import `.code` as ARM:

   ```powershell
   .\tests\export-structure.ps1 `
     -InputPath ".local-test\exefs\game\.code" `
     -Processor "ARM:LE:32:v7" `
     -Compiler default
   ```

7. Create a persistent mapped Ghidra project when you are ready to inspect or
   decompile locally:

   ```powershell
   .\tests\create-code-set-project.ps1 `
     -CodePath ".local-test\exefs\game\.code" `
     -ManifestPath ".local-test\exefs\game\manifest.structure.json" `
     -ProjectName "game-code-set" `
     -InitializeBss `
     -DisableSwitchAnalysis
   ```

8. Summarize analysis warnings from any headless run:

   ```powershell
   .\tests\summarize-headless-log.ps1 `
     -LogPath ".local-test\structure-export\game.headless.log"
   ```

9. List RomFS metadata without extracting file payload:

   ```powershell
   .\tests\list-cxi-romfs.ps1 -InputPath "C:\path\to\local\decrypted.cxi"
   ```

10. Check ExeFS/RomFS manifests for CRO/CRS modules:

   ```powershell
   .\tests\find-ctr-modules.ps1 `
     -ExeFsManifest ".local-test\exefs\game\manifest.structure.json" `
     -RomFsManifest ".local-test\romfs-list\game.romfs.structure.json"
   ```

11. Run a payload-free structure export:

   ```powershell
   .\tests\export-structure.ps1 -InputPath "C:\path\to\local\decrypted.cxi"
   ```

   If a decrypted NCCH/CXI image is named with a generic extension such as
   `.3ds`, preserve the original file and override only the temporary import
   name:

   ```powershell
   .\tests\export-structure.ps1 `
     -InputPath "C:\path\to\local\decrypted.3ds" `
     -ImportExtension .cxi
   ```

12. Compare memory blocks, functions, symbols, and external libraries against
   previous local runs:

   ```powershell
   .\tests\compare-structure.ps1 `
     -Baseline ".local-test\structure-export\old.structure.json" `
     -Current ".local-test\structure-export\new.structure.json"
   ```

## What To Check

- CXI/CIA/CRO/CRS import succeeds on current Ghidra.
- ARM language selection is sane.
- `.text`, `.rodata`, `.data`, and `.bss`-like regions are represented.
- CRO/CRS imports expose useful external libraries and export labels.
- Relocation handling is either correct or clearly reported as missing.
- Outputs under `.local-test/` contain only structure, not game payload.
- Standalone `.crs` imports do not crash, even when richer CXI/CIA context is
  unavailable.
- Generated `.cro` and `.crs` fixtures import through headless Ghidra before
  trying private game files.

## Payload Rules

Do not commit decrypted games, NCCH/CXI/CIA/CRO/CRS files, ExeFS/RomFS
contents, decoded text, copied disassembly, graphics, screenshots, audio,
scripts, maps, save data, or raw byte/file ranges.
