# SMT 3DS Start Here

This page is for local, user-owned SMT 3DS analysis with this loader. Keep ROMs,
extracted ExeFS/RomFS files, module binaries, screenshots, disassembly, and
decoded game assets out of git.

## One-Command Project Setup

Run the all-in-one helper for each decrypted title. It creates ignored local
artifacts under `.local-test/decomp-projects/`: an ExeFS manifest, RomFS file
listing, CRO/CRS discovery manifest, persistent mapped Ghidra code-set project,
and payload-safe project summary.

```powershell
.\tests\create-3ds-decomp-project.ps1 `
  -InputPath "C:\path\to\Shin Megami Tensei - Strange Journey Redux (USA) Decrypted.3ds" `
  -ProjectName "strange-journey-redux"

.\tests\create-3ds-decomp-project.ps1 `
  -InputPath "C:\path\to\Shin Megami Tensei IV (USA) Decrypted.3ds" `
  -ProjectName "smt-iv"

.\tests\create-3ds-decomp-project.ps1 `
  -InputPath "C:\path\to\Shin Megami Tensei IV - Apocalypse (USA).cci" `
  -ProjectName "smt-iv-apocalypse"
```

Open the resulting Ghidra projects from:

```text
.local-test\decomp-projects\<project>\ghidra\projects\<project>
```

Generate a payload-safe quality report and handoff note before giving the
project to another agent:

```powershell
.\tests\new-3ds-project-quality-report.ps1 `
  -ProjectManifest ".local-test\decomp-projects\smt-iv\project.structure.json"

.\tests\new-3ds-decomp-handoff.ps1 `
  -ProjectManifest ".local-test\decomp-projects\smt-iv\project.structure.json" `
  -TargetName "SMT IV"
```

## Current Local Module Result

The current payload-safe manifests for Strange Journey Redux, SMT IV, and SMT IV
Apocalypse found zero `.cro` or `.crs` files by ExeFS/RomFS filename. Treat
these as main-code-first decomp targets unless later evidence shows dynamically
loaded modules hidden behind a different extension or container format.

When a title does contain CRO/CRS modules, use:

```powershell
.\tests\validate-ctr-modules.ps1 `
  -InputPath "C:\path\to\local\decrypted.cxi" `
  -ModuleManifest ".local-test\decomp-projects\<project>\modules\<project>.modules.structure.json" `
  -ExtractedExeFsDir ".local-test\decomp-projects\<project>\exefs"
```

## What To Inspect First

- Program Info: code-set layout, dependency module IDs, service access control,
  named dependency count, and SVC comment count.
- Symbols: `ctr_entry`, `ctr_text_start`, `ctr_rodata_start`,
  `ctr_data_start`, and `ctr_bss_start`.
- External libraries: known 3DS system-module dependencies such as `3ds_fs`,
  `3ds_gsp`, `3ds_hid`, `3ds_ro`, and service ACL libraries such as
  `3ds_srv_fs_USER` or related names when present.
- Headless logs: summarize warning patterns with
  `tests/summarize-headless-log.ps1`.
- RomFS manifest extension counts: use them to prioritize asset/container
  format research without copying payload data into notes.

## Payload Rules

Commit only scripts, source, docs, and payload-free structure summaries. Do not
commit decrypted containers, extracted binaries, RomFS content, decoded text,
copied disassembly, screenshots, audio, maps, save data, or raw byte ranges.
