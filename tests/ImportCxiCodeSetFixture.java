// SPDX-License-Identifier: MIT
//
// Headless smoke helper for synthetic CXI fixtures. It mounts a local CXI,
// imports /exefs/code.bin through the code-set loader, and prints the loader
// log without emitting any payload bytes.
//
// @category CTR

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.program.model.listing.Program;

public class ImportCxiCodeSetFixture extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("Usage: ImportCxiCodeSetFixture.java <synthetic.cxi>");
		}

		FileSystemService fsService = FileSystemService.getInstance();
		try (FileSystemRef fsRef =
			fsService.probeFileForFilesystem(fsService.getLocalFSRL(new File(args[0])), monitor, null)) {
			if (fsRef == null) {
				throw new IllegalStateException("Input did not mount as a filesystem: " + args[0]);
			}

			GFile code = fsRef.getFilesystem().lookup("/exefs/code.bin");
			if (code == null) {
				throw new IllegalStateException("Missing /exefs/code.bin");
			}

			MessageLog log = new MessageLog();
			try (ByteProvider bp = fsRef.getFilesystem().getByteProvider(code, monitor);
					LoadResults<Program> loadResults = ProgramLoader.builder()
						.source(bp)
						.project(state.getProject())
						.projectFolderPath("/")
						.log(log)
						.monitor(monitor)
						.load()) {
				loadResults.getPrimary().save(monitor);
			}

			println(log.toString());
		}
	}
}
