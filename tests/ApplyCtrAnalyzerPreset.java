// SPDX-License-Identifier: MIT
//
// Headless script for applying conservative 3DS ARM analysis defaults to an
// imported code-set program. It avoids emitting payload data.
//
// @category CTR

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class ApplyCtrAnalyzerPreset extends GhidraScript {

    @Override
    public void run() throws Exception {
        Options analysis = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        setBoolean(analysis, "Decompiler Switch Analysis", false);
        setBoolean(analysis, "ARM Constant Reference Analyzer", true);
        setBoolean(analysis, "Reference", true);
        setBoolean(analysis, "Shared Return Calls", true);
        setBoolean(analysis, "Stack", true);
        setBoolean(analysis, "Subroutine References", true);

        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        info.setString("3DS Analyzer Preset", "safe-large-3ds-arm");
        info.setBoolean("3DS Analyzer Preset Disable Switch Analysis", true);
        println("Applied 3DS analyzer preset: safe-large-3ds-arm");
    }

    private void setBoolean(Options options, String name, boolean value) {
        options.setBoolean(name, value);
    }
}
