// SPDX-License-Identifier: MIT
//
// Headless post-script that emits a payload-free JSON summary of a loaded 3DS
// executable/module. It records structure only: language, memory blocks,
// function/symbol counts, and external library names. It must not emit ROM
// bytes, decoded text, copied disassembly, screenshots, graphics, audio,
// scripts, maps, save data, or raw file ranges.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportCtrStructureJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("{");
        field(out, "program", currentProgram.getName()).append(",");
        field(out, "language", currentProgram.getLanguageID().getIdAsString()).append(",");
        field(out, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()).append(",");
        field(out, "image_base", hex(currentProgram.getImageBase())).append(",");
        appendBlocks(out).append(",");
        appendCounts(out);
        out.append("}");
        println("JSON: " + out);
    }

    private StringBuilder appendBlocks(StringBuilder out) {
        out.append("\"memory_blocks\":[");
        boolean first = true;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!first) out.append(",");
            out.append("{");
            field(out, "name", block.getName()).append(",");
            field(out, "start", hex(block.getStart())).append(",");
            field(out, "end", hex(block.getEnd())).append(",");
            field(out, "type", block.getType().toString()).append(",");
            out.append("\"size\":").append(block.getSize()).append(",");
            out.append("\"read\":").append(block.isRead()).append(",");
            out.append("\"write\":").append(block.isWrite()).append(",");
            out.append("\"execute\":").append(block.isExecute());
            out.append("}");
            first = false;
        }
        out.append("]");
        return out;
    }

    private StringBuilder appendCounts(StringBuilder out) {
        int functions = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            fit.next();
            functions++;
        }

        int symbols = 0;
        SymbolIterator sit = currentProgram.getSymbolTable().getAllSymbols(true);
        while (sit.hasNext()) {
            sit.next();
            symbols++;
        }

        int blocks = 0;
        int initializedBlocks = 0;
        int uninitializedBlocks = 0;
        int readableBlocks = 0;
        int writableBlocks = 0;
        int executableBlocks = 0;
        for (MemoryBlock ignored : currentProgram.getMemory().getBlocks()) {
            blocks++;
            if (ignored.isInitialized()) initializedBlocks++;
            else uninitializedBlocks++;
            if (ignored.isRead()) readableBlocks++;
            if (ignored.isWrite()) writableBlocks++;
            if (ignored.isExecute()) executableBlocks++;
        }

        String[] libraries = currentProgram.getExternalManager().getExternalLibraryNames();

        out.append("\"counts\":{");
        out.append("\"functions\":").append(functions).append(",");
        out.append("\"memory_blocks\":").append(blocks).append(",");
        out.append("\"initialized_blocks\":").append(initializedBlocks).append(",");
        out.append("\"uninitialized_blocks\":").append(uninitializedBlocks).append(",");
        out.append("\"readable_blocks\":").append(readableBlocks).append(",");
        out.append("\"writable_blocks\":").append(writableBlocks).append(",");
        out.append("\"executable_blocks\":").append(executableBlocks).append(",");
        out.append("\"symbols_total\":").append(symbols).append(",");
        out.append("\"external_libraries\":").append(libraries.length);
        out.append("},");
        out.append("\"external_libraries\":[");
        for (int i = 0; i < libraries.length; i++) {
            if (i > 0) out.append(",");
            out.append("\"").append(escape(libraries[i])).append("\"");
        }
        out.append("]");
        return out;
    }

    private static StringBuilder field(StringBuilder out, String name, String value) {
        out.append("\"").append(escape(name)).append("\":\"").append(escape(value)).append("\"");
        return out;
    }

    private static String hex(Address address) {
        if (address == null) return "";
        return String.format("%08x", address.getOffset() & 0xffffffffL);
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
