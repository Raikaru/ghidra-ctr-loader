// SPDX-License-Identifier: MIT
//
// Headless pre-script that creates payload-safe labels/functions for known
// NCCH code-set anchors.

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Paths;

public class SeedCtrCodeSetSymbols extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: SeedCtrCodeSetSymbols.java <manifest.structure.json>");
        }

        JsonObject manifest = JsonParser.parseString(Files.readString(Paths.get(args[0]))).getAsJsonObject();
        JsonObject codeSet = manifest.getAsJsonObject("code_set");
        JsonObject text = codeSet.getAsJsonObject("text");
        JsonObject rodata = codeSet.getAsJsonObject("rodata");
        JsonObject data = codeSet.getAsJsonObject("data");
        JsonObject bss = codeSet.getAsJsonObject("bss");

        Address textStart = addr(text.get("address_value").getAsLong());
        label(textStart, "ctr_entry");
        label(textStart, "ctr_text_start");
        ensureFunction(textStart, "ctr_entry");

        label(addr(rodata.get("address_value").getAsLong()), "ctr_rodata_start");
        label(addr(data.get("address_value").getAsLong()), "ctr_data_start");
        label(addr(bss.get("address_value").getAsLong()), "ctr_bss_start");
    }

    private void label(Address address, String name) throws Exception {
        if (currentProgram.getSymbolTable().getSymbol(name, address, null) != null) {
            return;
        }
        currentProgram.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
    }

    private void ensureFunction(Address address, String name) throws Exception {
        if (currentProgram.getFunctionManager().getFunctionAt(address) != null) {
            return;
        }
        currentProgram.getListing().createFunction(name, address, new AddressSet(address), SourceType.ANALYSIS);
    }

    private Address addr(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
}
