// SPDX-License-Identifier: MIT
//
// Headless pre-script that creates payload-safe labels/functions for known
// NCCH code-set anchors.

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class SeedCtrCodeSetSymbols extends GhidraScript {

    private static final Map<Long, String> DEPENDENCIES = new HashMap<>();
    private static final Map<Integer, String> SVCS = new HashMap<>();

    static {
        DEPENDENCIES.put(0x0004013000001502L, "fs");
        DEPENDENCIES.put(0x0004013000001602L, "loader");
        DEPENDENCIES.put(0x0004013000001702L, "pm");
        DEPENDENCIES.put(0x0004013000001802L, "sm");
        DEPENDENCIES.put(0x0004013000001a02L, "hid");
        DEPENDENCIES.put(0x0004013000002402L, "gsp");
        DEPENDENCIES.put(0x0004013000002702L, "am");
        DEPENDENCIES.put(0x0004013000002d02L, "ro");
        DEPENDENCIES.put(0x0004013000002f02L, "http");
        DEPENDENCIES.put(0x0004013000003202L, "socket");
        DEPENDENCIES.put(0x0004013000003302L, "ac");
        DEPENDENCIES.put(0x0004013000003402L, "cec");
        DEPENDENCIES.put(0x0004013000003802L, "cup");

        SVCS.put(0x01, "ControlMemory");
        SVCS.put(0x02, "QueryMemory");
        SVCS.put(0x03, "ExitProcess");
        SVCS.put(0x08, "CreateThread");
        SVCS.put(0x09, "ExitThread");
        SVCS.put(0x0a, "SleepThread");
        SVCS.put(0x13, "CreateMutex");
        SVCS.put(0x14, "ReleaseMutex");
        SVCS.put(0x17, "CreateEvent");
        SVCS.put(0x18, "SignalEvent");
        SVCS.put(0x23, "CloseHandle");
        SVCS.put(0x24, "WaitSynchronization1");
        SVCS.put(0x25, "WaitSynchronizationN");
        SVCS.put(0x28, "GetSystemTick");
        SVCS.put(0x2d, "ConnectToPort");
        SVCS.put(0x32, "SendSyncRequest");
        SVCS.put(0x3c, "Break");
        SVCS.put(0x3d, "OutputDebugString");
        SVCS.put(0x7b, "Backdoor");
    }

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

        int namedDependencies = seedDependencyLibraries(manifest);
        int serviceAccess = seedServiceAccessLibraries(manifest);
        int svcComments = annotateSvcCalls();
        println("Seeded 3DS SDK metadata: " + namedDependencies + " dependency names, " + serviceAccess + " service ACL entries, " + svcComments + " SVC comments");
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

    private int seedDependencyLibraries(JsonObject manifest) throws Exception {
        if (!manifest.has("dependencies") || !manifest.get("dependencies").isJsonArray()) {
            return 0;
        }

        int count = 0;
        for (JsonElement element : manifest.getAsJsonArray("dependencies")) {
            JsonObject dependency = element.getAsJsonObject();
            String text = dependency.get("module_id").getAsString();
            long moduleId = Long.parseUnsignedLong(text.replace("0x", ""), 16);
            String name = DEPENDENCIES.get(moduleId);
            if (name == null) {
                continue;
            }
            currentProgram.getExternalManager().addExternalLibraryName("3ds_" + name, SourceType.ANALYSIS);
            count++;
        }
        return count;
    }

    private int seedServiceAccessLibraries(JsonObject manifest) throws Exception {
        if (!manifest.has("service_access") || !manifest.get("service_access").isJsonArray()) {
            return 0;
        }

        StringBuilder names = new StringBuilder();
        int count = 0;
        for (JsonElement element : manifest.getAsJsonArray("service_access")) {
            JsonObject service = element.getAsJsonObject();
            String name = service.get("name").getAsString();
            if (name == null || name.isBlank()) {
                continue;
            }
            if (names.length() > 0) {
                names.append(",");
            }
            names.append(name);
            currentProgram.getExternalManager().addExternalLibraryName("3ds_srv_" + safeServiceName(name), SourceType.ANALYSIS);
            count++;
        }

        currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
            .setLong("3DS Service Access Count", count);
        currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
            .setLong("3DS Named Service Access Count", count);
        currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
            .setString("3DS Service Access", names.toString());
        return count;
    }

    private String safeServiceName(String name) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                out.append(c);
            } else {
                out.append('_');
            }
        }
        return out.toString();
    }

    private int annotateSvcCalls() throws Exception {
        MemoryBlock text = currentProgram.getMemory().getBlock(".text");
        if (text == null) {
            return 0;
        }

        int count = 0;
        for (Address address = text.getStart(); address.compareTo(text.getEnd().subtract(3)) <= 0; address = address.add(4)) {
            int word = currentProgram.getMemory().getInt(address);
            if ((word & 0xff000000) != 0xef000000) {
                continue;
            }
            int svc = word & 0x00ffffff;
            String name = SVCS.get(svc);
            if (name == null) {
                continue;
            }
            currentProgram.getListing().setComment(address, CodeUnit.REPEATABLE_COMMENT, "3DS SVC 0x" + Integer.toHexString(svc) + ": " + name);
            count++;
        }
        return count;
    }
}
