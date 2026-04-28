package com.martmists.ctr.loader.loader

import com.martmists.ctr.ext.reader
import com.martmists.ctr.ext.stripNulls
import com.martmists.ctr.loader.filesystem.CIAFileSystem
import com.martmists.ctr.loader.format.NCCHExHeader
import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.Option
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.AbstractLibrarySupportLoader
import ghidra.app.util.opinion.Loader
import ghidra.app.util.opinion.LoadSpec
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder


class CtrCodeSetLoader : AbstractLibrarySupportLoader() {
    companion object {
        private const val OPTION_INITIALIZE_BSS = "Initialize .bss"
        private const val OPTION_SEED_LABELS = "Seed code-set labels"
        private const val OPTION_DISABLE_SWITCH_ANALYSIS = "Disable Decompiler Switch Analysis"
        private const val OPTION_WRITE_EXHEADER_METADATA = "Write ExHeader metadata"
    }

    override fun getName() = "3DS Code Set Loader"

    override fun findSupportedLoadSpecs(provider: ByteProvider): MutableCollection<LoadSpec> {
        val loadSpecs = mutableListOf<LoadSpec>()
        if (isValid(provider)) {
            loadSpecs.add(LoadSpec(this, 0, LanguageCompilerSpecPair("ARM:LE:32:v7", "default"), true))
        }
        return loadSpecs
    }

    override fun getDefaultOptions(
        provider: ByteProvider,
        loadSpec: LoadSpec?,
        domainObject: DomainObject?,
        loadIntoProgram: Boolean,
        mirrorFsLayout: Boolean,
    ): MutableList<Option> {
        val options = super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout).toMutableList()
        options.add(Option(OPTION_INITIALIZE_BSS, false))
        options.add(Option(OPTION_SEED_LABELS, true))
        options.add(Option(OPTION_DISABLE_SWITCH_ANALYSIS, true))
        options.add(Option(OPTION_WRITE_EXHEADER_METADATA, true))
        return options
    }

    override fun load(program: Program, settings: Loader.ImporterSettings) {
        val provider = settings.provider()
        val monitor = settings.monitor()
        val log = settings.log()
        val options = CodeSetLoaderOptions.from(settings.options())

        getNcchProvider(provider, monitor).getInputStream(0).reader {
            seek(0x200)
            val ncchEx = read<NCCHExHeader>()
            configureAnalysis(program, options)
            createCodeSetBlocks(provider, program, ncchEx, options, monitor, log)
            if (options.seedLabels) {
                seedCodeSetSymbols(program, ncchEx, log)
            }
            if (options.writeExHeaderMetadata) {
                writeExHeaderMetadata(program, ncchEx, log)
            }
        }
    }

    private fun isValid(provider: ByteProvider): Boolean {
        if (provider.name !in setOf(".code", "code.bin") || provider.fsrl.fs.container == null) {
            return false
        }

        val containerPath = provider.fsrl.fs.container.path.lowercase()
        if (!containerPath.endsWith(".cxi") && !containerPath.endsWith(".cia")) {
            return false
        }

        return try {
            BinaryReader(provider, true).readByte(0)
            true
        } catch (e: IOException) {
            false
        }
    }

    private fun getNcchProvider(provider: ByteProvider, monitor: TaskMonitor): ByteProvider {
        val container = provider.fsrl.fs.container
            ?: throw IllegalStateException("3DS code set imports require a parent CXI/CIA filesystem")
        val rawProvider = FileSystemService.getInstance().getByteProvider(container, true, monitor)
        val containerPath = container.path.lowercase()
        return when {
            containerPath.endsWith(".cxi") -> rawProvider
            containerPath.endsWith(".cia") -> CIAFileSystem.CIAByteProvider(rawProvider)
            else -> throw IllegalStateException("Unsupported 3DS code set container: ${container.path}")
        }
    }

    private fun configureAnalysis(program: Program, options: CodeSetLoaderOptions) {
        if (!options.disableSwitchAnalysis) {
            return
        }
        val analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES)
        analysisOptions.setBoolean("Decompiler Switch Analysis", false)
    }

    private fun createCodeSetBlocks(
        provider: ByteProvider,
        program: Program,
        ncchEx: NCCHExHeader,
        options: CodeSetLoaderOptions,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        val text = CodeSetSection(".text", ncchEx.sci.textCodeSetInfo, true, false, true)
        val rodata = CodeSetSection(".rodata", ncchEx.sci.readOnlyCodeSetInfo, true, false, false)
        val data = CodeSetSection(".data", ncchEx.sci.dataCodeSetInfo, true, true, false)
        val sections = listOf(text, rodata, data)

        val logicalSize = sections.sumOf { it.size }
        val aligned = logicalSize < provider.length()
        var codeOffset = 0L

        for (section in sections) {
            if (section.size == 0L) {
                codeOffset += if (aligned) section.physicalSize else 0L
                continue
            }

            requireProviderRange(provider, codeOffset, section.size, section.name)
            val fileBytes = MemoryBlockUtils.createFileBytes(program, provider, codeOffset, section.size, monitor)
            MemoryBlockUtils.createInitializedBlock(
                program,
                false,
                section.name,
                address(program, section.address),
                fileBytes,
                0,
                section.size,
                "",
                null,
                section.read,
                section.write,
                section.execute,
                log,
            )
            log.appendMsg("Mapped ${section.name} at 0x${section.address.toString(16)} size 0x${section.size.toString(16)}")
            codeOffset += if (aligned) section.physicalSize else section.size
        }

        val bssSize = Integer.toUnsignedLong(ncchEx.sci.bssSize)
        if (bssSize > 0) {
            val bssStart = Integer.toUnsignedLong(ncchEx.sci.dataCodeSetInfo.address) + Integer.toUnsignedLong(ncchEx.sci.dataCodeSetInfo.size)
            if (options.initializeBss) {
                val block = program.memory.createInitializedBlock(".bss", address(program, bssStart), bssSize, 0.toByte(), monitor, false)
                block.isRead = true
                block.isWrite = true
                block.isExecute = false
            } else {
                MemoryBlockUtils.createUninitializedBlock(
                    program,
                    false,
                    ".bss",
                    address(program, bssStart),
                    bssSize,
                    "",
                    null,
                    true,
                    true,
                    false,
                    log,
                )
            }
            log.appendMsg("Mapped .bss at 0x${bssStart.toString(16)} size 0x${bssSize.toString(16)}")
        }
    }

    private fun seedCodeSetSymbols(program: Program, ncchEx: NCCHExHeader, log: MessageLog) {
        val textStart = address(program, Integer.toUnsignedLong(ncchEx.sci.textCodeSetInfo.address))
        createLabel(program, textStart, "ctr_entry")
        createLabel(program, textStart, "ctr_text_start")
        ensureFunction(program, textStart, "ctr_entry")

        createLabel(program, address(program, Integer.toUnsignedLong(ncchEx.sci.readOnlyCodeSetInfo.address)), "ctr_rodata_start")
        createLabel(program, address(program, Integer.toUnsignedLong(ncchEx.sci.dataCodeSetInfo.address)), "ctr_data_start")

        val bssStart = Integer.toUnsignedLong(ncchEx.sci.dataCodeSetInfo.address) + Integer.toUnsignedLong(ncchEx.sci.dataCodeSetInfo.size)
        createLabel(program, address(program, bssStart), "ctr_bss_start")

        program.listing.setComment(textStart, CommentType.PLATE, "3DS code set entry\nStack size: 0x${Integer.toUnsignedLong(ncchEx.sci.stackSize).toString(16)}")
        log.appendMsg("Seeded 3DS code-set labels at 0x${textStart.offset.toString(16)}")
    }

    private fun writeExHeaderMetadata(program: Program, ncchEx: NCCHExHeader, log: MessageLog) {
        val info = program.getOptions(Program.PROGRAM_INFO)
        val dependencies = dependencyModuleIds(ncchEx)
        info.setString("3DS Application Title", ncchEx.sci.applicationTitle_8.stripNulls())
        info.setString("3DS Stack Size", hex(Integer.toUnsignedLong(ncchEx.sci.stackSize)))
        info.setString("3DS Text Code Set", sectionSummary(ncchEx.sci.textCodeSetInfo))
        info.setString("3DS Rodata Code Set", sectionSummary(ncchEx.sci.readOnlyCodeSetInfo))
        info.setString("3DS Data Code Set", sectionSummary(ncchEx.sci.dataCodeSetInfo))
        info.setString("3DS BSS Size", hex(Integer.toUnsignedLong(ncchEx.sci.bssSize)))
        info.setLong("3DS Dependency Count", dependencies.size.toLong())
        info.setString("3DS Dependency Module IDs", dependencies.joinToString(",") { hex(it) })
        log.appendMsg("Wrote 3DS ExHeader metadata (${dependencies.size} dependency module IDs)")
    }

    private fun dependencyModuleIds(ncchEx: NCCHExHeader): List<Long> {
        val buffer = ByteBuffer.wrap(ncchEx.sci.dependencyModuleList_384).order(ByteOrder.LITTLE_ENDIAN)
        return buildList {
            while (buffer.remaining() >= java.lang.Long.BYTES) {
                val id = buffer.long
                if (id != 0L) {
                    add(id)
                }
            }
        }
    }

    private fun sectionSummary(info: NCCHExHeader.SystemControlInfo.CodeSetInfo): String {
        return "address=${hex(Integer.toUnsignedLong(info.address))}, physical=${hex(Integer.toUnsignedLong(info.physRegionSize) * 0x1000L)}, size=${hex(Integer.toUnsignedLong(info.size))}"
    }

    private fun createLabel(program: Program, address: Address, name: String) {
        if (program.symbolTable.getSymbols(address).any { it.name == name }) {
            return
        }
        program.symbolTable.createLabel(address, name, SourceType.ANALYSIS)
    }

    private fun ensureFunction(program: Program, address: Address, name: String) {
        if (program.functionManager.getFunctionAt(address) != null) {
            return
        }
        program.listing.createFunction(name, address, AddressSet(address), SourceType.ANALYSIS)
    }

    private fun requireProviderRange(provider: ByteProvider, offset: Long, size: Long, description: String) {
        require(offset >= 0) { "$description has negative offset $offset" }
        require(size >= 0) { "$description has negative size $size" }
        require(offset <= provider.length() && offset + size <= provider.length()) {
            "$description range 0x${offset.toString(16)}..0x${(offset + size).toString(16)} exceeds provider length 0x${provider.length().toString(16)}"
        }
    }

    private fun address(program: Program, offset: Long): Address {
        return program.addressFactory.defaultAddressSpace.getAddress(offset)
    }

    private fun hex(value: Long): String {
        return "0x${value.toString(16)}"
    }

    private data class CodeSetSection(
        val name: String,
        val address: Long,
        val physicalSize: Long,
        val size: Long,
        val read: Boolean,
        val write: Boolean,
        val execute: Boolean,
    ) {
        constructor(name: String, info: NCCHExHeader.SystemControlInfo.CodeSetInfo, read: Boolean, write: Boolean, execute: Boolean) : this(
            name,
            Integer.toUnsignedLong(info.address),
            Integer.toUnsignedLong(info.physRegionSize) * 0x1000L,
            Integer.toUnsignedLong(info.size),
            read,
            write,
            execute,
        )
    }

    private data class CodeSetLoaderOptions(
        val initializeBss: Boolean,
        val seedLabels: Boolean,
        val disableSwitchAnalysis: Boolean,
        val writeExHeaderMetadata: Boolean,
    ) {
        companion object {
            fun from(options: List<Option>): CodeSetLoaderOptions {
                return CodeSetLoaderOptions(
                    initializeBss = booleanOption(options, OPTION_INITIALIZE_BSS, false),
                    seedLabels = booleanOption(options, OPTION_SEED_LABELS, true),
                    disableSwitchAnalysis = booleanOption(options, OPTION_DISABLE_SWITCH_ANALYSIS, true),
                    writeExHeaderMetadata = booleanOption(options, OPTION_WRITE_EXHEADER_METADATA, true),
                )
            }

            private fun booleanOption(options: List<Option>, name: String, default: Boolean): Boolean {
                val value = options.firstOrNull { it.name == name }?.value ?: return default
                return value as? Boolean ?: default
            }
        }
    }
}
