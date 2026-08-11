#include "PeParser.h"
#include <QFile>
#include <QFileInfo>
#include <cmath>
#include <array>
#include <algorithm>
#include <vector>

namespace Fidra {

PeParser::PeParser()
    : Valid(false) {
}

PeParser::~PeParser() = default;

bool PeParser::ParseFile(const QString& FilePath) {
    Valid = false;
    BinaryData.reset();
    RawData.clear();

    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly))
        return false;

    RawData = File.readAll();
    File.close();

    if (RawData.isEmpty())
        return false;

    try {
        std::vector<uint8_t> Buffer(
            reinterpret_cast<const uint8_t*>(RawData.constData()),
            reinterpret_cast<const uint8_t*>(RawData.constData()) + RawData.size()
        );
        BinaryData = LIEF::PE::Parser::parse(std::move(Buffer));
        if (BinaryData) {
            Valid = true;
        }
    } catch (...) {
        Valid = false;
    }

    return Valid;
}

bool PeParser::ParseMemory(const QByteArray& Data) {
    Valid = false;
    BinaryData.reset();
    RawData = Data;

    if (RawData.isEmpty())
        return false;

    try {
        std::vector<uint8_t> Buffer(
            reinterpret_cast<const uint8_t*>(RawData.constData()),
            reinterpret_cast<const uint8_t*>(RawData.constData()) + RawData.size()
        );
        BinaryData = LIEF::PE::Parser::parse(std::move(Buffer));
        if (BinaryData) {
            Valid = true;
        }
    } catch (...) {
        Valid = false;
    }

    return Valid;
}

bool PeParser::IsValid() const {
    return Valid;
}

bool PeParser::IsPe32Plus() const {
    if (!Valid || !BinaryData)
        return false;
    return BinaryData->optional_header().magic() == LIEF::PE::PE_TYPE::PE32_PLUS;
}

PeDosHeader PeParser::GetDosHeader() const {
    PeDosHeader Result{};
    if (!Valid || !BinaryData)
        return Result;

    const auto& Dos = BinaryData->dos_header();
    Result.Magic = Dos.magic();
    Result.Cblp = Dos.used_bytes_in_last_page();
    Result.Cp = Dos.file_size_in_pages();
    Result.Crlc = Dos.numberof_relocation();
    Result.Cparhdr = Dos.header_size_in_paragraphs();
    Result.Minalloc = Dos.minimum_extra_paragraphs();
    Result.Maxalloc = Dos.maximum_extra_paragraphs();
    Result.Ss = Dos.initial_relative_ss();
    Result.Sp = Dos.initial_sp();
    Result.Csum = Dos.checksum();
    Result.Ip = Dos.initial_ip();
    Result.Cs = Dos.initial_relative_cs();
    Result.Lfarlc = Dos.addressof_relocation_table();
    Result.Ovno = Dos.overlay_number();
    Result.Oemid = Dos.oem_id();
    Result.Oeminfo = Dos.oem_info();
    Result.Lfanew = Dos.addressof_new_exeheader();

    return Result;
}

PeFileHeader PeParser::GetFileHeader() const {
    PeFileHeader Result{};
    if (!Valid || !BinaryData)
        return Result;

    const auto& Hdr = BinaryData->header();
    Result.Machine = static_cast<uint16_t>(Hdr.machine());
    Result.NumberOfSections = Hdr.numberof_sections();
    Result.TimeDateStamp = Hdr.time_date_stamp();
    Result.PointerToSymbolTable = Hdr.pointerto_symbol_table();
    Result.NumberOfSymbols = Hdr.numberof_symbols();
    Result.SizeOfOptionalHeader = Hdr.sizeof_optional_header();
    Result.Characteristics = static_cast<uint16_t>(Hdr.characteristics());

    return Result;
}

PeOptionalHeader PeParser::GetOptionalHeader() const {
    PeOptionalHeader Result{};
    if (!Valid || !BinaryData)
        return Result;

    const auto& Opt = BinaryData->optional_header();
    Result.Magic = static_cast<uint16_t>(Opt.magic());
    Result.MajorLinkerVersion = Opt.major_linker_version();
    Result.MinorLinkerVersion = Opt.minor_linker_version();
    Result.SizeOfCode = Opt.sizeof_code();
    Result.SizeOfInitializedData = Opt.sizeof_initialized_data();
    Result.SizeOfUninitializedData = Opt.sizeof_uninitialized_data();
    Result.AddressOfEntryPoint = Opt.addressof_entrypoint();
    Result.BaseOfCode = Opt.baseof_code();
    Result.ImageBase = Opt.imagebase();
    Result.SectionAlignment = Opt.section_alignment();
    Result.FileAlignment = Opt.file_alignment();
    Result.MajorOperatingSystemVersion = Opt.major_operating_system_version();
    Result.MinorOperatingSystemVersion = Opt.minor_operating_system_version();
    Result.MajorImageVersion = Opt.major_image_version();
    Result.MinorImageVersion = Opt.minor_image_version();
    Result.MajorSubsystemVersion = Opt.major_subsystem_version();
    Result.MinorSubsystemVersion = Opt.minor_subsystem_version();
    Result.Win32VersionValue = Opt.win32_version_value();
    Result.SizeOfImage = Opt.sizeof_image();
    Result.SizeOfHeaders = Opt.sizeof_headers();
    Result.CheckSum = Opt.checksum();
    Result.Subsystem = static_cast<uint16_t>(Opt.subsystem());
    Result.DllCharacteristics = static_cast<uint16_t>(Opt.dll_characteristics());
    Result.SizeOfStackReserve = Opt.sizeof_stack_reserve();
    Result.SizeOfStackCommit = Opt.sizeof_stack_commit();
    Result.SizeOfHeapReserve = Opt.sizeof_heap_reserve();
    Result.SizeOfHeapCommit = Opt.sizeof_heap_commit();
    Result.LoaderFlags = Opt.loader_flags();
    Result.NumberOfRvaAndSizes = Opt.numberof_rva_and_size();

    struct DirInfo {
        LIEF::PE::DataDirectory::TYPES Type;
        QString Label;
    };

    static const DirInfo DirectoryTypes[] = {
        { LIEF::PE::DataDirectory::TYPES::EXPORT_TABLE, "Export Table" },
        { LIEF::PE::DataDirectory::TYPES::IMPORT_TABLE, "Import Table" },
        { LIEF::PE::DataDirectory::TYPES::RESOURCE_TABLE, "Resource Table" },
        { LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE, "Exception Table" },
        { LIEF::PE::DataDirectory::TYPES::CERTIFICATE_TABLE, "Certificate Table" },
        { LIEF::PE::DataDirectory::TYPES::BASE_RELOCATION_TABLE, "Base Relocation Table" },
        { LIEF::PE::DataDirectory::TYPES::DEBUG_DIR, "Debug" },
        { LIEF::PE::DataDirectory::TYPES::ARCHITECTURE, "Architecture" },
        { LIEF::PE::DataDirectory::TYPES::GLOBAL_PTR, "Global Ptr" },
        { LIEF::PE::DataDirectory::TYPES::TLS_TABLE, "TLS Table" },
        { LIEF::PE::DataDirectory::TYPES::LOAD_CONFIG_TABLE, "Load Config Table" },
        { LIEF::PE::DataDirectory::TYPES::BOUND_IMPORT, "Bound Import" },
        { LIEF::PE::DataDirectory::TYPES::IAT, "IAT" },
        { LIEF::PE::DataDirectory::TYPES::DELAY_IMPORT_DESCRIPTOR, "Delay Import Descriptor" },
        { LIEF::PE::DataDirectory::TYPES::CLR_RUNTIME_HEADER, "CLR Runtime Header" },
    };

    for (const auto& DirType : DirectoryTypes) {
        const auto* Dir = BinaryData->data_directory(DirType.Type);
        if (Dir) {
            PeDataDirectory Entry;
            Entry.Name = DirType.Label;
            Entry.Rva = Dir->RVA();
            Entry.Size = Dir->size();
            Result.DataDirectories.append(Entry);
        }
    }

    return Result;
}

QList<PeSectionInfo> PeParser::GetSections() const {
    QList<PeSectionInfo> Result;
    if (!Valid || !BinaryData)
        return Result;

    for (const auto& Section : BinaryData->sections()) {
        PeSectionInfo Info;
        Info.Name = QString::fromStdString(Section.name());
        Info.VirtualAddress = static_cast<uint32_t>(Section.virtual_address());
        Info.VirtualSize = static_cast<uint32_t>(Section.virtual_size());
        Info.RawSize = static_cast<uint32_t>(Section.size());
        Info.RawOffset = static_cast<uint32_t>(Section.offset());
        Info.Characteristics = static_cast<uint32_t>(Section.characteristics());

        LIEF::span<const uint8_t> Content = Section.content();
        if (!Content.empty()) {
            Info.Entropy = CalculateEntropy(Content.data(), Content.size());
        } else {
            Info.Entropy = 0.0;
        }

        Result.append(Info);
    }

    return Result;
}

QList<PeImportDll> PeParser::GetImports() const {
    QList<PeImportDll> Result;
    if (!Valid || !BinaryData)
        return Result;

    for (const auto& Import : BinaryData->imports()) {
        PeImportDll Dll;
        Dll.DllName = QString::fromStdString(Import.name());

        for (const auto& Entry : Import.entries()) {
            PeImportEntry Func;
            Func.IsOrdinal = Entry.is_ordinal();
            if (Func.IsOrdinal) {
                Func.Ordinal = static_cast<uint16_t>(Entry.ordinal());
                Func.Name = QString("Ordinal #%1").arg(Func.Ordinal);
                Func.Hint = 0;
            } else {
                Func.Name = QString::fromStdString(Entry.name());
                Func.Hint = static_cast<uint16_t>(Entry.hint());
                Func.Ordinal = 0;
            }
            Dll.Functions.append(Func);
        }

        Result.append(Dll);
    }

    return Result;
}

QList<PeExportEntry> PeParser::GetExports() const {
    QList<PeExportEntry> Result;
    if (!Valid || !BinaryData)
        return Result;

    const auto* ExportDir = BinaryData->get_export();
    if (!ExportDir)
        return Result;

    for (const auto& Entry : ExportDir->entries()) {
        PeExportEntry Export;
        Export.Ordinal = static_cast<uint16_t>(Entry.ordinal());
        Export.Name = QString::fromStdString(Entry.name());
        Export.Address = Entry.address();
        if (Entry.is_forwarded()) {
            auto FwdInfo = Entry.forward_information();
            Export.ForwarderName = QString::fromStdString(
                FwdInfo.library + "." + FwdInfo.function
            );
        }
        Result.append(Export);
    }

    return Result;
}

void PeParser::WalkResourceNode(const LIEF::PE::ResourceNode& Node, QList<PeResourceEntry>& Entries, int Depth, const QString& TypeName) const {
    if (Node.is_data()) {
        const auto& DataNode = static_cast<const LIEF::PE::ResourceData&>(Node);
        PeResourceEntry Entry;
        Entry.Id = Node.id();
        Entry.Name = Node.has_name() ? QString::fromStdU16String(Node.name()) : QString::number(Node.id());
        Entry.Type = TypeName;
        Entry.Offset = DataNode.offset();
        Entry.Size = static_cast<uint32_t>(DataNode.content().size());
        Entry.Depth = Depth;
        LIEF::span<const uint8_t> Content = DataNode.content();
        Entry.Data = QByteArray(reinterpret_cast<const char*>(Content.data()), static_cast<int>(Content.size()));
        Entries.append(Entry);
    } else if (Node.is_directory()) {
        const auto& DirNode = static_cast<const LIEF::PE::ResourceDirectory&>(Node);
        QString CurrentType = TypeName;

        if (Depth == 0) {
            static const QMap<uint32_t, QString> ResourceTypes = {
                {1, "RT_CURSOR"}, {2, "RT_BITMAP"}, {3, "RT_ICON"},
                {4, "RT_MENU"}, {5, "RT_DIALOG"}, {6, "RT_STRING"},
                {7, "RT_FONTDIR"}, {8, "RT_FONT"}, {9, "RT_ACCELERATOR"},
                {10, "RT_RCDATA"}, {11, "RT_MESSAGETABLE"}, {12, "RT_GROUP_CURSOR"},
                {14, "RT_GROUP_ICON"}, {16, "RT_VERSION"}, {17, "RT_DLGINCLUDE"},
                {19, "RT_PLUGPLAY"}, {20, "RT_VXD"}, {21, "RT_ANICURSOR"},
                {22, "RT_ANIICON"}, {23, "RT_HTML"}, {24, "RT_MANIFEST"},
            };
            CurrentType = ResourceTypes.value(Node.id(), QString("Type_%1").arg(Node.id()));
        }

        for (const auto& Child : DirNode.childs()) {
            WalkResourceNode(Child, Entries, Depth + 1, CurrentType);
        }
    }
}

QList<PeResourceEntry> PeParser::GetResources() const {
    QList<PeResourceEntry> Result;
    if (!Valid || !BinaryData)
        return Result;

    const auto* RootNode = BinaryData->resources();
    if (!RootNode)
        return Result;

    WalkResourceNode(*RootNode, Result, 0, "Unknown");

    return Result;
}

QList<PeTlsCallback> PeParser::GetTlsCallbacks() const {
    QList<PeTlsCallback> Result;
    if (!Valid || !BinaryData)
        return Result;

    if (!BinaryData->has_tls())
        return Result;

    const auto* Tls = BinaryData->tls();
    if (!Tls)
        return Result;
    for (uint64_t Callback : Tls->callbacks()) {
        PeTlsCallback Entry;
        Entry.Address = Callback;
        Result.append(Entry);
    }

    return Result;
}

QList<PeRichEntry> PeParser::GetRichHeader() const {
    QList<PeRichEntry> Result;
    if (!Valid || !BinaryData)
        return Result;

    if (!BinaryData->has_rich_header())
        return Result;

    const auto* Rich = BinaryData->rich_header();
    if (!Rich)
        return Result;
    for (const auto& Entry : Rich->entries()) {
        PeRichEntry RichEntry;
        RichEntry.Id = Entry.id();
        RichEntry.BuildId = Entry.build_id();
        RichEntry.Count = Entry.count();
        Result.append(RichEntry);
    }

    return Result;
}

QList<PackerDetection> PeParser::DetectPackers() const {
    QList<PackerDetection> Result;
    if (!Valid || !BinaryData)
        return Result;

    auto Sections = GetSections();
    if (Sections.isEmpty())
        return Result;

    bool FoundUpx0 = false;
    bool FoundUpx1 = false;
    for (const auto& Sec : Sections) {
        if (Sec.Name == "UPX0") FoundUpx0 = true;
        if (Sec.Name == "UPX1") FoundUpx1 = true;
    }
    if (FoundUpx0 && FoundUpx1) {
        PackerDetection Det;
        Det.Name = "UPX";
        Det.Confidence = 0.95;
        Det.Details = "UPX0 and UPX1 sections detected";
        Result.append(Det);
    } else if (FoundUpx0 || FoundUpx1) {
        PackerDetection Det;
        Det.Name = "UPX";
        Det.Confidence = 0.6;
        Det.Details = "Partial UPX section names found";
        Result.append(Det);
    }

    if (RawData.size() >= 4) {
        int UpxMagicPos = RawData.indexOf("UPX!");
        if (UpxMagicPos >= 0) {
            PackerDetection Det;
            Det.Name = "UPX";
            Det.Confidence = 0.9;
            Det.Details = QString("UPX magic signature at offset 0x%1").arg(UpxMagicPos, 0, 16);
            bool AlreadyHasUpx = false;
            for (const auto& Existing : Result) {
                if (Existing.Name == "UPX" && Existing.Confidence >= 0.9)
                    AlreadyHasUpx = true;
            }
            if (!AlreadyHasUpx)
                Result.append(Det);
        }
    }

    for (const auto& Sec : Sections) {
        if (Sec.Name == ".vmp0" || Sec.Name == ".vmp1" || Sec.Name == ".vmp2") {
            PackerDetection Det;
            Det.Name = "VMProtect";
            Det.Confidence = 0.9;
            Det.Details = QString("VMProtect section '%1' detected").arg(Sec.Name);
            Result.append(Det);
            break;
        }
    }

    if (Sections.size() >= 2) {
        const auto& LastSection = Sections.last();
        uint32_t EntryPoint = BinaryData->optional_header().addressof_entrypoint();
        uint32_t LastSecStart = LastSection.VirtualAddress;
        uint32_t LastSecEnd = LastSecStart + LastSection.VirtualSize;
        if (EntryPoint >= LastSecStart && EntryPoint < LastSecEnd && LastSection.Entropy > 6.5) {
            bool AlreadyVmp = false;
            for (const auto& Det : Result) {
                if (Det.Name == "VMProtect")
                    AlreadyVmp = true;
            }
            if (!AlreadyVmp) {
                PackerDetection Det;
                Det.Name = "VMProtect";
                Det.Confidence = 0.5;
                Det.Details = "Entry point in last section with high entropy";
                Result.append(Det);
            }
        }
    }

    for (const auto& Sec : Sections) {
        if (Sec.Name == ".themida" || Sec.Name == ".winlicense") {
            PackerDetection Det;
            Det.Name = "Themida/WinLicense";
            Det.Confidence = 0.95;
            Det.Details = QString("Themida section '%1' detected").arg(Sec.Name);
            Result.append(Det);
            break;
        }
    }

    for (const auto& Sec : Sections) {
        if (Sec.Name == ".aspack" || Sec.Name == ".adata") {
            PackerDetection Det;
            Det.Name = "ASPack";
            Det.Confidence = 0.85;
            Det.Details = QString("ASPack section '%1' detected").arg(Sec.Name);
            Result.append(Det);
            break;
        }
    }

    for (const auto& Sec : Sections) {
        if (Sec.Name.startsWith(".pec")) {
            PackerDetection Det;
            Det.Name = "PECompact";
            Det.Confidence = 0.8;
            Det.Details = QString("PECompact section '%1' detected").arg(Sec.Name);
            Result.append(Det);
            break;
        }
    }

    int HighEntropyCount = 0;
    int ExecutableSections = 0;
    for (const auto& Sec : Sections) {
        if (Sec.RawSize > 0) {
            ExecutableSections++;
            if (Sec.Entropy > 7.0)
                HighEntropyCount++;
        }
    }
    if (ExecutableSections > 0 && HighEntropyCount > ExecutableSections / 2) {
        bool AlreadyDetected = !Result.isEmpty();
        if (!AlreadyDetected) {
            PackerDetection Det;
            Det.Name = "Unknown Packer/Crypter";
            Det.Confidence = 0.4;
            Det.Details = QString("%1 of %2 sections have entropy > 7.0").arg(HighEntropyCount).arg(ExecutableSections);
            Result.append(Det);
        }
    }

    return Result;
}

double PeParser::CalculateEntropy(const uint8_t* Data, size_t Size) {
    if (!Data || Size == 0)
        return 0.0;

    std::array<uint64_t, 256> Frequencies{};
    for (size_t I = 0; I < Size; ++I)
        Frequencies[Data[I]]++;

    double Entropy = 0.0;
    double SizeD = static_cast<double>(Size);

    for (size_t I = 0; I < 256; ++I) {
        if (Frequencies[I] == 0)
            continue;
        double Probability = static_cast<double>(Frequencies[I]) / SizeD;
        Entropy -= Probability * std::log2(Probability);
    }

    return Entropy;
}

QList<QPair<uint64_t, double>> PeParser::CalculateFileEntropy(size_t BlockSize) const {
    QList<QPair<uint64_t, double>> Result;
    if (RawData.isEmpty() || BlockSize == 0)
        return Result;

    const auto* Bytes = reinterpret_cast<const uint8_t*>(RawData.constData());
    size_t TotalSize = static_cast<size_t>(RawData.size());

    for (size_t Offset = 0; Offset < TotalSize; Offset += BlockSize) {
        size_t ChunkSize = std::min(BlockSize, TotalSize - Offset);
        double BlockEntropy = CalculateEntropy(Bytes + Offset, ChunkSize);
        Result.append(QPair<uint64_t, double>(static_cast<uint64_t>(Offset), BlockEntropy));
    }

    return Result;
}

const QByteArray& PeParser::GetRawData() const {
    return RawData;
}

LIEF::PE::Binary* PeParser::GetBinary() const {
    return BinaryData.get();
}

}
