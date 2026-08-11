#include "AnalysisEngine.h"
#include <capstone/capstone.h>
#include <QFile>
#include <QFileInfo>
#include <QThread>
#include <QtConcurrent>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <cxxabi.h>
#include <cstdlib>
#include <QRegularExpression>

namespace Fidra {

AnalysisWorker::AnalysisWorker(AnalysisDatabase* Db, QObject* Parent)
    : QObject(Parent)
    , Db(Db)
    , Cancelled(0) {
}

AnalysisWorker::~AnalysisWorker() {
}

void AnalysisWorker::Cancel() {
    Cancelled.storeRelaxed(1);
}

void AnalysisWorker::Run() {
    EmitProgress(AnalysisState::Loading, 0, "Loading binary...");
    LoadBinary();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    BinaryInfo Info = Db->GetBinaryInfo();
    if (Info.Segments.isEmpty()) {
        emit LogMessage("No segments loaded");
        emit Finished(false);
        return;
    }

    EmitProgress(AnalysisState::Loading, 3, "Parsing exception directory...");
    ParsePdata();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Loading, 5, "Parsing SEH/exception unwinding...");
    ParseSeh();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Loading, 7, "Detecting packer/compiler...");
    DetectPackerCompiler();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    int ThreadCount = QThread::idealThreadCount();
    if (ThreadCount < 2) ThreadCount = 2;
    EmitProgress(AnalysisState::Disassembling, 10,
        QString("Recursive descent disassembly (%1 threads)...").arg(ThreadCount));
    RunRecursiveDescentMT();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Disassembling, 25, "Linear sweep for missed functions...");
    RunLinearSweep();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Disassembling, 30, "Scanning vtables for function pointers...");
    ScanVtables();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Disassembling, 33, "Scanning code pointer references...");
    ScanCodePointers();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Disassembling, 36, "Resolving jump tables...");
    ResolveJumpTables();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::Disassembling, 38, "Filling code gaps (aggressive scan)...");
    FillCodeGaps();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::FindingFunctions, 42, "Detecting tail call functions...");
    DetectTailCallFunctions();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::FindingFunctions, 44, "Finding functions...");
    FindFunctions();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::FindingStrings, 50, "Finding strings...");
    FindStrings();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::BuildingXrefs, 58, "Building cross-references...");
    BuildXrefs();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::BuildingXrefs, 65, "Finding string references...");
    FindStringReferences();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::BuildingXrefs, 68, "Generating auto-comments for API calls...");
    GenerateAutoComments();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 70, "Naming imports and exports...");
    NameImportsExports();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 72, "Demangling C++ names...");
    DemangleNames();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 74, "Demangling Rust/Go/Swift/D names...");
    DemangleExtended();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 75, "Matching function signatures...");
    MatchSignatures();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 77, "Detecting non-returning functions...");
    DetectNonReturning();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 79, "Parsing C++ RTTI...");
    ParseRtti();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 82, "Analyzing functions...");
    AnalyzeFunctions();
    if (Cancelled.loadRelaxed()) { emit Finished(false); return; }

    EmitProgress(AnalysisState::AnalyzingFunctions, 95, "Detecting thunks...");
    DetectThunks();

    EmitProgress(AnalysisState::Complete, 100,
        QString("Analysis complete: %1 functions, %2 instructions, %3 strings, %4 xrefs")
            .arg(Db->FunctionCount())
            .arg(Db->InstructionCount())
            .arg(Db->StringCount())
            .arg(Db->XrefCount()));

    emit LogMessage(QString("Analysis complete: %1 functions, %2 instructions, %3 strings, %4 xrefs")
        .arg(Db->FunctionCount()).arg(Db->InstructionCount())
        .arg(Db->StringCount()).arg(Db->XrefCount()));

    emit Finished(true);
}

void AnalysisWorker::LoadBinary() {
    BinaryInfo Info = Db->GetBinaryInfo();
    QString FilePath = Info.FilePath;

    QFile File(FilePath);
    if (!File.open(QIODevice::ReadOnly)) {
        emit LogMessage("Failed to open file: " + FilePath);
        return;
    }

    QByteArray Data = File.readAll();
    File.close();

    if (Data.size() < 4) {
        emit LogMessage("File too small");
        return;
    }

    uint16_t Magic16 = 0;
    std::memcpy(&Magic16, Data.constData(), 2);

    uint32_t Magic32 = 0;
    if (Data.size() >= 4) {
        std::memcpy(&Magic32, Data.constData(), 4);
    }

    if (Magic16 == 0x5A4D) {
        emit LogMessage("Detected PE format");
        LoadPe(Data);
    } else if (Magic32 == 0x464C457F) {
        emit LogMessage("Detected ELF format");
        LoadElf(Data);
    } else if (Magic32 == 0xFEEDFACE || Magic32 == 0xFEEDFACF ||
               Magic32 == 0xCEFAEDFE || Magic32 == 0xCFFAEDFE ||
               Magic32 == 0xBEBAFECA || Magic32 == 0xCAFEBABE) {
        emit LogMessage("Detected Mach-O format");
        LoadMachO(Data);
    } else {
        emit LogMessage("Unknown format, loading as raw binary");
        Info.Arch = Architecture::X64;
        Info.Is64Bit = true;
        Info.ImageBase = 0x400000;
        Info.EntryPoint = 0x400000;
        Info.ImageSize = static_cast<size_t>(Data.size());

        Segment Seg;
        Seg.Name = ".raw";
        Seg.VirtualAddress = 0x400000;
        Seg.VirtualSize = static_cast<size_t>(Data.size());
        Seg.RawSize = static_cast<size_t>(Data.size());
        Seg.RawOffset = 0;
        Seg.Characteristics = 0;
        Seg.Type = SegmentType::Code;
        Seg.Data = Data;
        Seg.IsReadable = true;
        Seg.IsWritable = false;
        Seg.IsExecutable = true;
        Info.Segments.append(Seg);

        Db->SetBinaryInfo(Info);
    }
}

void AnalysisWorker::LoadPe(const QByteArray& Data) {
    if (Data.size() < 64) return;

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    size_t FileSize = static_cast<size_t>(Data.size());

    uint32_t PeOffset = 0;
    std::memcpy(&PeOffset, Raw + 0x3C, 4);

    if (PeOffset + 24 > FileSize) {
        emit LogMessage("Invalid PE offset");
        return;
    }

    uint32_t PeSig = 0;
    std::memcpy(&PeSig, Raw + PeOffset, 4);
    if (PeSig != 0x00004550) {
        emit LogMessage("Invalid PE signature");
        return;
    }

    const uint8_t* CoffHdr = Raw + PeOffset + 4;
    uint16_t Machine = 0;
    std::memcpy(&Machine, CoffHdr, 2);
    uint16_t NumberOfSections = 0;
    std::memcpy(&NumberOfSections, CoffHdr + 2, 2);
    uint32_t TimeDateStamp = 0;
    std::memcpy(&TimeDateStamp, CoffHdr + 4, 4);
    uint16_t SizeOfOptionalHeader = 0;
    std::memcpy(&SizeOfOptionalHeader, CoffHdr + 16, 2);
    uint16_t CoffCharacteristics = 0;
    std::memcpy(&CoffCharacteristics, CoffHdr + 18, 2);

    const uint8_t* OptHdr = CoffHdr + 20;
    uint16_t OptMagic = 0;
    std::memcpy(&OptMagic, OptHdr, 2);

    bool Is64 = (OptMagic == 0x20B);

    BinaryInfo Info = Db->GetBinaryInfo();
    Info.Arch = Is64 ? Architecture::X64 : Architecture::X86;
    Info.Is64Bit = Is64;
    Info.TimeDateStamp = TimeDateStamp;
    Info.IsDll = (CoffCharacteristics & 0x2000) != 0;
    Info.IsDriver = false;

    uint32_t AddressOfEntryPoint = 0;
    std::memcpy(&AddressOfEntryPoint, OptHdr + 16, 4);

    uint64_t ImageBase = 0;
    if (Is64) {
        std::memcpy(&ImageBase, OptHdr + 24, 8);
    } else {
        uint32_t ImageBase32 = 0;
        std::memcpy(&ImageBase32, OptHdr + 28, 4);
        ImageBase = ImageBase32;
    }

    uint32_t SectionAlignment = 0;
    std::memcpy(&SectionAlignment, OptHdr + 32, 4);
    uint32_t FileAlignment = 0;
    std::memcpy(&FileAlignment, OptHdr + 36, 4);

    uint16_t MajorLinkerVersion = 0;
    std::memcpy(&MajorLinkerVersion, OptHdr + 2, 1);
    uint16_t MinorLinkerVersion = 0;
    std::memcpy(&MinorLinkerVersion, OptHdr + 3, 1);

    uint32_t SizeOfImage = 0;
    if (Is64) {
        std::memcpy(&SizeOfImage, OptHdr + 56, 4);
    } else {
        std::memcpy(&SizeOfImage, OptHdr + 56, 4);
    }

    uint16_t Subsystem = 0;
    if (Is64) {
        std::memcpy(&Subsystem, OptHdr + 68, 2);
    } else {
        std::memcpy(&Subsystem, OptHdr + 68, 2);
    }

    Info.ImageBase = ImageBase;
    Info.EntryPoint = ImageBase + AddressOfEntryPoint;
    Info.ImageSize = SizeOfImage;
    Info.Subsystem = Subsystem;
    Info.LinkerVersion = QString("%1.%2").arg(MajorLinkerVersion).arg(MinorLinkerVersion);

    if (Subsystem == 1) {
        Info.IsDriver = true;
    }

    uint32_t NumberOfRvaAndSizes = 0;
    size_t DataDirOffset = 0;
    if (Is64) {
        std::memcpy(&NumberOfRvaAndSizes, OptHdr + 108, 4);
        DataDirOffset = 112;
    } else {
        std::memcpy(&NumberOfRvaAndSizes, OptHdr + 92, 4);
        DataDirOffset = 96;
    }

    struct DataDirectory {
        uint32_t Rva;
        uint32_t Size;
    };

    QVector<DataDirectory> DataDirs;
    for (uint32_t I = 0; I < NumberOfRvaAndSizes && I < 16; ++I) {
        DataDirectory Dir;
        size_t Off = DataDirOffset + I * 8;
        if (Off + 8 > SizeOfOptionalHeader) break;
        std::memcpy(&Dir.Rva, OptHdr + Off, 4);
        std::memcpy(&Dir.Size, OptHdr + Off + 4, 4);
        DataDirs.append(Dir);
    }

    const uint8_t* SectionTable = OptHdr + SizeOfOptionalHeader;

    auto RvaToFileOffset = [&](uint32_t Rva, const QList<Segment>& Segments) -> size_t {
        for (const auto& Seg : Segments) {
            uint32_t SegVa = static_cast<uint32_t>(Seg.VirtualAddress - ImageBase);
            if (Rva >= SegVa && Rva < SegVa + static_cast<uint32_t>(Seg.VirtualSize)) {
                return Seg.RawOffset + (Rva - SegVa);
            }
        }
        return 0;
    };

    for (uint16_t I = 0; I < NumberOfSections; ++I) {
        if (Cancelled.loadRelaxed()) return;

        const uint8_t* SecHdr = SectionTable + I * 40;
        if (static_cast<size_t>(SecHdr - Raw) + 40 > FileSize) break;

        Segment Seg;

        char NameBuf[9] = {};
        std::memcpy(NameBuf, SecHdr, 8);
        Seg.Name = QString::fromLatin1(NameBuf).trimmed();

        uint32_t VirtualSize = 0;
        std::memcpy(&VirtualSize, SecHdr + 8, 4);
        uint32_t VirtualAddress = 0;
        std::memcpy(&VirtualAddress, SecHdr + 12, 4);
        uint32_t SizeOfRawData = 0;
        std::memcpy(&SizeOfRawData, SecHdr + 16, 4);
        uint32_t PointerToRawData = 0;
        std::memcpy(&PointerToRawData, SecHdr + 20, 4);
        uint32_t Characteristics = 0;
        std::memcpy(&Characteristics, SecHdr + 36, 4);

        Seg.VirtualAddress = ImageBase + VirtualAddress;
        Seg.VirtualSize = VirtualSize > 0 ? VirtualSize : SizeOfRawData;
        Seg.RawSize = SizeOfRawData;
        Seg.RawOffset = PointerToRawData;
        Seg.Characteristics = Characteristics;

        Seg.IsReadable = (Characteristics & 0x40000000) != 0;
        Seg.IsWritable = (Characteristics & 0x80000000) != 0;
        Seg.IsExecutable = (Characteristics & 0x20000000) != 0;

        bool IsCode = (Characteristics & 0x00000020) != 0;
        bool IsInitData = (Characteristics & 0x00000040) != 0;
        bool IsUninitData = (Characteristics & 0x00000080) != 0;

        if (IsCode || Seg.IsExecutable) {
            Seg.Type = SegmentType::Code;
        } else if (IsUninitData) {
            Seg.Type = SegmentType::Bss;
        } else if (IsInitData) {
            Seg.Type = SegmentType::Data;
        } else {
            Seg.Type = SegmentType::Unknown;
        }

        if (Seg.Name == ".rsrc") Seg.Type = SegmentType::Resource;
        if (Seg.Name == ".reloc") Seg.Type = SegmentType::Reloc;

        if (PointerToRawData > 0 && SizeOfRawData > 0 && PointerToRawData < FileSize) {
            size_t Available = FileSize - PointerToRawData;
            size_t ToRead = std::min(static_cast<size_t>(SizeOfRawData), Available);
            Seg.Data = Data.mid(static_cast<qsizetype>(PointerToRawData), static_cast<qsizetype>(ToRead));
            if (static_cast<size_t>(Seg.Data.size()) < Seg.VirtualSize) {
                Seg.Data.append(QByteArray(static_cast<int>(Seg.VirtualSize - Seg.Data.size()), '\0'));
            }
        } else {
            Seg.Data = QByteArray(static_cast<int>(Seg.VirtualSize), '\0');
        }

        Info.Segments.append(Seg);
    }

    if (DataDirs.size() > 1 && DataDirs[1].Rva != 0 && DataDirs[1].Size != 0) {
        size_t ImportOffset = RvaToFileOffset(DataDirs[1].Rva, Info.Segments);
        if (ImportOffset > 0 && ImportOffset + 20 <= FileSize) {
            for (int DescIdx = 0; DescIdx < 1024; ++DescIdx) {
                if (Cancelled.loadRelaxed()) break;
                size_t DescOff = ImportOffset + DescIdx * 20;
                if (DescOff + 20 > FileSize) break;

                uint32_t OriginalFirstThunk = 0;
                std::memcpy(&OriginalFirstThunk, Raw + DescOff, 4);
                uint32_t NameRva = 0;
                std::memcpy(&NameRva, Raw + DescOff + 12, 4);
                uint32_t FirstThunk = 0;
                std::memcpy(&FirstThunk, Raw + DescOff + 16, 4);

                if (NameRva == 0) break;

                size_t NameOff = RvaToFileOffset(NameRva, Info.Segments);
                QString DllName;
                if (NameOff > 0 && NameOff < FileSize) {
                    char DllBuf[256] = {};
                    size_t MaxCopy = std::min(static_cast<size_t>(255), FileSize - NameOff);
                    std::memcpy(DllBuf, Raw + NameOff, MaxCopy);
                    DllName = QString::fromLatin1(DllBuf);
                }

                uint32_t ThunkRva = (OriginalFirstThunk != 0) ? OriginalFirstThunk : FirstThunk;
                if (ThunkRva == 0) continue;

                size_t ThunkOff = RvaToFileOffset(ThunkRva, Info.Segments);
                if (ThunkOff == 0) continue;

                int EntrySize = Is64 ? 8 : 4;

                for (int ThunkIdx = 0; ThunkIdx < 4096; ++ThunkIdx) {
                    size_t TEntryOff = ThunkOff + ThunkIdx * EntrySize;
                    if (TEntryOff + EntrySize > FileSize) break;

                    uint64_t ThunkData = 0;
                    std::memcpy(&ThunkData, Raw + TEntryOff, EntrySize);
                    if (ThunkData == 0) break;

                    ImportEntry Imp;
                    Imp.DllName = DllName;
                    Imp.IatAddress = ImageBase + FirstThunk + ThunkIdx * EntrySize;
                    Imp.ThunkAddress = ImageBase + ThunkRva + ThunkIdx * EntrySize;
                    Imp.IsBound = false;

                    bool IsOrdinal = Is64 ? (ThunkData & 0x8000000000000000ULL) != 0
                                          : (ThunkData & 0x80000000ULL) != 0;

                    if (IsOrdinal) {
                        Imp.Ordinal = static_cast<uint16_t>(ThunkData & 0xFFFF);
                        Imp.FuncName = QString("Ordinal#%1").arg(Imp.Ordinal);
                    } else {
                        uint32_t HintNameRva = static_cast<uint32_t>(ThunkData & 0x7FFFFFFF);
                        size_t HintNameOff = RvaToFileOffset(HintNameRva, Info.Segments);
                        Imp.Ordinal = 0;
                        if (HintNameOff > 0 && HintNameOff + 2 < FileSize) {
                            std::memcpy(&Imp.Ordinal, Raw + HintNameOff, 2);
                            char FuncBuf[256] = {};
                            size_t FnMax = std::min(static_cast<size_t>(255), FileSize - HintNameOff - 2);
                            std::memcpy(FuncBuf, Raw + HintNameOff + 2, FnMax);
                            Imp.FuncName = QString::fromLatin1(FuncBuf);
                        }
                    }

                    Info.Imports.append(Imp);
                }
            }
        }
    }

    if (DataDirs.size() > 13 && DataDirs[13].Rva != 0 && DataDirs[13].Size != 0) {
        size_t DelayOffset = RvaToFileOffset(DataDirs[13].Rva, Info.Segments);
        if (DelayOffset > 0 && DelayOffset + 32 <= FileSize) {
            for (int DescIdx = 0; DescIdx < 256; ++DescIdx) {
                if (Cancelled.loadRelaxed()) break;
                size_t DescOff = DelayOffset + DescIdx * 32;
                if (DescOff + 32 > FileSize) break;

                uint32_t Attrs = 0;
                std::memcpy(&Attrs, Raw + DescOff, 4);
                uint32_t DllNameRva = 0;
                std::memcpy(&DllNameRva, Raw + DescOff + 4, 4);
                uint32_t DelayIat = 0;
                std::memcpy(&DelayIat, Raw + DescOff + 12, 4);
                uint32_t DelayInt = 0;
                std::memcpy(&DelayInt, Raw + DescOff + 16, 4);

                if (DllNameRva == 0 && DelayIat == 0) break;

                bool IsRvaBased = (Attrs & 1) != 0;
                uint32_t ResolvedNameRva = IsRvaBased ? DllNameRva
                    : static_cast<uint32_t>(DllNameRva - ImageBase);

                size_t NameOff = RvaToFileOffset(ResolvedNameRva, Info.Segments);
                QString DllName;
                if (NameOff > 0 && NameOff < FileSize) {
                    char DllBuf[256] = {};
                    size_t MaxCopy = std::min(static_cast<size_t>(255), FileSize - NameOff);
                    std::memcpy(DllBuf, Raw + NameOff, MaxCopy);
                    DllName = QString::fromLatin1(DllBuf);
                }

                uint32_t ThunkRva = (DelayInt != 0) ? DelayInt : DelayIat;
                if (!IsRvaBased && ThunkRva >= ImageBase) {
                    ThunkRva = static_cast<uint32_t>(ThunkRva - ImageBase);
                }
                uint32_t IatRva = IsRvaBased ? DelayIat
                    : static_cast<uint32_t>(DelayIat - ImageBase);

                size_t ThunkOff = RvaToFileOffset(ThunkRva, Info.Segments);
                if (ThunkOff == 0) continue;

                int EntrySize = Is64 ? 8 : 4;

                for (int ThunkIdx = 0; ThunkIdx < 4096; ++ThunkIdx) {
                    size_t TEntryOff = ThunkOff + ThunkIdx * EntrySize;
                    if (TEntryOff + EntrySize > FileSize) break;

                    uint64_t ThunkData = 0;
                    std::memcpy(&ThunkData, Raw + TEntryOff, EntrySize);
                    if (ThunkData == 0) break;

                    ImportEntry Imp;
                    Imp.DllName = DllName;
                    Imp.IatAddress = ImageBase + IatRva + ThunkIdx * EntrySize;
                    Imp.ThunkAddress = ImageBase + ThunkRva + ThunkIdx * EntrySize;
                    Imp.IsBound = false;

                    bool IsOrdinal = Is64 ? (ThunkData & 0x8000000000000000ULL) != 0
                                          : (ThunkData & 0x80000000ULL) != 0;

                    if (IsOrdinal) {
                        Imp.Ordinal = static_cast<uint16_t>(ThunkData & 0xFFFF);
                        Imp.FuncName = QString("Ordinal#%1").arg(Imp.Ordinal);
                    } else {
                        uint32_t HintNameRva = static_cast<uint32_t>(ThunkData & 0x7FFFFFFF);
                        size_t HintNameOff = RvaToFileOffset(HintNameRva, Info.Segments);
                        Imp.Ordinal = 0;
                        if (HintNameOff > 0 && HintNameOff + 2 < FileSize) {
                            std::memcpy(&Imp.Ordinal, Raw + HintNameOff, 2);
                            char FuncBuf[256] = {};
                            size_t FnMax = std::min(static_cast<size_t>(255), FileSize - HintNameOff - 2);
                            std::memcpy(FuncBuf, Raw + HintNameOff + 2, FnMax);
                            Imp.FuncName = QString::fromLatin1(FuncBuf);
                        }
                    }

                    Info.Imports.append(Imp);
                }
            }
        }
    }

    if (DataDirs.size() > 0 && DataDirs[0].Rva != 0 && DataDirs[0].Size != 0) {
        size_t ExportOffset = RvaToFileOffset(DataDirs[0].Rva, Info.Segments);
        if (ExportOffset > 0 && ExportOffset + 40 <= FileSize) {
            uint32_t NumberOfFunctions = 0;
            std::memcpy(&NumberOfFunctions, Raw + ExportOffset + 20, 4);
            uint32_t NumberOfNames = 0;
            std::memcpy(&NumberOfNames, Raw + ExportOffset + 24, 4);
            uint32_t AddressOfFunctionsRva = 0;
            std::memcpy(&AddressOfFunctionsRva, Raw + ExportOffset + 28, 4);
            uint32_t AddressOfNamesRva = 0;
            std::memcpy(&AddressOfNamesRva, Raw + ExportOffset + 32, 4);
            uint32_t AddressOfNameOrdinalsRva = 0;
            std::memcpy(&AddressOfNameOrdinalsRva, Raw + ExportOffset + 36, 4);
            uint32_t OrdinalBase = 0;
            std::memcpy(&OrdinalBase, Raw + ExportOffset + 16, 4);

            if (NumberOfFunctions > 10000) NumberOfFunctions = 10000;
            if (NumberOfNames > 10000) NumberOfNames = 10000;

            size_t FuncTableOff = RvaToFileOffset(AddressOfFunctionsRva, Info.Segments);
            size_t NameTableOff = RvaToFileOffset(AddressOfNamesRva, Info.Segments);
            size_t OrdTableOff = RvaToFileOffset(AddressOfNameOrdinalsRva, Info.Segments);

            if (FuncTableOff > 0 && NameTableOff > 0 && OrdTableOff > 0) {
                for (uint32_t I = 0; I < NumberOfNames; ++I) {
                    if (NameTableOff + I * 4 + 4 > FileSize) break;
                    if (OrdTableOff + I * 2 + 2 > FileSize) break;

                    uint32_t FuncNameRva = 0;
                    std::memcpy(&FuncNameRva, Raw + NameTableOff + I * 4, 4);
                    uint16_t OrdIdx = 0;
                    std::memcpy(&OrdIdx, Raw + OrdTableOff + I * 2, 2);

                    uint32_t FuncRva = 0;
                    if (OrdIdx < NumberOfFunctions && FuncTableOff + OrdIdx * 4 + 4 <= FileSize) {
                        std::memcpy(&FuncRva, Raw + FuncTableOff + OrdIdx * 4, 4);
                    }

                    ExportEntry Exp;
                    Exp.Ordinal = static_cast<uint16_t>(OrdIdx + OrdinalBase);
                    Exp.Rva = FuncRva;
                    Exp.Addr = ImageBase + FuncRva;

                    size_t FnNameOff = RvaToFileOffset(FuncNameRva, Info.Segments);
                    if (FnNameOff > 0 && FnNameOff < FileSize) {
                        char ExpName[256] = {};
                        size_t NameMax = std::min(static_cast<size_t>(255), FileSize - FnNameOff);
                        std::memcpy(ExpName, Raw + FnNameOff, NameMax);
                        Exp.Name = QString::fromLatin1(ExpName);
                    }

                    Exp.IsForwarder = false;
                    if (DataDirs[0].Rva != 0 && FuncRva >= DataDirs[0].Rva &&
                        FuncRva < DataDirs[0].Rva + DataDirs[0].Size) {
                        Exp.IsForwarder = true;
                        size_t FwdOff = RvaToFileOffset(FuncRva, Info.Segments);
                        if (FwdOff > 0 && FwdOff < FileSize) {
                            char FwdBuf[256] = {};
                            size_t FwdMax = std::min(static_cast<size_t>(255), FileSize - FwdOff);
                            std::memcpy(FwdBuf, Raw + FwdOff, FwdMax);
                            Exp.ForwarderName = QString::fromLatin1(FwdBuf);
                        }
                    }

                    Info.Exports.append(Exp);
                }
            }
        }
    }

    emit LogMessage(QString("PE loaded: %1 sections, %2 imports, %3 exports, base=0x%4")
        .arg(Info.Segments.size())
        .arg(Info.Imports.size())
        .arg(Info.Exports.size())
        .arg(Info.ImageBase, 0, 16));

    Db->SetBinaryInfo(Info);
}

void AnalysisWorker::LoadElf(const QByteArray& Data) {
    if (Data.size() < 64) return;

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    size_t FileSize = static_cast<size_t>(Data.size());

    uint8_t EiClass = Raw[4];
    bool Is64 = (EiClass == 2);

    BinaryInfo Info = Db->GetBinaryInfo();
    Info.Is64Bit = Is64;
    Info.IsDll = false;
    Info.IsDriver = false;
    Info.TimeDateStamp = 0;

    if (Is64) {
        if (FileSize < 64) return;

        uint16_t EType = 0;
        std::memcpy(&EType, Raw + 16, 2);
        uint16_t EMachine = 0;
        std::memcpy(&EMachine, Raw + 18, 2);
        uint64_t EEntry = 0;
        std::memcpy(&EEntry, Raw + 24, 8);
        uint64_t EShoff = 0;
        std::memcpy(&EShoff, Raw + 40, 8);
        uint16_t EShentsize = 0;
        std::memcpy(&EShentsize, Raw + 58, 2);
        uint16_t EShnum = 0;
        std::memcpy(&EShnum, Raw + 60, 2);
        uint16_t EShstrndx = 0;
        std::memcpy(&EShstrndx, Raw + 62, 2);

        switch (EMachine) {
        case 0x3E: Info.Arch = Architecture::X64; break;
        case 0x03: Info.Arch = Architecture::X86; Info.Is64Bit = false; break;
        case 0xB7: Info.Arch = Architecture::ARM64; break;
        case 0x28: Info.Arch = Architecture::ARM; Info.Is64Bit = false; break;
        default: Info.Arch = Architecture::X64; break;
        }

        if (EType == 3) Info.IsDll = true;
        Info.EntryPoint = EEntry;
        Info.ImageBase = 0;

        QByteArray ShStrTab;
        if (EShstrndx < EShnum) {
            size_t StrSecOff = static_cast<size_t>(EShoff) + EShstrndx * EShentsize;
            if (StrSecOff + EShentsize <= FileSize) {
                uint64_t ShOffset = 0;
                std::memcpy(&ShOffset, Raw + StrSecOff + 24, 8);
                uint64_t ShSize = 0;
                std::memcpy(&ShSize, Raw + StrSecOff + 32, 8);
                if (ShOffset + ShSize <= FileSize) {
                    ShStrTab = Data.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                }
            }
        }

        Address MinAddr = UINT64_MAX;

        for (uint16_t I = 0; I < EShnum; ++I) {
            if (Cancelled.loadRelaxed()) return;
            size_t SecOff = static_cast<size_t>(EShoff) + I * EShentsize;
            if (SecOff + EShentsize > FileSize) break;

            uint32_t ShName = 0;
            std::memcpy(&ShName, Raw + SecOff, 4);
            uint32_t ShType = 0;
            std::memcpy(&ShType, Raw + SecOff + 4, 4);
            uint64_t ShFlags = 0;
            std::memcpy(&ShFlags, Raw + SecOff + 8, 8);
            uint64_t ShAddr = 0;
            std::memcpy(&ShAddr, Raw + SecOff + 16, 8);
            uint64_t ShOffset = 0;
            std::memcpy(&ShOffset, Raw + SecOff + 24, 8);
            uint64_t ShSize = 0;
            std::memcpy(&ShSize, Raw + SecOff + 32, 8);

            bool Alloc = (ShFlags & 0x2) != 0;
            if (!Alloc) continue;
            if (ShType == 0) continue;

            Segment Seg;
            if (ShName < static_cast<uint32_t>(ShStrTab.size())) {
                Seg.Name = QString::fromLatin1(ShStrTab.constData() + ShName);
            } else {
                Seg.Name = QString(".sec%1").arg(I);
            }

            Seg.VirtualAddress = ShAddr;
            Seg.VirtualSize = static_cast<size_t>(ShSize);
            Seg.RawOffset = static_cast<size_t>(ShOffset);
            Seg.Characteristics = static_cast<uint32_t>(ShFlags);

            bool Exec = (ShFlags & 0x4) != 0;
            bool Write = (ShFlags & 0x1) != 0;
            Seg.IsReadable = true;
            Seg.IsWritable = Write;
            Seg.IsExecutable = Exec;

            if (Exec) {
                Seg.Type = SegmentType::Code;
            } else if (ShType == 8) {
                Seg.Type = SegmentType::Bss;
            } else {
                Seg.Type = SegmentType::Data;
            }

            if (ShType != 8 && ShOffset + ShSize <= FileSize) {
                Seg.Data = Data.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                Seg.RawSize = static_cast<size_t>(ShSize);
            } else {
                Seg.Data = QByteArray(static_cast<int>(ShSize), '\0');
                Seg.RawSize = 0;
            }

            if (ShAddr > 0 && ShAddr < MinAddr) {
                MinAddr = ShAddr;
            }

            Info.Segments.append(Seg);
        }

        if (MinAddr != UINT64_MAX) {
            Info.ImageBase = MinAddr;
        }
        Info.ImageSize = 0;
        for (const auto& S : Info.Segments) {
            Address SegEnd = S.VirtualAddress + S.VirtualSize;
            if (SegEnd - Info.ImageBase > Info.ImageSize) {
                Info.ImageSize = static_cast<size_t>(SegEnd - Info.ImageBase);
            }
        }

        for (uint16_t I = 0; I < EShnum; ++I) {
            size_t SecOff = static_cast<size_t>(EShoff) + I * EShentsize;
            if (SecOff + EShentsize > FileSize) break;

            uint32_t ShType = 0;
            std::memcpy(&ShType, Raw + SecOff + 4, 4);

            if (ShType != 2 && ShType != 11) continue;

            uint64_t ShOffset = 0;
            std::memcpy(&ShOffset, Raw + SecOff + 24, 8);
            uint64_t ShSize = 0;
            std::memcpy(&ShSize, Raw + SecOff + 32, 8);
            uint64_t ShEntsize = 0;
            std::memcpy(&ShEntsize, Raw + SecOff + 56, 8);
            uint32_t ShLink = 0;
            std::memcpy(&ShLink, Raw + SecOff + 40, 4);

            if (ShEntsize == 0) continue;

            QByteArray SymStrTab;
            if (ShLink < EShnum) {
                size_t StrTabOff = static_cast<size_t>(EShoff) + ShLink * EShentsize;
                if (StrTabOff + EShentsize <= FileSize) {
                    uint64_t StrOff = 0;
                    std::memcpy(&StrOff, Raw + StrTabOff + 24, 8);
                    uint64_t StrSz = 0;
                    std::memcpy(&StrSz, Raw + StrTabOff + 32, 8);
                    if (StrOff + StrSz <= FileSize) {
                        SymStrTab = Data.mid(static_cast<int>(StrOff), static_cast<int>(StrSz));
                    }
                }
            }

            uint64_t SymCount = ShSize / ShEntsize;
            for (uint64_t J = 0; J < SymCount; ++J) {
                size_t SymOff = static_cast<size_t>(ShOffset + J * ShEntsize);
                if (SymOff + ShEntsize > FileSize) break;

                uint32_t StName = 0;
                std::memcpy(&StName, Raw + SymOff, 4);
                uint8_t StInfo = Raw[SymOff + 4];
                uint16_t StShndx = 0;
                std::memcpy(&StShndx, Raw + SymOff + 6, 2);
                uint64_t StValue = 0;
                std::memcpy(&StValue, Raw + SymOff + 8, 8);

                uint8_t StBind = StInfo >> 4;
                uint8_t StType = StInfo & 0xF;

                if (StName == 0 || StValue == 0) continue;
                if (StType != 1 && StType != 2) continue;

                QString SymName;
                if (StName < static_cast<uint32_t>(SymStrTab.size())) {
                    SymName = QString::fromLatin1(SymStrTab.constData() + StName);
                }
                if (SymName.isEmpty()) continue;

                if (StBind == 1 || StBind == 2) {
                    if (StShndx == 0) {
                        ImportEntry Imp;
                        Imp.DllName = QString();
                        Imp.FuncName = SymName;
                        Imp.Ordinal = 0;
                        Imp.IatAddress = StValue;
                        Imp.ThunkAddress = StValue;
                        Imp.IsBound = false;
                        Info.Imports.append(Imp);
                    } else {
                        ExportEntry Exp;
                        Exp.Name = SymName;
                        Exp.Ordinal = 0;
                        Exp.Addr = StValue;
                        Exp.Rva = static_cast<uint32_t>(StValue - Info.ImageBase);
                        Exp.IsForwarder = false;
                        Info.Exports.append(Exp);
                    }
                }
            }
        }
    } else {
        if (FileSize < 52) return;

        uint16_t EMachine = 0;
        std::memcpy(&EMachine, Raw + 18, 2);
        uint32_t EEntry = 0;
        std::memcpy(&EEntry, Raw + 24, 4);
        uint32_t EShoff = 0;
        std::memcpy(&EShoff, Raw + 32, 4);
        uint16_t EShentsize = 0;
        std::memcpy(&EShentsize, Raw + 46, 2);
        uint16_t EShnum = 0;
        std::memcpy(&EShnum, Raw + 48, 2);
        uint16_t EShstrndx = 0;
        std::memcpy(&EShstrndx, Raw + 50, 2);

        switch (EMachine) {
        case 0x03: Info.Arch = Architecture::X86; break;
        case 0x28: Info.Arch = Architecture::ARM; break;
        default: Info.Arch = Architecture::X86; break;
        }

        Info.EntryPoint = EEntry;
        Info.ImageBase = 0;

        QByteArray ShStrTab;
        if (EShstrndx < EShnum) {
            size_t StrSecOff = EShoff + EShstrndx * EShentsize;
            if (StrSecOff + EShentsize <= FileSize) {
                uint32_t ShOff = 0;
                std::memcpy(&ShOff, Raw + StrSecOff + 16, 4);
                uint32_t ShSz = 0;
                std::memcpy(&ShSz, Raw + StrSecOff + 20, 4);
                if (ShOff + ShSz <= FileSize) {
                    ShStrTab = Data.mid(static_cast<int>(ShOff), static_cast<int>(ShSz));
                }
            }
        }

        Address MinAddr = UINT64_MAX;

        for (uint16_t I = 0; I < EShnum; ++I) {
            if (Cancelled.loadRelaxed()) return;
            size_t SecOff = EShoff + I * EShentsize;
            if (SecOff + EShentsize > FileSize) break;

            uint32_t ShName = 0;
            std::memcpy(&ShName, Raw + SecOff, 4);
            uint32_t ShType = 0;
            std::memcpy(&ShType, Raw + SecOff + 4, 4);
            uint32_t ShFlags = 0;
            std::memcpy(&ShFlags, Raw + SecOff + 8, 4);
            uint32_t ShAddr = 0;
            std::memcpy(&ShAddr, Raw + SecOff + 12, 4);
            uint32_t ShOffset = 0;
            std::memcpy(&ShOffset, Raw + SecOff + 16, 4);
            uint32_t ShSize = 0;
            std::memcpy(&ShSize, Raw + SecOff + 20, 4);

            bool Alloc = (ShFlags & 0x2) != 0;
            if (!Alloc) continue;
            if (ShType == 0) continue;

            Segment Seg;
            if (ShName < static_cast<uint32_t>(ShStrTab.size())) {
                Seg.Name = QString::fromLatin1(ShStrTab.constData() + ShName);
            } else {
                Seg.Name = QString(".sec%1").arg(I);
            }

            Seg.VirtualAddress = ShAddr;
            Seg.VirtualSize = ShSize;
            Seg.RawOffset = ShOffset;
            Seg.Characteristics = ShFlags;

            bool Exec = (ShFlags & 0x4) != 0;
            bool Write = (ShFlags & 0x1) != 0;
            Seg.IsReadable = true;
            Seg.IsWritable = Write;
            Seg.IsExecutable = Exec;
            Seg.Type = Exec ? SegmentType::Code : (ShType == 8 ? SegmentType::Bss : SegmentType::Data);

            if (ShType != 8 && ShOffset + ShSize <= FileSize) {
                Seg.Data = Data.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                Seg.RawSize = ShSize;
            } else {
                Seg.Data = QByteArray(static_cast<int>(ShSize), '\0');
                Seg.RawSize = 0;
            }

            if (ShAddr > 0 && ShAddr < MinAddr) MinAddr = ShAddr;
            Info.Segments.append(Seg);
        }

        if (MinAddr != UINT64_MAX) Info.ImageBase = MinAddr;
        Info.ImageSize = 0;
        for (const auto& S : Info.Segments) {
            Address SegEnd = S.VirtualAddress + S.VirtualSize;
            if (SegEnd - Info.ImageBase > Info.ImageSize) {
                Info.ImageSize = static_cast<size_t>(SegEnd - Info.ImageBase);
            }
        }
    }

    emit LogMessage(QString("ELF loaded: %1 sections, %2 imports, %3 exports, entry=0x%4")
        .arg(Info.Segments.size())
        .arg(Info.Imports.size())
        .arg(Info.Exports.size())
        .arg(Info.EntryPoint, 0, 16));

    Db->SetBinaryInfo(Info);
}

void AnalysisWorker::AddDisassemblyTarget(Address Addr) {
    if (VisitedAddresses.contains(Addr)) return;
    if (!Db->IsAddressValid(Addr)) return;
    DisassemblyQueue.append(Addr);
}

void AnalysisWorker::ParsePdata() {
    BinaryInfo Info = Db->GetBinaryInfo();
    if (!Info.Is64Bit) return;

    const Segment* PdataSeg = nullptr;
    for (const auto& Seg : Info.Segments) {
        if (Seg.Name == ".pdata") {
            PdataSeg = &Seg;
            break;
        }
    }

    if (!PdataSeg || PdataSeg->Data.isEmpty()) return;

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(PdataSeg->Data.constData());
    size_t DataSize = static_cast<size_t>(PdataSeg->Data.size());
    int EntryCount = static_cast<int>(DataSize / 12);
    int ValidCount = 0;

    for (int I = 0; I < EntryCount; ++I) {
        if (Cancelled.loadRelaxed()) return;

        size_t Off = I * 12;
        if (Off + 12 > DataSize) break;

        uint32_t BeginRva = 0, EndRva = 0;
        std::memcpy(&BeginRva, Raw + Off, 4);
        std::memcpy(&EndRva, Raw + Off + 4, 4);

        if (BeginRva == 0 || EndRva == 0) continue;
        if (EndRva <= BeginRva) continue;
        if (EndRva - BeginRva > 0x1000000) continue;

        Address FuncStart = Info.ImageBase + BeginRva;
        Address FuncEnd = Info.ImageBase + EndRva;

        if (!Db->IsAddressValid(FuncStart)) continue;

        FunctionStarts.insert(FuncStart);

        AnalyzedFunction Func;
        Func.Name = QString("sub_%1").arg(FuncStart, 0, 16);
        Func.Start = FuncStart;
        Func.End = FuncEnd;
        Func.Size = EndRva - BeginRva;
        Func.InstructionCount = 0;
        Func.BasicBlockCount = 0;
        Func.StackFrameSize = 0;
        Func.ArgCount = 0;
        Func.IsImported = false;
        Func.IsExported = false;
        Func.IsThunk = false;

        for (const auto& Exp : Info.Exports) {
            if (Exp.Addr == FuncStart) {
                Func.Name = Exp.Name;
                Func.IsExported = true;
                break;
            }
        }

        Db->AddFunction(Func);
        ValidCount++;

        if (ValidCount % 10000 == 0) {
            EmitProgress(AnalysisState::Loading, 5,
                QString("Parsed %1/%2 .pdata entries (%3 functions)")
                    .arg(I).arg(EntryCount).arg(ValidCount));
        }
    }

    emit LogMessage(QString(".pdata: %1 entries, %2 valid functions").arg(EntryCount).arg(ValidCount));
}

void AnalysisWorker::AddDisassemblyTargetMT(Address Addr) {
    if (QueuedSetMT.contains(Addr)) return;
    QueuedSetMT.insert(Addr);
    QueueMT.append(Addr);
}

void AnalysisWorker::DisassembleFromMT(Address Start, size_t CsHandle) {
    csh Handle = static_cast<csh>(CsHandle);

    {
        QMutexLocker Locker(&QueueMutex);
        if (VisitedMT.contains(Start)) return;
    }
    if (!Db->IsAddressValid(Start)) return;
    if (Db->HasInstruction(Start)) return;

    Address CurrentAddr = Start;
    constexpr size_t ChunkSize = 4096;
    constexpr int MaxInsnsPerRun = 50000;
    int InsnsThisRun = 0;

    while (InsnsThisRun < MaxInsnsPerRun) {
        if (Cancelled.loadRelaxed()) break;

        {
            QMutexLocker Locker(&QueueMutex);
            if (VisitedMT.contains(CurrentAddr)) break;
        }
        if (!Db->IsAddressValid(CurrentAddr)) break;
        if (Db->HasInstruction(CurrentAddr)) break;

        QByteArray Bytes = Db->ReadBytes(CurrentAddr, ChunkSize);
        if (Bytes.isEmpty()) break;

        cs_insn* Insns = nullptr;
        size_t Count = cs_disasm(Handle,
            reinterpret_cast<const uint8_t*>(Bytes.constData()),
            static_cast<size_t>(Bytes.size()),
            CurrentAddr, 0, &Insns);

        if (Count == 0) {
            QMutexLocker Locker(&QueueMutex);
            VisitedMT.insert(CurrentAddr);
            break;
        }

        bool StopFlow = false;

        for (size_t I = 0; I < Count && !StopFlow; ++I) {
            Address InsnAddr = Insns[I].address;

            {
                QMutexLocker Locker(&QueueMutex);
                if (VisitedMT.contains(InsnAddr)) { StopFlow = true; break; }
                VisitedMT.insert(InsnAddr);
            }
            if (Db->HasInstruction(InsnAddr)) { StopFlow = true; break; }

            AnalyzedInstruction Ai;
            Ai.Addr = InsnAddr;
            std::memcpy(Ai.Bytes, Insns[I].bytes, std::min(static_cast<size_t>(Insns[I].size), static_cast<size_t>(15)));
            Ai.Size = static_cast<uint8_t>(Insns[I].size);
            Ai.Mnemonic = QString::fromUtf8(Insns[I].mnemonic);
            Ai.Operands = QString::fromUtf8(Insns[I].op_str);
            Ai.Comment = QString();
            Ai.BranchTarget = 0;
            Ai.MemoryRef = 0;

            QString Mn = Ai.Mnemonic.toLower();
            Ai.IsCall = Mn.startsWith("call");
            Ai.IsRet = (Mn == "ret" || Mn == "retn" || Mn == "retf");
            Ai.IsNop = (Mn == "nop");
            Ai.IsPush = Mn.startsWith("push");
            Ai.IsPop = Mn.startsWith("pop");
            Ai.IsJump = Mn.startsWith('j') || Mn == "jmp";
            Ai.IsConditional = Ai.IsJump && Mn != "jmp";

            cs_detail* Detail = Insns[I].detail;
            if (Detail) {
                cs_x86* X86 = &Detail->x86;
                for (uint8_t OpIdx = 0; OpIdx < X86->op_count; ++OpIdx) {
                    cs_x86_op* Op = &X86->operands[OpIdx];
                    if (Op->type == X86_OP_IMM && (Ai.IsCall || Ai.IsJump)) {
                        Ai.BranchTarget = static_cast<Address>(Op->imm);
                    }
                    if (Op->type == X86_OP_MEM) {
                        if (Op->mem.base == X86_REG_RIP || Op->mem.base == X86_REG_EIP) {
                            Address NextAddr = InsnAddr + Insns[I].size;
                            Ai.MemoryRef = static_cast<Address>(static_cast<int64_t>(NextAddr) + Op->mem.disp);
                        } else if (Op->mem.base == X86_REG_INVALID && Op->mem.index == X86_REG_INVALID && Op->mem.disp != 0) {
                            Ai.MemoryRef = static_cast<Address>(Op->mem.disp);
                        }
                    }
                }
            }

            Db->AddInstruction(Ai);
            Db->SetItemType(InsnAddr, ItemType::Code);
            InsnsThisRun++;
            TotalDisasmMT.fetchAndAddRelaxed(1);

            if (Ai.IsCall && Ai.BranchTarget != 0) {
                QMutexLocker Locker(&QueueMutex);
                FunctionStarts.insert(Ai.BranchTarget);
                if (!VisitedMT.contains(Ai.BranchTarget) && !QueuedSetMT.contains(Ai.BranchTarget)) {
                    AddDisassemblyTargetMT(Ai.BranchTarget);
                }
            }

            if (Ai.IsJump && !Ai.IsConditional) {
                if (Ai.BranchTarget != 0) {
                    QMutexLocker Locker(&QueueMutex);
                    if (!VisitedMT.contains(Ai.BranchTarget) && !QueuedSetMT.contains(Ai.BranchTarget)) {
                        AddDisassemblyTargetMT(Ai.BranchTarget);
                    }
                }
                StopFlow = true;
            } else if (Ai.IsConditional && Ai.BranchTarget != 0) {
                QMutexLocker Locker(&QueueMutex);
                if (!VisitedMT.contains(Ai.BranchTarget) && !QueuedSetMT.contains(Ai.BranchTarget)) {
                    AddDisassemblyTargetMT(Ai.BranchTarget);
                }
            }

            if (Ai.IsRet) StopFlow = true;
            if (Ai.Mnemonic == "int3" || Ai.Mnemonic == "hlt" || Ai.Mnemonic == "ud2") StopFlow = true;
        }

        Address LastAddr = Insns[Count - 1].address;
        Address NextLinear = LastAddr + Insns[Count - 1].size;
        cs_free(Insns, Count);

        if (StopFlow) break;
        CurrentAddr = NextLinear;
    }
}

void AnalysisWorker::RunRecursiveDescentMT() {
    BinaryInfo Info = Db->GetBinaryInfo();

    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

    switch (Info.Arch) {
    case Architecture::ARM:
        CsArch = CS_ARCH_ARM;
        CsMode = CS_MODE_ARM;
        break;
    case Architecture::ARM64:
        CsArch = CS_ARCH_ARM64;
        CsMode = CS_MODE_ARM;
        break;
    default:
        break;
    }

    TotalDisasmMT.storeRelaxed(0);

    {
        QMutexLocker Locker(&QueueMutex);
        if (Info.EntryPoint != 0) {
            AddDisassemblyTargetMT(Info.EntryPoint);
            FunctionStarts.insert(Info.EntryPoint);
        }
        for (const auto& Exp : Info.Exports) {
            if (Exp.Addr != 0 && !Exp.IsForwarder) {
                AddDisassemblyTargetMT(Exp.Addr);
                FunctionStarts.insert(Exp.Addr);
            }
        }
        for (Address FuncAddr : FunctionStarts) {
            if (QueuedSetMT.contains(FuncAddr)) continue;
            QByteArray Bytes = Db->ReadBytes(FuncAddr, 4);
            if (Bytes.size() >= 4) {
                uint8_t First = static_cast<uint8_t>(Bytes[0]);
                if (First != 0x00 && First != 0xCC && First != 0x90) {
                    AddDisassemblyTargetMT(FuncAddr);
                }
            }
        }
    }

    int NumThreads = QThread::idealThreadCount();
    if (NumThreads < 2) NumThreads = 2;
    if (NumThreads > 16) NumThreads = 16;

    NumThreads = NumThreads - 1;
    if (NumThreads < 2) NumThreads = 2;
    if (NumThreads > 12) NumThreads = 12;

    emit LogMessage(QString("Starting %1 disassembly threads").arg(NumThreads));

    QList<QFuture<void>> Futures;

    for (int T = 0; T < NumThreads; ++T) {
        QFuture<void> Future = QtConcurrent::run([this, CsArch, CsMode]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
            csh Handle;
            if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

            while (!Cancelled.loadRelaxed()) {
                Address Target = 0;
                {
                    QMutexLocker Locker(&QueueMutex);
                    while (!QueueMT.isEmpty()) {
                        Target = QueueMT.takeFirst();
                        if (!VisitedMT.contains(Target)) break;
                        Target = 0;
                    }
                }

                if (Target == 0) {
                    QThread::msleep(1);
                    bool StillWorking = false;
                    {
                        QMutexLocker Locker(&QueueMutex);
                        StillWorking = !QueueMT.isEmpty();
                    }
                    if (!StillWorking) {
                        QThread::msleep(5);
                        QMutexLocker Locker(&QueueMutex);
                        if (QueueMT.isEmpty()) break;
                    }
                    continue;
                }

                DisassembleFromMT(Target, static_cast<size_t>(Handle));
            }

            cs_close(&Handle);
        });
        Futures.append(Future);
    }

    int LastReported = 0;
    while (true) {
        bool AllDone = true;
        for (const auto& F : Futures) {
            if (!F.isFinished()) { AllDone = false; break; }
        }
        if (AllDone) break;

        int Current = TotalDisasmMT.loadRelaxed();
        if (Current - LastReported >= 1000) {
            int QueueSize = 0;
            {
                QMutexLocker Locker(&QueueMutex);
                QueueSize = QueueMT.size();
            }
            EmitProgress(AnalysisState::Disassembling,
                10 + std::min(30, Current / 100),
                QString("Disassembled %1 instructions, %2 targets queued (%3 threads)")
                    .arg(Current).arg(QueueSize).arg(NumThreads));
            LastReported = Current;
        }
        QThread::msleep(50);
    }

    for (auto& F : Futures) {
        F.waitForFinished();
    }

    emit LogMessage(QString("Recursive descent complete: %1 instructions (%2 threads)")
        .arg(Db->InstructionCount()).arg(NumThreads));
}

void AnalysisWorker::RunRecursiveDescent() {
    BinaryInfo Info = Db->GetBinaryInfo();

    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

    switch (Info.Arch) {
    case Architecture::X86:
    case Architecture::X64:
        CsArch = CS_ARCH_X86;
        break;
    case Architecture::ARM:
        CsArch = CS_ARCH_ARM;
        CsMode = CS_MODE_ARM;
        break;
    case Architecture::ARM64:
        CsArch = CS_ARCH_ARM64;
        CsMode = CS_MODE_ARM;
        break;
    default:
        break;
    }

    csh Handle;
    if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) {
        emit LogMessage("Failed to init Capstone");
        return;
    }
    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

    if (Info.EntryPoint != 0) {
        AddDisassemblyTarget(Info.EntryPoint);
        FunctionStarts.insert(Info.EntryPoint);
    }

    for (const auto& Exp : Info.Exports) {
        if (Exp.Addr != 0 && !Exp.IsForwarder) {
            AddDisassemblyTarget(Exp.Addr);
            FunctionStarts.insert(Exp.Addr);
        }
    }

    int PdataSeeded = 0;
    for (Address FuncAddr : FunctionStarts) {
        if (VisitedAddresses.contains(FuncAddr)) continue;
        if (DisassemblyQueue.contains(FuncAddr)) continue;

        QByteArray Bytes = Db->ReadBytes(FuncAddr, 4);
        if (Bytes.size() >= 4) {
            uint8_t First = static_cast<uint8_t>(Bytes[0]);
            if (First != 0x00 && First != 0xCC && First != 0x90) {
                AddDisassemblyTarget(FuncAddr);
                PdataSeeded++;
            }
        }
    }

    if (PdataSeeded > 0) {
        emit LogMessage(QString("Seeded %1 .pdata functions for disassembly").arg(PdataSeeded));
    }

    int TotalDisassembled = 0;

    while (!DisassemblyQueue.isEmpty()) {
        if (Cancelled.loadRelaxed()) break;

        Address StartAddr = DisassemblyQueue.takeFirst();
        if (VisitedAddresses.contains(StartAddr)) continue;

        DisassembleFrom(StartAddr);

        TotalDisassembled = Db->InstructionCount();
        if (TotalDisassembled % 1000 == 0) {
            EmitProgress(AnalysisState::Disassembling,
                10 + std::min(30, TotalDisassembled / 100),
                QString("Disassembled %1 instructions, %2 targets queued")
                    .arg(TotalDisassembled)
                    .arg(DisassemblyQueue.size()));
        }
    }

    cs_close(&Handle);

    emit LogMessage(QString("Recursive descent complete: %1 instructions").arg(Db->InstructionCount()));
}

void AnalysisWorker::DisassembleFrom(Address Start) {
    if (VisitedAddresses.contains(Start)) return;
    if (!Db->IsAddressValid(Start)) return;

    BinaryInfo Info = Db->GetBinaryInfo();

    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

    switch (Info.Arch) {
    case Architecture::ARM:
        CsArch = CS_ARCH_ARM;
        CsMode = CS_MODE_ARM;
        break;
    case Architecture::ARM64:
        CsArch = CS_ARCH_ARM64;
        CsMode = CS_MODE_ARM;
        break;
    default:
        break;
    }

    csh Handle;
    if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

    Address CurrentAddr = Start;
    constexpr size_t ChunkSize = 4096;
    constexpr int MaxInsnsPerRun = 50000;
    int InsnsThisRun = 0;

    while (InsnsThisRun < MaxInsnsPerRun) {
        if (Cancelled.loadRelaxed()) break;
        if (VisitedAddresses.contains(CurrentAddr)) break;
        if (!Db->IsAddressValid(CurrentAddr)) break;
        if (Db->HasInstruction(CurrentAddr)) break;

        QByteArray Bytes = Db->ReadBytes(CurrentAddr, ChunkSize);
        if (Bytes.isEmpty()) break;

        cs_insn* Insns = nullptr;
        size_t Count = cs_disasm(Handle,
            reinterpret_cast<const uint8_t*>(Bytes.constData()),
            static_cast<size_t>(Bytes.size()),
            CurrentAddr, 0, &Insns);

        if (Count == 0) {
            VisitedAddresses.insert(CurrentAddr);
            break;
        }

        bool StopFlow = false;

        for (size_t I = 0; I < Count && !StopFlow; ++I) {
            Address InsnAddr = Insns[I].address;
            if (VisitedAddresses.contains(InsnAddr)) { StopFlow = true; break; }
            if (Db->HasInstruction(InsnAddr)) { StopFlow = true; break; }

            VisitedAddresses.insert(InsnAddr);

            AnalyzedInstruction Ai;
            Ai.Addr = InsnAddr;
            std::memcpy(Ai.Bytes, Insns[I].bytes, std::min(static_cast<size_t>(Insns[I].size), static_cast<size_t>(15)));
            Ai.Size = static_cast<uint8_t>(Insns[I].size);
            Ai.Mnemonic = QString::fromUtf8(Insns[I].mnemonic);
            Ai.Operands = QString::fromUtf8(Insns[I].op_str);
            Ai.Comment = QString();
            Ai.BranchTarget = 0;
            Ai.MemoryRef = 0;

            QString Mn = Ai.Mnemonic.toLower();
            Ai.IsCall = Mn.startsWith("call");
            Ai.IsRet = (Mn == "ret" || Mn == "retn" || Mn == "retf");
            Ai.IsNop = (Mn == "nop");
            Ai.IsPush = Mn.startsWith("push");
            Ai.IsPop = Mn.startsWith("pop");
            Ai.IsJump = Mn.startsWith('j') || Mn == "jmp";
            Ai.IsConditional = Ai.IsJump && Mn != "jmp";

            cs_detail* Detail = Insns[I].detail;
            if (Detail && CsArch == CS_ARCH_X86) {
                cs_x86* X86 = &Detail->x86;
                for (uint8_t OpIdx = 0; OpIdx < X86->op_count; ++OpIdx) {
                    cs_x86_op* Op = &X86->operands[OpIdx];
                    if (Op->type == X86_OP_IMM && (Ai.IsCall || Ai.IsJump)) {
                        Ai.BranchTarget = static_cast<Address>(Op->imm);
                    }
                    if (Op->type == X86_OP_MEM) {
                        if (Op->mem.base == X86_REG_RIP || Op->mem.base == X86_REG_EIP) {
                            Address NextAddr = InsnAddr + Insns[I].size;
                            Ai.MemoryRef = static_cast<Address>(static_cast<int64_t>(NextAddr) + Op->mem.disp);
                        } else if (Op->mem.base == X86_REG_INVALID && Op->mem.index == X86_REG_INVALID && Op->mem.disp != 0) {
                            Ai.MemoryRef = static_cast<Address>(Op->mem.disp);
                        }
                    }
                }
            }

            Db->AddInstruction(Ai);
            Db->SetItemType(InsnAddr, ItemType::Code);
            InsnsThisRun++;

            if (Ai.IsCall && Ai.BranchTarget != 0) {
                FunctionStarts.insert(Ai.BranchTarget);
                AddDisassemblyTarget(Ai.BranchTarget);
            }

            if (Ai.IsJump && !Ai.IsConditional) {
                if (Ai.BranchTarget != 0) {
                    AddDisassemblyTarget(Ai.BranchTarget);
                }
                StopFlow = true;
            } else if (Ai.IsConditional && Ai.BranchTarget != 0) {
                AddDisassemblyTarget(Ai.BranchTarget);
            }

            if (Ai.IsRet) {
                StopFlow = true;
            }

            if (Ai.Mnemonic == "int3" || Ai.Mnemonic == "hlt" || Ai.Mnemonic == "ud2") {
                StopFlow = true;
            }
        }

        Address LastAddr = Insns[Count - 1].address;
        Address NextLinear = LastAddr + Insns[Count - 1].size;
        cs_free(Insns, Count);

        if (StopFlow) break;
        CurrentAddr = NextLinear;
    }

    cs_close(&Handle);
}

void AnalysisWorker::FindFunctions() {
    BinaryInfo Info = Db->GetBinaryInfo();

    for (Address Addr : FunctionStarts) {
        if (Cancelled.loadRelaxed()) return;
        if (Db->HasFunction(Addr)) continue;
        if (!Db->HasInstruction(Addr)) continue;

        AnalyzedFunction Func;
        Func.Name = QString("sub_%1").arg(Addr, 0, 16);
        Func.Start = Addr;
        Func.End = Addr;
        Func.Size = 0;
        Func.InstructionCount = 0;
        Func.BasicBlockCount = 0;
        Func.StackFrameSize = 0;
        Func.ArgCount = 0;
        Func.IsImported = false;
        Func.IsExported = false;
        Func.IsThunk = false;

        Db->AddFunction(Func);
    }

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;
        if (Seg.Data.isEmpty()) continue;

        const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        size_t SSize = static_cast<size_t>(Seg.Data.size());

        for (size_t Off = 0; Off + 4 <= SSize; ++Off) {
            Address Addr = Seg.VirtualAddress + Off;
            if (Db->HasFunction(Addr)) continue;

            bool FoundPrologue = false;

            if (Info.Is64Bit) {
                if (Off + 4 <= SSize &&
                    SData[Off] == 0x55 && SData[Off+1] == 0x48 &&
                    SData[Off+2] == 0x89 && SData[Off+3] == 0xE5) {
                    FoundPrologue = true;
                }
                if (!FoundPrologue && Off + 3 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x83 && SData[Off+2] == 0xEC) {
                    FoundPrologue = true;
                }
                if (!FoundPrologue && Off + 4 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x89 &&
                    SData[Off+2] == 0x5C && SData[Off+3] == 0x24) {
                    FoundPrologue = true;
                }
                if (!FoundPrologue && Off + 2 <= SSize &&
                    SData[Off] == 0x40 &&
                    (SData[Off+1] == 0x53 || SData[Off+1] == 0x55 ||
                     SData[Off+1] == 0x56 || SData[Off+1] == 0x57)) {
                    FoundPrologue = true;
                }
            } else {
                if (Off + 3 <= SSize &&
                    SData[Off] == 0x55 && SData[Off+1] == 0x89 && SData[Off+2] == 0xE5) {
                    FoundPrologue = true;
                }
                if (!FoundPrologue && Off + 1 <= SSize &&
                    SData[Off] == 0x55) {
                    if (Off + 3 <= SSize && SData[Off+1] == 0x8B && SData[Off+2] == 0xEC) {
                        FoundPrologue = true;
                    }
                }
            }

            if (FoundPrologue && Db->HasInstruction(Addr)) {
                AnalyzedFunction Func;
                Func.Name = QString("sub_%1").arg(Addr, 0, 16);
                Func.Start = Addr;
                Func.End = Addr;
                Func.Size = 0;
                Func.InstructionCount = 0;
                Func.BasicBlockCount = 0;
                Func.StackFrameSize = 0;
                Func.ArgCount = 0;
                Func.IsImported = false;
                Func.IsExported = false;
                Func.IsThunk = false;
                Db->AddFunction(Func);
            }
        }
    }

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    std::sort(AllFuncs.begin(), AllFuncs.end(), [](const AnalyzedFunction& A, const AnalyzedFunction& B) {
        return A.Start < B.Start;
    });

    for (int I = 0; I < AllFuncs.size(); ++I) {
        if (Cancelled.loadRelaxed()) return;

        Address FuncStart = AllFuncs[I].Start;
        Address FuncEnd = FuncStart;

        Address Limit = 0;
        if (I + 1 < AllFuncs.size()) {
            Limit = AllFuncs[I + 1].Start;
        }

        QList<AnalyzedInstruction> FuncInsns = Db->GetInstructions(FuncStart,
            Limit > 0 ? Limit : FuncStart + 0x10000);

        int InsnCount = 0;
        for (const auto& Insn : FuncInsns) {
            if (Insn.Addr < FuncStart) continue;
            if (Limit > 0 && Insn.Addr >= Limit) break;

            InsnCount++;
            Address InsnEnd = Insn.Addr + Insn.Size;
            if (InsnEnd > FuncEnd) FuncEnd = InsnEnd;

            if (Insn.IsRet) break;
        }

        AnalyzedFunction Updated = AllFuncs[I];
        Updated.End = FuncEnd;
        Updated.Size = static_cast<size_t>(FuncEnd - FuncStart);
        Updated.InstructionCount = InsnCount;
        Db->UpdateFunction(FuncStart, Updated);
    }

    emit LogMessage(QString("Found %1 functions").arg(Db->FunctionCount()));
}

void AnalysisWorker::FindStrings() {
    BinaryInfo Info = Db->GetBinaryInfo();
    QAtomicInt StringsFound(0);

    QList<const Segment*> SegPtrs;
    for (const Segment& Seg : Info.Segments) {
        if (Seg.Data.isEmpty()) continue;
        if (Seg.IsExecutable && Seg.Type == SegmentType::Code) continue;
        SegPtrs.append(&Seg);
    }

    QList<QFuture<void>> Futures;

    for (const Segment* SegPtr : SegPtrs) {
        QFuture<void> Future = QtConcurrent::run([this, SegPtr, &StringsFound]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
            const Segment& Seg = *SegPtr;
            const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
            size_t SSize = static_cast<size_t>(Seg.Data.size());

            for (size_t Off = 0; Off < SSize; ) {
                if (Cancelled.loadRelaxed()) return;

                Address Addr = Seg.VirtualAddress + Off;

                if (Db->GetItemType(Addr) == ItemType::Code) {
                    Off++;
                    continue;
                }

                int AsciiLen = 0;
                if (IsAsciiString(SData + Off, SSize - Off, AsciiLen)) {
                    AnalyzedString Str;
                    Str.Addr = Addr;
                    Str.Value = QString::fromLatin1(reinterpret_cast<const char*>(SData + Off), AsciiLen);
                    Str.IsWide = false;
                    Str.Length = AsciiLen;
                    Db->AddString(Str);
                    Db->SetItemType(Addr, ItemType::String);
                    StringsFound.fetchAndAddRelaxed(1);
                    Off += AsciiLen + 1;
                    continue;
                }

                int WideLen = 0;
                if (Off + 1 < SSize && IsWideString(SData + Off, SSize - Off, WideLen)) {
                    AnalyzedString Str;
                    Str.Addr = Addr;
                    Str.Value = QString::fromUtf16(reinterpret_cast<const char16_t*>(SData + Off), WideLen);
                    Str.IsWide = true;
                    Str.Length = WideLen;
                    Db->AddString(Str);
                    Db->SetItemType(Addr, ItemType::WideString);
                    StringsFound.fetchAndAddRelaxed(1);
                    Off += (WideLen + 1) * 2;
                    continue;
                }

                Off++;
            }
        });
        Futures.append(Future);
    }

    for (auto& F : Futures) {
        F.waitForFinished();
    }

    emit LogMessage(QString("Found %1 strings (%2 segments parallel)")
        .arg(StringsFound.loadRelaxed()).arg(SegPtrs.size()));
}

bool AnalysisWorker::IsAsciiString(const uint8_t* Data, size_t MaxLen, int& OutLen) {
    OutLen = 0;
    for (size_t I = 0; I < MaxLen && I < 4096; ++I) {
        uint8_t Byte = Data[I];
        if (Byte == 0) {
            if (OutLen >= 4) return true;
            return false;
        }
        if (Byte >= 0x20 && Byte <= 0x7E) {
            OutLen++;
        } else if (Byte == '\t' || Byte == '\n' || Byte == '\r') {
            OutLen++;
        } else {
            return false;
        }
    }
    return false;
}

bool AnalysisWorker::IsWideString(const uint8_t* Data, size_t MaxLen, int& OutLen) {
    OutLen = 0;
    if (MaxLen < 4) return false;

    for (size_t I = 0; I + 1 < MaxLen && I < 8192; I += 2) {
        uint16_t Wchar = 0;
        std::memcpy(&Wchar, Data + I, 2);

        if (Wchar == 0) {
            if (OutLen >= 4) return true;
            return false;
        }

        if ((Wchar >= 0x20 && Wchar <= 0x7E) || Wchar == '\t' || Wchar == '\n' || Wchar == '\r') {
            OutLen++;
        } else if (Wchar > 0x7E && Wchar < 0xD800) {
            OutLen++;
        } else {
            return false;
        }
    }
    return false;
}

void AnalysisWorker::BuildXrefs() {
    QMap<Address, QString> AllNames = Db->GetAllNames();
    BinaryInfo Info = Db->GetBinaryInfo();
    int XrefCount = 0;

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Insn.IsCall && Insn.BranchTarget != 0) {
                Xref Ref;
                Ref.From = Insn.Addr;
                Ref.To = Insn.BranchTarget;
                Ref.Type = XrefType::CodeCall;
                Db->AddXref(Ref);
                XrefCount++;
            } else if (Insn.IsJump && !Insn.IsConditional && Insn.BranchTarget != 0) {
                Xref Ref;
                Ref.From = Insn.Addr;
                Ref.To = Insn.BranchTarget;
                Ref.Type = XrefType::CodeJump;
                Db->AddXref(Ref);
                XrefCount++;
            } else if (Insn.IsConditional && Insn.BranchTarget != 0) {
                Xref Ref;
                Ref.From = Insn.Addr;
                Ref.To = Insn.BranchTarget;
                Ref.Type = XrefType::CodeCondJump;
                Db->AddXref(Ref);
                XrefCount++;
            }

            if (Insn.MemoryRef != 0 && Db->IsAddressValid(Insn.MemoryRef)) {
                Xref Ref;
                Ref.From = Insn.Addr;
                Ref.To = Insn.MemoryRef;
                Ref.Type = Insn.Mnemonic.contains("lea") ? XrefType::DataOffset : XrefType::DataRead;
                Db->AddXref(Ref);
                XrefCount++;
            }
        }
    }

    emit LogMessage(QString("Built %1 cross-references").arg(XrefCount));
}

void AnalysisWorker::FindStringReferences() {
    QList<AnalyzedString> AllStrings = Db->GetAllStrings();
    QMap<Address, int> StringAddrMap;
    for (int I = 0; I < AllStrings.size(); ++I) {
        StringAddrMap[AllStrings[I].Addr] = I;
    }

    BinaryInfo Info = Db->GetBinaryInfo();

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Insn.MemoryRef != 0 && StringAddrMap.contains(Insn.MemoryRef)) {
                int Idx = StringAddrMap[Insn.MemoryRef];
                AllStrings[Idx].References.append(Insn.Addr);

                AnalyzedInstruction Modified = Insn;
                Modified.Comment = QString("\"%1\"").arg(AllStrings[Idx].Value.left(60));
                Db->AddInstruction(Modified);
            }
        }
    }

    for (const auto& Str : AllStrings) {
        if (!Str.References.isEmpty()) {
            Db->AddString(Str);
        }
    }
}

void AnalysisWorker::NameImportsExports() {
    BinaryInfo Info = Db->GetBinaryInfo();

    for (const auto& Imp : Info.Imports) {
        if (Imp.IatAddress != 0 && !Imp.FuncName.isEmpty()) {
            QString FullName;
            if (!Imp.DllName.isEmpty()) {
                QString ShortDll = Imp.DllName;
                if (ShortDll.endsWith(".dll", Qt::CaseInsensitive)) {
                    ShortDll = ShortDll.left(ShortDll.size() - 4);
                }
                FullName = ShortDll + "." + Imp.FuncName;
            } else {
                FullName = Imp.FuncName;
            }
            Db->SetName(Imp.IatAddress, FullName);
        }
    }

    for (const auto& Exp : Info.Exports) {
        if (Exp.Addr != 0 && !Exp.Name.isEmpty()) {
            Db->SetName(Exp.Addr, Exp.Name);
            if (Db->HasFunction(Exp.Addr)) {
                AnalyzedFunction Func = Db->GetFunction(Exp.Addr);
                Func.Name = Exp.Name;
                Func.IsExported = true;
                Db->UpdateFunction(Exp.Addr, Func);
            }
        }
    }

    if (Info.EntryPoint != 0) {
        Db->SetName(Info.EntryPoint, "entry_point");
        if (Db->HasFunction(Info.EntryPoint)) {
            AnalyzedFunction Func = Db->GetFunction(Info.EntryPoint);
            Func.Name = "entry_point";
            Db->UpdateFunction(Info.EntryPoint, Func);
        }
    }
}

void AnalysisWorker::AnalyzeFunctions() {
    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    int Total = AllFuncs.size();
    QAtomicInt Done(0);

    int BatchSize = std::max(1, Total / (QThread::idealThreadCount() * 4));
    QList<QFuture<void>> Futures;

    for (int Start = 0; Start < Total; Start += BatchSize) {
        int End = std::min(Start + BatchSize, Total);
        QFuture<void> Future = QtConcurrent::run([this, &AllFuncs, &Done, Total, Start, End]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
            for (int I = Start; I < End; ++I) {
                if (Cancelled.loadRelaxed()) return;
                AnalyzeFunction(AllFuncs[I]);
                Db->UpdateFunction(AllFuncs[I].Start, AllFuncs[I]);
                int D = Done.fetchAndAddRelaxed(1) + 1;
                if (D % 500 == 0) {
                    EmitProgress(AnalysisState::AnalyzingFunctions,
                        80 + (D * 15 / std::max(1, Total)),
                        QString("Analyzing function %1/%2").arg(D).arg(Total));
                }
            }
        });
        Futures.append(Future);
    }

    for (auto& F : Futures) {
        F.waitForFinished();
    }
}

void AnalysisWorker::AnalyzeFunction(AnalyzedFunction& Func) {
    BinaryInfo Info = Db->GetBinaryInfo();

    QList<AnalyzedInstruction> Insns = Db->GetInstructions(Func.Start, Func.End);
    Func.InstructionCount = Insns.size();

    QList<Xref> XrefsTo = Db->GetXrefsTo(Func.Start);
    for (const auto& Ref : XrefsTo) {
        if (Ref.Type == XrefType::CodeCall) {
            Func.Callers.append(Ref.From);
        }
    }

    for (const auto& Insn : Insns) {
        if (Insn.IsCall && Insn.BranchTarget != 0) {
            if (!Func.Callees.contains(Insn.BranchTarget)) {
                Func.Callees.append(Insn.BranchTarget);
            }
        }
    }

    Func.StackFrameSize = 0;
    for (const auto& Insn : Insns) {
        if (Insn.Addr > Func.Start + 32) break;
        QString Mn = Insn.Mnemonic.toLower();
        QString Op = Insn.Operands.toLower();

        if (Mn == "sub" && (Op.startsWith("rsp,") || Op.startsWith("esp,"))) {
            QString ValStr = Op.mid(Op.indexOf(',') + 1).trimmed();
            if (ValStr.startsWith("0x")) {
                Func.StackFrameSize = ValStr.mid(2).toInt(nullptr, 16);
            } else {
                Func.StackFrameSize = ValStr.toInt();
            }
            break;
        }
    }

    Func.ArgCount = 0;
    if (Info.Is64Bit) {
        bool UsesRcx = false, UsesRdx = false, UsesR8 = false, UsesR9 = false;
        for (const auto& Insn : Insns) {
            if (Insn.Addr > Func.Start + 64) break;
            QString Op = Insn.Operands.toLower();
            if (Op.contains("rcx") || Op.contains("ecx")) UsesRcx = true;
            if (Op.contains("rdx") || Op.contains("edx")) UsesRdx = true;
            if (Op.contains("r8")) UsesR8 = true;
            if (Op.contains("r9")) UsesR9 = true;
        }
        if (UsesR9) Func.ArgCount = 4;
        else if (UsesR8) Func.ArgCount = 3;
        else if (UsesRdx) Func.ArgCount = 2;
        else if (UsesRcx) Func.ArgCount = 1;
    } else {
        int MaxArgOffset = 0;
        for (const auto& Insn : Insns) {
            if (Insn.Addr > Func.Start + 64) break;
            QString Op = Insn.Operands.toLower();
            QRegularExpression Re("\\[ebp\\+(?:0x)?([0-9a-f]+)\\]");
            auto Match = Re.match(Op);
            if (Match.hasMatch()) {
                int Off = Match.captured(1).toInt(nullptr, 16);
                if (Off >= 8 && Off < 0x100) {
                    int ArgIdx = (Off - 8) / 4 + 1;
                    if (ArgIdx > MaxArgOffset) MaxArgOffset = ArgIdx;
                }
            }
        }
        Func.ArgCount = MaxArgOffset;
    }

    QSet<Address> BlockStarts;
    BlockStarts.insert(Func.Start);

    for (const auto& Insn : Insns) {
        if (Insn.IsJump || Insn.IsConditional) {
            if (Insn.BranchTarget >= Func.Start && Insn.BranchTarget < Func.End) {
                BlockStarts.insert(Insn.BranchTarget);
            }
            Address Next = Insn.Addr + Insn.Size;
            if (Next >= Func.Start && Next < Func.End) {
                BlockStarts.insert(Next);
            }
        }
    }

    Func.BasicBlockCount = BlockStarts.size();
}

void AnalysisWorker::RunLinearSweep() {
    BinaryInfo Info = Db->GetBinaryInfo();
    if (Info.Arch != Architecture::X86 && Info.Arch != Architecture::X64) {
        emit LogMessage("Linear sweep: skipping non-x86 architecture");
        return;
    }

    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

    QList<Address> NewTargets;
    int ProloguesFound = 0;

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;
        if (Seg.Data.isEmpty()) continue;

        const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        size_t SSize = static_cast<size_t>(Seg.Data.size());

        for (size_t Off = 0; Off + 8 <= SSize; ) {
            if (Cancelled.loadRelaxed()) return;

            Address Addr = Seg.VirtualAddress + Off;

            if (Db->HasInstruction(Addr)) {
                auto Insn = Db->GetInstruction(Addr);
                Off += Insn.Size > 0 ? Insn.Size : 1;
                continue;
            }

            if (SData[Off] == 0xCC || SData[Off] == 0x00 || SData[Off] == 0x90) {
                Off++;
                continue;
            }

            bool FoundPrologue = false;

            if (Info.Is64Bit) {
                if (Off + 4 <= SSize && SData[Off] == 0xF3 && SData[Off+1] == 0x0F &&
                    SData[Off+2] == 0x1E && SData[Off+3] == 0xFA) {
                    if (Off + 5 <= SSize && SData[Off+4] == 0x55) {
                        FoundPrologue = true;
                    } else if (Off + 5 <= SSize && (SData[Off+4] == 0x53 || SData[Off+4] == 0x56 || SData[Off+4] == 0x57)) {
                        FoundPrologue = true;
                    } else if (Off + 6 <= SSize && SData[Off+4] == 0x41 &&
                               (SData[Off+5] == 0x54 || SData[Off+5] == 0x55 ||
                                SData[Off+5] == 0x56 || SData[Off+5] == 0x57)) {
                        FoundPrologue = true;
                    } else if (Off + 7 <= SSize && SData[Off+4] == 0x48 &&
                               SData[Off+5] == 0x83 && SData[Off+6] == 0xEC) {
                        FoundPrologue = true;
                    } else if (Off + 8 <= SSize && SData[Off+4] == 0x48 &&
                               SData[Off+5] == 0x89 && SData[Off+6] == 0x5C &&
                               SData[Off+7] == 0x24) {
                        FoundPrologue = true;
                    }
                }

                if (!FoundPrologue && Off + 4 <= SSize &&
                    SData[Off] == 0x55 && SData[Off+1] == 0x48 &&
                    SData[Off+2] == 0x89 && SData[Off+3] == 0xE5) {
                    FoundPrologue = true;
                }

                if (!FoundPrologue && Off + 3 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x83 && SData[Off+2] == 0xEC) {
                    if (Off > 0 && SData[Off-1] != 0xCC && SData[Off-1] != 0xC3 &&
                        SData[Off-1] != 0x90 && SData[Off-1] != 0x00) {
                        Off++;
                        continue;
                    }
                    FoundPrologue = true;
                }

                if (!FoundPrologue && Off + 4 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x89 &&
                    SData[Off+2] == 0x5C && SData[Off+3] == 0x24) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        FoundPrologue = true;
                    }
                }

                if (!FoundPrologue && Off + 5 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x89 &&
                    SData[Off+2] == 0x4C && SData[Off+3] == 0x24) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        FoundPrologue = true;
                    }
                }

                if (!FoundPrologue && Off + 2 <= SSize &&
                    SData[Off] == 0x40 &&
                    (SData[Off+1] == 0x53 || SData[Off+1] == 0x55 ||
                     SData[Off+1] == 0x56 || SData[Off+1] == 0x57)) {
                    FoundPrologue = true;
                }

                if (!FoundPrologue && Off + 2 <= SSize &&
                    SData[Off] == 0x41 &&
                    (SData[Off+1] == 0x54 || SData[Off+1] == 0x55 ||
                     SData[Off+1] == 0x56 || SData[Off+1] == 0x57)) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        FoundPrologue = true;
                    }
                }

                if (!FoundPrologue && Off + 8 <= SSize &&
                    SData[Off] == 0x48 && SData[Off+1] == 0x8B &&
                    SData[Off+2] == 0xC4) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        FoundPrologue = true;
                    }
                }
            } else {
                if (Off + 3 <= SSize &&
                    SData[Off] == 0x55 && SData[Off+1] == 0x89 && SData[Off+2] == 0xE5) {
                    FoundPrologue = true;
                }

                if (!FoundPrologue && Off + 3 <= SSize &&
                    SData[Off] == 0x55 && SData[Off+1] == 0x8B && SData[Off+2] == 0xEC) {
                    FoundPrologue = true;
                }

                if (!FoundPrologue && Off + 3 <= SSize &&
                    SData[Off] == 0x83 && SData[Off+1] == 0xEC) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        FoundPrologue = true;
                    }
                }

                if (!FoundPrologue && Off + 1 <= SSize && SData[Off] == 0x55) {
                    if (Off == 0 || SData[Off-1] == 0xCC || SData[Off-1] == 0xC3 ||
                        SData[Off-1] == 0x90 || SData[Off-1] == 0x00) {
                        if (Off + 2 <= SSize && SData[Off+1] == 0x57) {
                            FoundPrologue = true;
                        }
                    }
                }
            }

            if (FoundPrologue) {
                QMutexLocker Locker(&QueueMutex);
                if (!VisitedMT.contains(Addr) && !QueuedSetMT.contains(Addr)) {
                    NewTargets.append(Addr);
                    FunctionStarts.insert(Addr);
                    ProloguesFound++;
                }
            }

            Off++;
        }
    }

    if (NewTargets.isEmpty()) {
        emit LogMessage("Linear sweep: no new function prologues found");
        return;
    }

    constexpr int MaxLinearSweepTargets = 200000;
    if (ProloguesFound > MaxLinearSweepTargets) {
        emit LogMessage(QString("Linear sweep: capping from %1 to %2 targets").arg(ProloguesFound).arg(MaxLinearSweepTargets));
        NewTargets.resize(MaxLinearSweepTargets);
        ProloguesFound = MaxLinearSweepTargets;
    }

    emit LogMessage(QString("Linear sweep: found %1 new function prologues, disassembling...").arg(ProloguesFound));

    {
        QMutexLocker Locker(&QueueMutex);
        for (Address Target : NewTargets) {
            AddDisassemblyTargetMT(Target);
        }
    }

    int NumThreads = QThread::idealThreadCount();
    if (NumThreads < 2) NumThreads = 2;
    if (NumThreads > 16) NumThreads = 16;

    QAtomicInt FuncsProcessed(0);
    int TotalTargets = ProloguesFound;

    QList<QFuture<void>> Futures;

    for (int T = 0; T < NumThreads; ++T) {
        QFuture<void> Future = QtConcurrent::run([this, CsArch, CsMode, &FuncsProcessed, TotalTargets]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
            csh Handle;
            if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

            int IdleCount = 0;

            while (!Cancelled.loadRelaxed()) {
                Address Target = 0;
                {
                    QMutexLocker Locker(&QueueMutex);
                    while (!QueueMT.isEmpty()) {
                        Target = QueueMT.takeFirst();
                        if (!VisitedMT.contains(Target)) break;
                        Target = 0;
                    }
                }

                if (Target == 0) {
                    if (++IdleCount > 50) {
                        QMutexLocker Locker(&QueueMutex);
                        if (QueueMT.isEmpty()) break;
                    }
                    QThread::msleep(1);
                    continue;
                }

                IdleCount = 0;
                DisassembleFromMT(Target, static_cast<size_t>(Handle));

                int Done = FuncsProcessed.fetchAndAddRelaxed(1) + 1;
                if (Done % 5000 == 0) {
                    int Pct = 25 + std::min(4, Done * 5 / std::max(1, TotalTargets));
                    EmitProgress(AnalysisState::Disassembling, Pct,
                        QString("Linear sweep: %1/%2 functions disassembled, %3 instructions")
                            .arg(Done).arg(TotalTargets).arg(Db->InstructionCount()));
                }
            }

            cs_close(&Handle);
        });
        Futures.append(Future);
    }

    for (auto& F : Futures) {
        F.waitForFinished();
    }

    int TotalNow = Db->InstructionCount();
    emit LogMessage(QString("Linear sweep complete: %1 total instructions now").arg(TotalNow));
}

void AnalysisWorker::ScanVtables() {
    BinaryInfo Info = Db->GetBinaryInfo();
    int PtrSize = Info.Is64Bit ? 8 : 4;
    int VtableFuncsFound = 0;

    auto IsCodeAddress = [&](Address Addr) -> bool {
        for (const Segment& Seg : Info.Segments) {
            if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
            if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
                return true;
            }
        }
        return false;
    };

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.IsExecutable) continue;
        if (Seg.Data.isEmpty()) continue;
        if (Seg.IsWritable && Seg.Name != ".data.rel.ro" && Seg.Name != ".data.rel.ro.local") continue;

        const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        size_t SSize = static_cast<size_t>(Seg.Data.size());

        int ConsecutiveCodePtrs = 0;
        QList<Address> PtrRun;

        for (size_t Off = 0; Off + PtrSize <= SSize; Off += PtrSize) {
            if (Cancelled.loadRelaxed()) return;

            uint64_t PtrVal = 0;
            if (PtrSize == 8) {
                std::memcpy(&PtrVal, SData + Off, 8);
            } else {
                uint32_t Val32 = 0;
                std::memcpy(&Val32, SData + Off, 4);
                PtrVal = Val32;
            }

            if (PtrVal != 0 && IsCodeAddress(PtrVal)) {
                QByteArray FirstBytes = Db->ReadBytes(PtrVal, 4);
                if (FirstBytes.size() >= 1) {
                    uint8_t FirstByte = static_cast<uint8_t>(FirstBytes[0]);
                    if (FirstByte != 0x00 && FirstByte != 0xCC) {
                        PtrRun.append(PtrVal);
                        ConsecutiveCodePtrs++;
                        continue;
                    }
                }
            }

            if (ConsecutiveCodePtrs >= 2) {
                for (Address FuncAddr : PtrRun) {
                    QMutexLocker Locker(&QueueMutex);
                    if (!VisitedMT.contains(FuncAddr)) {
                        FunctionStarts.insert(FuncAddr);
                        if (!QueuedSetMT.contains(FuncAddr)) {
                            AddDisassemblyTargetMT(FuncAddr);
                        }
                        VtableFuncsFound++;
                    }
                }
            }

            ConsecutiveCodePtrs = 0;
            PtrRun.clear();
        }

        if (ConsecutiveCodePtrs >= 2) {
            for (Address FuncAddr : PtrRun) {
                QMutexLocker Locker(&QueueMutex);
                if (!VisitedMT.contains(FuncAddr)) {
                    FunctionStarts.insert(FuncAddr);
                    if (!QueuedSetMT.contains(FuncAddr)) {
                        AddDisassemblyTargetMT(FuncAddr);
                    }
                    VtableFuncsFound++;
                }
            }
        }
    }

    if (VtableFuncsFound > 0) {
        emit LogMessage(QString("Vtable scan: found %1 function pointers").arg(VtableFuncsFound));

        BinaryInfo Info2 = Db->GetBinaryInfo();
        cs_arch CsArch = CS_ARCH_X86;
        cs_mode CsMode = Info2.Is64Bit ? CS_MODE_64 : CS_MODE_32;

        int NumThreads = QThread::idealThreadCount();
        if (NumThreads < 2) NumThreads = 2;
        if (NumThreads > 16) NumThreads = 16;

        QList<QFuture<void>> Futures;
        for (int T = 0; T < NumThreads; ++T) {
            QFuture<void> Future = QtConcurrent::run([this, CsArch, CsMode]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
                csh Handle;
                if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
                cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
                while (!Cancelled.loadRelaxed()) {
                    Address Target = 0;
                    {
                        QMutexLocker Locker(&QueueMutex);
                        while (!QueueMT.isEmpty()) {
                            Target = QueueMT.takeFirst();
                            if (!VisitedMT.contains(Target)) break;
                            Target = 0;
                        }
                    }
                    if (Target == 0) {
                        QThread::msleep(1);
                        QMutexLocker Locker(&QueueMutex);
                        if (QueueMT.isEmpty()) break;
                        continue;
                    }
                    DisassembleFromMT(Target, static_cast<size_t>(Handle));
                }
                cs_close(&Handle);
            });
            Futures.append(Future);
        }
        for (auto& F : Futures) F.waitForFinished();

        emit LogMessage(QString("Vtable scan disassembly complete: %1 total instructions").arg(Db->InstructionCount()));
    } else {
        emit LogMessage("Vtable scan: no vtables found");
    }
}

void AnalysisWorker::ScanCodePointers() {
    BinaryInfo Info = Db->GetBinaryInfo();
    int PtrSize = Info.Is64Bit ? 8 : 4;
    int CodePtrsFound = 0;

    auto IsCodeAddress = [&](Address Addr) -> bool {
        for (const Segment& Seg : Info.Segments) {
            if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
            if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
                return true;
            }
        }
        return false;
    };

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Cancelled.loadRelaxed()) return;
            if (Insn.MemoryRef == 0) continue;
            if (Insn.IsCall || Insn.IsJump) continue;

            Address DataAddr = Insn.MemoryRef;
            if (!Db->IsAddressValid(DataAddr)) continue;

            QByteArray PtrBytes = Db->ReadBytes(DataAddr, PtrSize);
            if (PtrBytes.size() < PtrSize) continue;

            uint64_t PtrVal = 0;
            if (PtrSize == 8) {
                std::memcpy(&PtrVal, PtrBytes.constData(), 8);
            } else {
                uint32_t Val32 = 0;
                std::memcpy(&Val32, PtrBytes.constData(), 4);
                PtrVal = Val32;
            }

            if (PtrVal != 0 && IsCodeAddress(PtrVal) && !Db->HasInstruction(PtrVal)) {
                QByteArray FirstBytes = Db->ReadBytes(PtrVal, 4);
                if (FirstBytes.size() >= 1) {
                    uint8_t FirstByte = static_cast<uint8_t>(FirstBytes[0]);
                    if (FirstByte != 0x00 && FirstByte != 0xCC) {
                        QMutexLocker Locker(&QueueMutex);
                        if (!VisitedMT.contains(PtrVal) && !QueuedSetMT.contains(PtrVal)) {
                            FunctionStarts.insert(PtrVal);
                            AddDisassemblyTargetMT(PtrVal);
                            CodePtrsFound++;
                        }
                    }
                }
            }
        }
    }

    if (CodePtrsFound > 0) {
        emit LogMessage(QString("Code pointer scan: found %1 new targets").arg(CodePtrsFound));

        cs_arch CsArch = CS_ARCH_X86;
        cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

        int NumThreads = QThread::idealThreadCount();
        if (NumThreads < 2) NumThreads = 2;
        if (NumThreads > 16) NumThreads = 16;

        QList<QFuture<void>> Futures;
        for (int T = 0; T < NumThreads; ++T) {
            QFuture<void> Future = QtConcurrent::run([this, CsArch, CsMode]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
                csh Handle;
                if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
                cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
                while (!Cancelled.loadRelaxed()) {
                    Address Target = 0;
                    {
                        QMutexLocker Locker(&QueueMutex);
                        while (!QueueMT.isEmpty()) {
                            Target = QueueMT.takeFirst();
                            if (!VisitedMT.contains(Target)) break;
                            Target = 0;
                        }
                    }
                    if (Target == 0) {
                        QThread::msleep(1);
                        QMutexLocker Locker(&QueueMutex);
                        if (QueueMT.isEmpty()) break;
                        continue;
                    }
                    DisassembleFromMT(Target, static_cast<size_t>(Handle));
                }
                cs_close(&Handle);
            });
            Futures.append(Future);
        }
        for (auto& F : Futures) F.waitForFinished();
    } else {
        emit LogMessage("Code pointer scan: no new targets");
    }
}

void AnalysisWorker::FillCodeGaps() {
    BinaryInfo Info = Db->GetBinaryInfo();
    if (Info.Arch != Architecture::X86 && Info.Arch != Architecture::X64) {
        emit LogMessage("Gap fill: skipping non-x86");
        return;
    }

    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;
    int GapFuncsFound = 0;
    int GapInsnsAdded = 0;

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
        if (Seg.Data.isEmpty()) continue;

        const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        size_t SSize = static_cast<size_t>(Seg.Data.size());

        csh Handle;
        if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) continue;
        cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

        size_t Off = 0;
        while (Off < SSize) {
            if (Cancelled.loadRelaxed()) break;

            Address Addr = Seg.VirtualAddress + Off;

            if (Db->HasInstruction(Addr)) {
                auto Insn = Db->GetInstruction(Addr);
                Off += Insn.Size > 0 ? Insn.Size : 1;
                continue;
            }

            if (SData[Off] == 0xCC || SData[Off] == 0x00 || SData[Off] == 0x90) {
                Off++;
                continue;
            }

            size_t GapStart = Off;
            size_t ChunkSize = std::min(SSize - Off, static_cast<size_t>(256));

            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, SData + Off, ChunkSize, Addr, 0, &Insns);

            if (Count == 0) {
                Off++;
                continue;
            }

            bool Valid = true;
            int ValidInsns = 0;

            for (size_t I = 0; I < Count; ++I) {
                Address InsnAddr = Insns[I].address;
                if (Db->HasInstruction(InsnAddr)) break;

                QString Mn = QString::fromUtf8(Insns[I].mnemonic).toLower();

                if (Insns[I].size == 0) { Valid = false; break; }
                if (Mn == "invalid" || Mn == "(bad)") { Valid = false; break; }

                if (Mn == "in" || Mn == "out" || Mn == "ins" || Mn == "outs" ||
                    Mn == "cli" || Mn == "sti" || Mn == "hlt" || Mn == "lgdt" ||
                    Mn == "lidt" || Mn == "ltr" || Mn == "lldt") {
                    if (!Info.IsDriver) { Valid = false; break; }
                }

                ValidInsns++;

                if (Mn == "ret" || Mn == "retn" || Mn == "retf" ||
                    Mn == "int3" || Mn == "ud2" || Mn == "jmp") {
                    break;
                }
            }

            if (!Valid || ValidInsns < 2) {
                cs_free(Insns, Count);
                Off++;
                continue;
            }

            bool IsNewFunc = false;
            if (GapStart == 0) {
                IsNewFunc = true;
            } else if (GapStart > 0) {
                uint8_t PrevByte = SData[GapStart - 1];
                if (PrevByte == 0xCC || PrevByte == 0xC3 || PrevByte == 0xCB ||
                    PrevByte == 0x90 || PrevByte == 0x00) {
                    IsNewFunc = true;
                }
            }

            if ((Addr & 0xF) == 0) {
                IsNewFunc = true;
            }

            for (size_t I = 0; I < Count && I < static_cast<size_t>(ValidInsns); ++I) {
                Address InsnAddr = Insns[I].address;
                if (Db->HasInstruction(InsnAddr)) break;

                {
                    QMutexLocker Locker(&QueueMutex);
                    if (VisitedMT.contains(InsnAddr)) break;
                    VisitedMT.insert(InsnAddr);
                }

                AnalyzedInstruction Ai;
                Ai.Addr = InsnAddr;
                std::memcpy(Ai.Bytes, Insns[I].bytes, std::min(static_cast<size_t>(Insns[I].size), static_cast<size_t>(15)));
                Ai.Size = static_cast<uint8_t>(Insns[I].size);
                Ai.Mnemonic = QString::fromUtf8(Insns[I].mnemonic);
                Ai.Operands = QString::fromUtf8(Insns[I].op_str);
                Ai.Comment = QString();
                Ai.BranchTarget = 0;
                Ai.MemoryRef = 0;

                QString Mn = Ai.Mnemonic.toLower();
                Ai.IsCall = Mn.startsWith("call");
                Ai.IsRet = (Mn == "ret" || Mn == "retn" || Mn == "retf");
                Ai.IsNop = (Mn == "nop");
                Ai.IsPush = Mn.startsWith("push");
                Ai.IsPop = Mn.startsWith("pop");
                Ai.IsJump = Mn.startsWith('j') || Mn == "jmp";
                Ai.IsConditional = Ai.IsJump && Mn != "jmp";

                cs_detail* Detail = Insns[I].detail;
                if (Detail) {
                    cs_x86* X86 = &Detail->x86;
                    for (uint8_t OpIdx = 0; OpIdx < X86->op_count; ++OpIdx) {
                        cs_x86_op* Op = &X86->operands[OpIdx];
                        if (Op->type == X86_OP_IMM && (Ai.IsCall || Ai.IsJump)) {
                            Ai.BranchTarget = static_cast<Address>(Op->imm);
                        }
                        if (Op->type == X86_OP_MEM) {
                            if (Op->mem.base == X86_REG_RIP || Op->mem.base == X86_REG_EIP) {
                                Address NextAddr = InsnAddr + Insns[I].size;
                                Ai.MemoryRef = static_cast<Address>(static_cast<int64_t>(NextAddr) + Op->mem.disp);
                            } else if (Op->mem.base == X86_REG_INVALID && Op->mem.index == X86_REG_INVALID && Op->mem.disp != 0) {
                                Ai.MemoryRef = static_cast<Address>(Op->mem.disp);
                            }
                        }
                    }
                }

                Db->AddInstruction(Ai);
                Db->SetItemType(InsnAddr, ItemType::Code);
                GapInsnsAdded++;

                if (Ai.IsCall && Ai.BranchTarget != 0) {
                    QMutexLocker Locker(&QueueMutex);
                    FunctionStarts.insert(Ai.BranchTarget);
                }

                QString Mn2 = Ai.Mnemonic.toLower();
                if (Mn2 == "ret" || Mn2 == "retn" || Mn2 == "retf" ||
                    Mn2 == "int3" || Mn2 == "ud2" || Mn2 == "jmp") {
                    break;
                }
            }

            if (IsNewFunc) {
                QMutexLocker Locker(&QueueMutex);
                FunctionStarts.insert(Addr);
                GapFuncsFound++;
            }

            Address LastAddr = Insns[std::min(Count, static_cast<size_t>(ValidInsns)) - 1].address;
            size_t LastSize = Insns[std::min(Count, static_cast<size_t>(ValidInsns)) - 1].size;
            Off = (LastAddr + LastSize) - Seg.VirtualAddress;

            cs_free(Insns, Count);

            if (GapFuncsFound % 1000 == 0 && GapFuncsFound > 0) {
                EmitProgress(AnalysisState::Disassembling, 42,
                    QString("Gap fill: %1 functions, %2 instructions so far")
                        .arg(GapFuncsFound).arg(GapInsnsAdded));
            }
        }

        cs_close(&Handle);
    }

    emit LogMessage(QString("Gap fill: %1 new functions, %2 new instructions").arg(GapFuncsFound).arg(GapInsnsAdded));
}

void AnalysisWorker::DetectTailCallFunctions() {
    BinaryInfo Info = Db->GetBinaryInfo();
    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    int TailCallsFound = 0;

    QSet<Address> ExistingFunctions;
    for (const auto& Func : AllFuncs) {
        ExistingFunctions.insert(Func.Start);
    }

    for (const auto& Func : AllFuncs) {
        if (Cancelled.loadRelaxed()) return;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(Func.Start, Func.End);

        for (const auto& Insn : Insns) {
            if (!Insn.IsJump || Insn.IsConditional) continue;
            if (Insn.BranchTarget == 0) continue;

            Address Target = Insn.BranchTarget;
            if (Target >= Func.Start && Target < Func.End) continue;
            if (ExistingFunctions.contains(Target)) continue;
            if (!Db->IsAddressValid(Target)) continue;
            if (!Db->HasInstruction(Target)) continue;

            QByteArray FirstBytes = Db->ReadBytes(Target, 4);
            if (FirstBytes.size() >= 1) {
                uint8_t FirstByte = static_cast<uint8_t>(FirstBytes[0]);
                if (FirstByte == 0x00 || FirstByte == 0xCC) continue;
            }

            FunctionStarts.insert(Target);
            ExistingFunctions.insert(Target);
            TailCallsFound++;
        }
    }

    emit LogMessage(QString("Tail call detection: %1 new functions").arg(TailCallsFound));
}

void AnalysisWorker::ResolveJumpTables() {
    BinaryInfo Info = Db->GetBinaryInfo();
    if (Info.Arch != Architecture::X86 && Info.Arch != Architecture::X64) return;

    int PtrSize = Info.Is64Bit ? 8 : 4;
    int JumpTableEntries = 0;

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Cancelled.loadRelaxed()) return;
            if (!Insn.IsJump || Insn.IsConditional) continue;
            if (Insn.BranchTarget != 0) continue;
            if (Insn.MemoryRef == 0) continue;

            Address TableBase = Insn.MemoryRef;
            if (!Db->IsAddressValid(TableBase)) continue;

            for (int EntryIdx = 0; EntryIdx < 256; ++EntryIdx) {
                Address EntryAddr = TableBase + EntryIdx * PtrSize;
                QByteArray PtrBytes = Db->ReadBytes(EntryAddr, PtrSize);
                if (PtrBytes.size() < PtrSize) break;

                uint64_t Target = 0;
                if (PtrSize == 8) {
                    std::memcpy(&Target, PtrBytes.constData(), 8);
                } else {
                    uint32_t Val32 = 0;
                    std::memcpy(&Val32, PtrBytes.constData(), 4);
                    Target = Val32;
                }

                if (Target == 0) break;

                bool InCode = false;
                for (const Segment& CodeSeg : Info.Segments) {
                    if (CodeSeg.Type != SegmentType::Code && !CodeSeg.IsExecutable) continue;
                    if (Target >= CodeSeg.VirtualAddress && Target < CodeSeg.VirtualAddress + CodeSeg.VirtualSize) {
                        InCode = true;
                        break;
                    }
                }

                if (!InCode) break;

                if (!Db->HasInstruction(Target)) {
                    QMutexLocker Locker(&QueueMutex);
                    if (!VisitedMT.contains(Target) && !QueuedSetMT.contains(Target)) {
                        AddDisassemblyTargetMT(Target);
                        JumpTableEntries++;
                    }
                }
            }
        }
    }

    if (JumpTableEntries > 0) {
        emit LogMessage(QString("Jump table scan: %1 new code targets").arg(JumpTableEntries));

        cs_arch CsArch = CS_ARCH_X86;
        cs_mode CsMode = Info.Is64Bit ? CS_MODE_64 : CS_MODE_32;

        int NumThreads = QThread::idealThreadCount();
        if (NumThreads < 2) NumThreads = 2;
        if (NumThreads > 16) NumThreads = 16;

        QList<QFuture<void>> Futures;
        for (int T = 0; T < NumThreads; ++T) {
            QFuture<void> Future = QtConcurrent::run([this, CsArch, CsMode]() {
            QThread::currentThread()->setPriority(QThread::LowPriority);
                csh Handle;
                if (cs_open(CsArch, CsMode, &Handle) != CS_ERR_OK) return;
                cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
                while (!Cancelled.loadRelaxed()) {
                    Address Target = 0;
                    {
                        QMutexLocker Locker(&QueueMutex);
                        while (!QueueMT.isEmpty()) {
                            Target = QueueMT.takeFirst();
                            if (!VisitedMT.contains(Target)) break;
                            Target = 0;
                        }
                    }
                    if (Target == 0) {
                        QThread::msleep(1);
                        QMutexLocker Locker(&QueueMutex);
                        if (QueueMT.isEmpty()) break;
                        continue;
                    }
                    DisassembleFromMT(Target, static_cast<size_t>(Handle));
                }
                cs_close(&Handle);
            });
            Futures.append(Future);
        }
        for (auto& F : Futures) F.waitForFinished();
    } else {
        emit LogMessage("Jump table scan: no tables found");
    }
}

void AnalysisWorker::MatchSignatures() {
    BinaryInfo Info = Db->GetBinaryInfo();
    SigMatcher.LoadBuiltinSignatures(Info.Is64Bit);

    emit LogMessage(QString("Matching %1 signatures against functions...").arg(SigMatcher.SignatureCount()));

    QList<SignatureMatch> Matches = SigMatcher.MatchFunctions(Db);
    int Applied = 0;

    for (const auto& Match : Matches) {
        if (Cancelled.loadRelaxed()) return;

        if (Db->HasFunction(Match.Addr)) {
            AnalyzedFunction Func = Db->GetFunction(Match.Addr);
            if (Func.Name.startsWith("sub_")) {
                Func.Name = Match.Name;
                Db->UpdateFunction(Match.Addr, Func);
                Db->SetName(Match.Addr, Match.Name);
                Applied++;
            }
        }
    }

    emit LogMessage(QString("Signature matching: %1 matches, %2 applied").arg(Matches.size()).arg(Applied));
}

void AnalysisWorker::DetectThunks() {
    BinaryInfo Info = Db->GetBinaryInfo();
    QMap<Address, QString> ImportNames;
    for (const auto& Imp : Info.Imports) {
        if (Imp.IatAddress != 0 && !Imp.FuncName.isEmpty()) {
            ImportNames[Imp.IatAddress] = Imp.FuncName;
        }
    }

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    for (auto& Func : AllFuncs) {
        if (Func.InstructionCount > 3) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(Func.Start, Func.Start + 16);
        if (Insns.isEmpty()) continue;

        const auto& FirstInsn = Insns[0];
        if (FirstInsn.IsJump && !FirstInsn.IsConditional) {
            Address Target = FirstInsn.MemoryRef;
            if (Target == 0) Target = FirstInsn.BranchTarget;

            if (Target != 0 && ImportNames.contains(Target)) {
                Func.IsThunk = true;
                Func.Name = ImportNames[Target];
                Db->UpdateFunction(Func.Start, Func);
                Db->SetName(Func.Start, Func.Name);
            }
        }
    }
}

void AnalysisWorker::DemangleNames() {
    int DemangledCount = 0;

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    for (auto& Func : AllFuncs) {
        if (Cancelled.loadRelaxed()) return;

        QByteArray MangledBytes = Func.Name.toLatin1();
        const char* MangledStr = MangledBytes.constData();

        if (Func.Name.startsWith("_Z")) {
            int Status = 0;
            char* Demangled = abi::__cxa_demangle(MangledStr, nullptr, nullptr, &Status);
            if (Status == 0 && Demangled) {
                Func.DemangledName = QString::fromUtf8(Demangled);
                Db->UpdateFunction(Func.Start, Func);
                Db->SetName(Func.Start, Func.DemangledName);
                DemangledCount++;
                std::free(Demangled);
            }
        }
    }

    BinaryInfo Info = Db->GetBinaryInfo();
    for (auto& Imp : Info.Imports) {
        if (Cancelled.loadRelaxed()) return;
        if (Imp.FuncName.startsWith("_Z")) {
            QByteArray Bytes = Imp.FuncName.toLatin1();
            int Status = 0;
            char* Demangled = abi::__cxa_demangle(Bytes.constData(), nullptr, nullptr, &Status);
            if (Status == 0 && Demangled) {
                QString DemangledStr = QString::fromUtf8(Demangled);
                Db->SetName(Imp.IatAddress, DemangledStr);
                if (Db->HasFunction(Imp.IatAddress)) {
                    AnalyzedFunction Func = Db->GetFunction(Imp.IatAddress);
                    Func.DemangledName = DemangledStr;
                    Db->UpdateFunction(Imp.IatAddress, Func);
                }
                DemangledCount++;
                std::free(Demangled);
            }
        }
    }

    for (auto& Exp : Info.Exports) {
        if (Cancelled.loadRelaxed()) return;
        if (Exp.Name.startsWith("_Z")) {
            QByteArray Bytes = Exp.Name.toLatin1();
            int Status = 0;
            char* Demangled = abi::__cxa_demangle(Bytes.constData(), nullptr, nullptr, &Status);
            if (Status == 0 && Demangled) {
                QString DemangledStr = QString::fromUtf8(Demangled);
                Db->SetName(Exp.Addr, DemangledStr);
                if (Db->HasFunction(Exp.Addr)) {
                    AnalyzedFunction Func = Db->GetFunction(Exp.Addr);
                    Func.DemangledName = DemangledStr;
                    Db->UpdateFunction(Exp.Addr, Func);
                }
                DemangledCount++;
                std::free(Demangled);
            }
        }
    }

    QMap<Address, QString> AllNames = Db->GetAllNames();
    for (auto It = AllNames.constBegin(); It != AllNames.constEnd(); ++It) {
        if (Cancelled.loadRelaxed()) return;
        const QString& Name = It.value();
        if (Name.startsWith("_Z") && !Db->HasFunction(It.key())) {
            QByteArray Bytes = Name.toLatin1();
            int Status = 0;
            char* Demangled = abi::__cxa_demangle(Bytes.constData(), nullptr, nullptr, &Status);
            if (Status == 0 && Demangled) {
                Db->SetName(It.key(), QString::fromUtf8(Demangled));
                DemangledCount++;
                std::free(Demangled);
            }
        }
    }

    emit LogMessage(QString("Demangled %1 C++ names").arg(DemangledCount));
}

void AnalysisWorker::DetectNonReturning() {
    QSet<QString> KnownNoReturn;
    KnownNoReturn.insert("exit");
    KnownNoReturn.insert("_exit");
    KnownNoReturn.insert("abort");
    KnownNoReturn.insert("__assert_fail");
    KnownNoReturn.insert("__stack_chk_fail");
    KnownNoReturn.insert("__fortify_fail");
    KnownNoReturn.insert("__cxa_throw");
    KnownNoReturn.insert("__cxa_rethrow");
    KnownNoReturn.insert("longjmp");
    KnownNoReturn.insert("__longjmp_chk");
    KnownNoReturn.insert("siglongjmp");
    KnownNoReturn.insert("err");
    KnownNoReturn.insert("errx");
    KnownNoReturn.insert("verr");
    KnownNoReturn.insert("verrx");
    KnownNoReturn.insert("__libc_fatal");
    KnownNoReturn.insert("__assert_rtn");
    KnownNoReturn.insert("ExitProcess");
    KnownNoReturn.insert("TerminateProcess");
    KnownNoReturn.insert("RaiseException");
    KnownNoReturn.insert("FatalExit");
    KnownNoReturn.insert("_CxxThrowException");

    QSet<Address> NoReturnAddrs;
    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();

    for (auto& Func : AllFuncs) {
        if (Cancelled.loadRelaxed()) return;

        QString CheckName = Func.Name;
        QString CheckDemangled = Func.DemangledName;

        if (CheckName.contains('.')) {
            CheckName = CheckName.mid(CheckName.lastIndexOf('.') + 1);
        }

        if (KnownNoReturn.contains(CheckName) || KnownNoReturn.contains(CheckDemangled)) {
            Func.IsNoReturn = true;
            Db->UpdateFunction(Func.Start, Func);
            NoReturnAddrs.insert(Func.Start);
        }
    }

    int InitialCount = NoReturnAddrs.size();

    bool Changed = true;
    while (Changed) {
        if (Cancelled.loadRelaxed()) return;
        Changed = false;

        AllFuncs = Db->GetAllFunctions();
        for (auto& Func : AllFuncs) {
            if (Cancelled.loadRelaxed()) return;
            if (Func.IsNoReturn) continue;
            if (Func.Blocks.isEmpty()) continue;

            bool HasRetInstruction = false;
            bool HasTerminalNonLoopExit = false;
            bool AllTerminalsAreNoReturn = true;
            int TerminalBlockCount = 0;

            QSet<Address> BlockStartAddrs;
            for (const auto& Block : Func.Blocks) {
                BlockStartAddrs.insert(Block.Start);
            }

            for (const auto& Block : Func.Blocks) {
                if (Cancelled.loadRelaxed()) return;

                QList<AnalyzedInstruction> BlockInsts = Db->GetInstructions(Block.Start, Block.End);
                if (BlockInsts.isEmpty()) continue;

                const auto& LastInst = BlockInsts.last();
                if (LastInst.IsRet) {
                    HasRetInstruction = true;
                    break;
                }

                bool IsTerminal = true;
                for (const auto& Succ : Block.Successors) {
                    if (BlockStartAddrs.contains(Succ)) {
                        IsTerminal = false;
                        break;
                    }
                }

                if (Block.Successors.isEmpty()) {
                    IsTerminal = true;
                }

                if (!IsTerminal) continue;

                bool IsBackEdge = false;
                for (const auto& Succ : Block.Successors) {
                    if (Succ <= Block.Start && Succ >= Func.Start) {
                        IsBackEdge = true;
                    }
                }
                if (IsBackEdge && !Block.Successors.isEmpty()) continue;

                TerminalBlockCount++;
                HasTerminalNonLoopExit = true;

                bool BlockEndsInNoReturn = false;
                for (int I = BlockInsts.size() - 1; I >= 0; --I) {
                    if (BlockInsts[I].IsCall && BlockInsts[I].BranchTarget != 0) {
                        if (NoReturnAddrs.contains(BlockInsts[I].BranchTarget)) {
                            BlockEndsInNoReturn = true;
                        }
                        break;
                    }
                }

                if (!BlockEndsInNoReturn) {
                    AllTerminalsAreNoReturn = false;
                }
            }

            if (HasRetInstruction) continue;
            if (!HasTerminalNonLoopExit) continue;
            if (TerminalBlockCount == 0) continue;
            if (!AllTerminalsAreNoReturn) continue;

            Func.IsNoReturn = true;
            Db->UpdateFunction(Func.Start, Func);
            NoReturnAddrs.insert(Func.Start);
            Changed = true;
        }
    }

    emit LogMessage(QString("Non-returning function detection: %1 known, %2 propagated, %3 total")
        .arg(InitialCount)
        .arg(NoReturnAddrs.size() - InitialCount)
        .arg(NoReturnAddrs.size()));
}

void AnalysisWorker::ParseRtti() {
    BinaryInfo Info = Db->GetBinaryInfo();
    int PtrSize = Info.Is64Bit ? 8 : 4;
    int ClassesFound = 0;
    int VtablesNamed = 0;

    auto ReadPtr = [&](const uint8_t* Base, size_t Off) -> uint64_t {
        uint64_t Val = 0;
        if (PtrSize == 8) {
            std::memcpy(&Val, Base + Off, 8);
        } else {
            uint32_t Val32 = 0;
            std::memcpy(&Val32, Base + Off, 4);
            Val = Val32;
        }
        return Val;
    };

    auto ReadBytesAt = [&](Address Addr, size_t Size) -> QByteArray {
        return Db->ReadBytes(Addr, Size);
    };

    auto ReadPtrAt = [&](Address Addr) -> uint64_t {
        QByteArray Bytes = ReadBytesAt(Addr, PtrSize);
        if (Bytes.size() < PtrSize) return 0;
        uint64_t Val = 0;
        if (PtrSize == 8) {
            std::memcpy(&Val, Bytes.constData(), 8);
        } else {
            uint32_t Val32 = 0;
            std::memcpy(&Val32, Bytes.constData(), 4);
            Val = Val32;
        }
        return Val;
    };

    auto ReadCStringAt = [&](Address Addr, int MaxLen = 512) -> QString {
        QByteArray Bytes = ReadBytesAt(Addr, MaxLen);
        if (Bytes.isEmpty()) return QString();
        int Len = 0;
        while (Len < Bytes.size() && Bytes[Len] != '\0') Len++;
        return QString::fromLatin1(Bytes.constData(), Len);
    };

    auto DemangleName = [](const QString& Mangled) -> QString {
        QByteArray Bytes = Mangled.toLatin1();
        QString Prefixed = "_Z" + Mangled;
        QByteArray PrefixedBytes = Prefixed.toLatin1();

        int Status = 0;
        char* Result = abi::__cxa_demangle(PrefixedBytes.constData(), nullptr, nullptr, &Status);
        if (Status == 0 && Result) {
            QString Demangled = QString::fromUtf8(Result);
            std::free(Result);
            return Demangled;
        }

        Status = 0;
        Result = abi::__cxa_demangle(Bytes.constData(), nullptr, nullptr, &Status);
        if (Status == 0 && Result) {
            QString Demangled = QString::fromUtf8(Result);
            std::free(Result);
            return Demangled;
        }

        int Idx = 0;
        int NameLen = 0;
        while (Idx < Mangled.size() && Mangled[Idx].isDigit()) {
            NameLen = NameLen * 10 + Mangled[Idx].digitValue();
            Idx++;
        }
        if (NameLen > 0 && Idx + NameLen <= Mangled.size()) {
            return Mangled.mid(Idx, NameLen);
        }

        return Mangled;
    };

    auto IsCodeAddress = [&](Address Addr) -> bool {
        for (const Segment& Seg : Info.Segments) {
            if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
            if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
                return true;
            }
        }
        return false;
    };

    auto IsDataAddress = [&](Address Addr) -> bool {
        for (const Segment& Seg : Info.Segments) {
            if (Seg.IsExecutable) continue;
            if (Addr >= Seg.VirtualAddress && Addr < Seg.VirtualAddress + Seg.VirtualSize) {
                return true;
            }
        }
        return false;
    };

    struct RttiClass {
        QString MangledName;
        QString ClassName;
        Address TypeInfoAddr;
        Address VtableAddr;
        int TypeInfoKind;
        QList<Address> BaseClasses;
    };

    QMap<Address, RttiClass> FoundClasses;

    QMap<Address, QString> SymbolNames = Db->GetAllNames();

    QMap<Address, Address> TypeInfoSymbols;
    QMap<Address, Address> VtableSymbols;

    for (auto It = SymbolNames.constBegin(); It != SymbolNames.constEnd(); ++It) {
        if (Cancelled.loadRelaxed()) return;
        const QString& Name = It.value();
        if (Name.startsWith("_ZTI")) {
            TypeInfoSymbols.insert(It.key(), It.key());
        } else if (Name.startsWith("_ZTV")) {
            VtableSymbols.insert(It.key(), It.key());
        }
    }

    for (const auto& Exp : Info.Exports) {
        if (Cancelled.loadRelaxed()) return;
        if (Exp.Name.startsWith("_ZTI")) {
            TypeInfoSymbols.insert(Exp.Addr, Exp.Addr);
        } else if (Exp.Name.startsWith("_ZTV")) {
            VtableSymbols.insert(Exp.Addr, Exp.Addr);
        }
    }

    for (auto TiIt = TypeInfoSymbols.constBegin(); TiIt != TypeInfoSymbols.constEnd(); ++TiIt) {
        if (Cancelled.loadRelaxed()) return;

        Address TiAddr = TiIt.key();
        QString SymName = Db->GetName(TiAddr);
        if (SymName.isEmpty()) continue;

        QString MangledSuffix = SymName.mid(4);

        Address VptrAddr = ReadPtrAt(TiAddr);
        Address NamePtrAddr = ReadPtrAt(TiAddr + PtrSize);
        if (NamePtrAddr == 0) continue;

        QString RawName = ReadCStringAt(NamePtrAddr);
        if (RawName.isEmpty()) continue;

        QString ClassName = DemangleName(RawName);

        RttiClass Cls;
        Cls.MangledName = MangledSuffix;
        Cls.ClassName = ClassName;
        Cls.TypeInfoAddr = TiAddr;
        Cls.VtableAddr = 0;
        Cls.TypeInfoKind = 0;

        QMap<Address, QString> AllNames = Db->GetAllNames();
        QString VptrName;
        for (auto Nit = AllNames.constBegin(); Nit != AllNames.constEnd(); ++Nit) {
            if (Nit.key() == VptrAddr || (Nit.key() <= VptrAddr && Nit.key() + 64 > VptrAddr)) {
                VptrName = Nit.value();
                break;
            }
        }

        if (VptrName.contains("__class_type_info")) {
            Cls.TypeInfoKind = 0;
        } else if (VptrName.contains("__si_class_type_info")) {
            Cls.TypeInfoKind = 1;
            Address BaseTypeInfoPtr = ReadPtrAt(TiAddr + PtrSize * 2);
            if (BaseTypeInfoPtr != 0 && IsDataAddress(BaseTypeInfoPtr)) {
                Cls.BaseClasses.append(BaseTypeInfoPtr);
            }
        } else if (VptrName.contains("__vmi_class_type_info")) {
            Cls.TypeInfoKind = 2;
            QByteArray FlagsBytes = ReadBytesAt(TiAddr + PtrSize * 2, 4);
            QByteArray BaseCountBytes = ReadBytesAt(TiAddr + PtrSize * 2 + 4, 4);
            if (BaseCountBytes.size() >= 4) {
                uint32_t BaseCount = 0;
                std::memcpy(&BaseCount, BaseCountBytes.constData(), 4);
                if (BaseCount > 64) BaseCount = 64;

                Address BaseArrayStart = TiAddr + PtrSize * 2 + 8;
                for (uint32_t B = 0; B < BaseCount; ++B) {
                    Address BaseEntryAddr = BaseArrayStart + B * (PtrSize + sizeof(long));
                    Address BaseTypeInfoPtr = ReadPtrAt(BaseEntryAddr);
                    if (BaseTypeInfoPtr != 0 && IsDataAddress(BaseTypeInfoPtr)) {
                        Cls.BaseClasses.append(BaseTypeInfoPtr);
                    }
                }
            }
        } else {
            Address BaseTiPtr = ReadPtrAt(TiAddr + PtrSize * 2);
            if (BaseTiPtr != 0 && IsDataAddress(BaseTiPtr)) {
                Cls.TypeInfoKind = 1;
                Cls.BaseClasses.append(BaseTiPtr);
            } else {
                Cls.TypeInfoKind = 0;
            }
        }

        FoundClasses.insert(TiAddr, Cls);
        ClassesFound++;
    }

    for (auto VtIt = VtableSymbols.constBegin(); VtIt != VtableSymbols.constEnd(); ++VtIt) {
        if (Cancelled.loadRelaxed()) return;

        Address VtAddr = VtIt.key();
        QString SymName = Db->GetName(VtAddr);
        if (SymName.isEmpty()) continue;

        QString MangledSuffix = SymName.mid(4);

        Address RttiPtr = ReadPtrAt(VtAddr + PtrSize);

        QString MatchedClassName;
        for (auto& Cls : FoundClasses) {
            if (Cls.MangledName == MangledSuffix) {
                Cls.VtableAddr = VtAddr;
                MatchedClassName = Cls.ClassName;
                break;
            }
        }

        if (MatchedClassName.isEmpty() && RttiPtr != 0) {
            if (FoundClasses.contains(RttiPtr)) {
                MatchedClassName = FoundClasses[RttiPtr].ClassName;
                FoundClasses[RttiPtr].VtableAddr = VtAddr;
            }
        }

        if (MatchedClassName.isEmpty()) {
            MatchedClassName = DemangleName(MangledSuffix);
        }

        Address FirstVfuncAddr = VtAddr + PtrSize * 2;
        int SlotIdx = 0;

        for (int Limit = 0; Limit < 1024; ++Limit) {
            if (Cancelled.loadRelaxed()) return;

            Address SlotAddr = FirstVfuncAddr + SlotIdx * PtrSize;
            Address FuncPtr = ReadPtrAt(SlotAddr);

            if (FuncPtr == 0) break;
            if (!IsCodeAddress(FuncPtr)) break;

            QByteArray FirstBytes = Db->ReadBytes(FuncPtr, 4);
            if (FirstBytes.size() < 1) break;
            uint8_t FirstByte = static_cast<uint8_t>(FirstBytes[0]);
            if (FirstByte == 0x00 || FirstByte == 0xCC) break;

            QString VfuncName = QString("%1::vfunc_%2").arg(MatchedClassName).arg(SlotIdx);

            if (Db->HasFunction(FuncPtr)) {
                AnalyzedFunction Func = Db->GetFunction(FuncPtr);
                if (Func.Name.startsWith("sub_") || Func.Name.startsWith("fn_")) {
                    Func.Name = VfuncName;
                    Func.DemangledName = VfuncName;
                    Db->UpdateFunction(FuncPtr, Func);
                    Db->SetName(FuncPtr, VfuncName);
                    VtablesNamed++;
                }
            } else {
                Db->SetName(FuncPtr, VfuncName);
                VtablesNamed++;
            }

            SlotIdx++;
        }
    }

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Name != ".data.rel.ro" && Seg.Name != ".data.rel.ro.local") continue;
        if (Seg.Data.isEmpty()) continue;

        const uint8_t* SData = reinterpret_cast<const uint8_t*>(Seg.Data.constData());
        size_t SSize = static_cast<size_t>(Seg.Data.size());

        for (size_t Off = 0; Off + PtrSize * 3 <= SSize; Off += PtrSize) {
            if (Cancelled.loadRelaxed()) return;

            Address CurrentAddr = Seg.VirtualAddress + Off;

            if (TypeInfoSymbols.contains(CurrentAddr) || VtableSymbols.contains(CurrentAddr)) continue;

            Address RttiPtr = ReadPtr(SData, Off + PtrSize);
            if (RttiPtr == 0 || !IsDataAddress(RttiPtr)) continue;

            if (!FoundClasses.contains(RttiPtr)) continue;

            const RttiClass& Cls = FoundClasses[RttiPtr];
            Address FirstVfuncAddr = CurrentAddr + PtrSize * 2;
            Address FirstFunc = ReadPtr(SData, Off + PtrSize * 2);

            if (FirstFunc == 0 || !IsCodeAddress(FirstFunc)) continue;

            QByteArray Probe = Db->ReadBytes(FirstFunc, 4);
            if (Probe.size() < 1) continue;
            uint8_t ProbeByte = static_cast<uint8_t>(Probe[0]);
            if (ProbeByte == 0x00 || ProbeByte == 0xCC) continue;

            int SlotIdx = 0;
            for (int Limit = 0; Limit < 1024; ++Limit) {
                if (Cancelled.loadRelaxed()) return;

                size_t SlotOff = Off + PtrSize * 2 + SlotIdx * PtrSize;
                if (SlotOff + PtrSize > SSize) break;

                Address FuncPtr = ReadPtr(SData, SlotOff);
                if (FuncPtr == 0 || !IsCodeAddress(FuncPtr)) break;

                QByteArray FirstBytes = Db->ReadBytes(FuncPtr, 4);
                if (FirstBytes.size() < 1) break;
                uint8_t FirstByte = static_cast<uint8_t>(FirstBytes[0]);
                if (FirstByte == 0x00 || FirstByte == 0xCC) break;

                QString VfuncName = QString("%1::vfunc_%2").arg(Cls.ClassName).arg(SlotIdx);

                if (Db->HasFunction(FuncPtr)) {
                    AnalyzedFunction Func = Db->GetFunction(FuncPtr);
                    if (Func.Name.startsWith("sub_") || Func.Name.startsWith("fn_")) {
                        Func.Name = VfuncName;
                        Func.DemangledName = VfuncName;
                        Db->UpdateFunction(FuncPtr, Func);
                        Db->SetName(FuncPtr, VfuncName);
                        VtablesNamed++;
                    }
                } else {
                    Db->SetName(FuncPtr, VfuncName);
                    VtablesNamed++;
                }

                SlotIdx++;
            }
        }
    }

    emit LogMessage(QString("RTTI parsing: %1 classes found, %2 vtable functions named").arg(ClassesFound).arg(VtablesNamed));
}

void AnalysisWorker::ParseSeh() {
    BinaryInfo Info = Db->GetBinaryInfo();
    if (!Info.Is64Bit) return;

    const Segment* PdataSeg = nullptr;
    for (const auto& Seg : Info.Segments) {
        if (Seg.Name == ".pdata") {
            PdataSeg = &Seg;
            break;
        }
    }

    if (!PdataSeg || PdataSeg->Data.isEmpty()) return;

    auto FindSegmentData = [&](uint32_t Rva) -> const Segment* {
        for (const auto& Seg : Info.Segments) {
            uint64_t SegRva = Seg.VirtualAddress - Info.ImageBase;
            if (Rva >= SegRva && Rva < SegRva + Seg.VirtualSize) {
                return &Seg;
            }
        }
        return nullptr;
    };

    auto ReadU8FromRva = [&](uint32_t Rva) -> uint8_t {
        const Segment* Seg = FindSegmentData(Rva);
        if (!Seg) return 0;
        uint64_t SegRva = Seg->VirtualAddress - Info.ImageBase;
        size_t Off = static_cast<size_t>(Rva - SegRva);
        if (Off >= static_cast<size_t>(Seg->Data.size())) return 0;
        return static_cast<uint8_t>(Seg->Data[static_cast<int>(Off)]);
    };

    auto ReadU16FromRva = [&](uint32_t Rva) -> uint16_t {
        const Segment* Seg = FindSegmentData(Rva);
        if (!Seg) return 0;
        uint64_t SegRva = Seg->VirtualAddress - Info.ImageBase;
        size_t Off = static_cast<size_t>(Rva - SegRva);
        if (Off + 2 > static_cast<size_t>(Seg->Data.size())) return 0;
        uint16_t Val = 0;
        std::memcpy(&Val, Seg->Data.constData() + Off, 2);
        return Val;
    };

    auto ReadU32FromRva = [&](uint32_t Rva) -> uint32_t {
        const Segment* Seg = FindSegmentData(Rva);
        if (!Seg) return 0;
        uint64_t SegRva = Seg->VirtualAddress - Info.ImageBase;
        size_t Off = static_cast<size_t>(Rva - SegRva);
        if (Off + 4 > static_cast<size_t>(Seg->Data.size())) return 0;
        uint32_t Val = 0;
        std::memcpy(&Val, Seg->Data.constData() + Off, 4);
        return Val;
    };

    const uint8_t* PdataRaw = reinterpret_cast<const uint8_t*>(PdataSeg->Data.constData());
    size_t PdataSize = static_cast<size_t>(PdataSeg->Data.size());
    int EntryCount = static_cast<int>(PdataSize / 12);
    int HandlersFound = 0;

    constexpr uint8_t UNW_FLAG_EHANDLER = 0x01;
    constexpr uint8_t UNW_FLAG_UHANDLER = 0x02;
    constexpr uint8_t UNW_FLAG_CHAININFO = 0x04;

    for (int I = 0; I < EntryCount; ++I) {
        if (Cancelled.loadRelaxed()) return;

        size_t Off = I * 12;
        if (Off + 12 > PdataSize) break;

        uint32_t BeginRva = 0, EndRva = 0, UnwindInfoRva = 0;
        std::memcpy(&BeginRva, PdataRaw + Off, 4);
        std::memcpy(&EndRva, PdataRaw + Off + 4, 4);
        std::memcpy(&UnwindInfoRva, PdataRaw + Off + 8, 4);

        if (BeginRva == 0 || EndRva == 0 || UnwindInfoRva == 0) continue;
        if (EndRva <= BeginRva) continue;

        Address FuncStart = Info.ImageBase + BeginRva;

        uint32_t CurrentUnwindRva = UnwindInfoRva;
        int ChainDepth = 0;
        constexpr int MaxChainDepth = 16;

        while (CurrentUnwindRva != 0 && ChainDepth < MaxChainDepth) {
            ChainDepth++;

            uint8_t VersionAndFlags = ReadU8FromRva(CurrentUnwindRva);
            uint8_t Version = VersionAndFlags & 0x07;
            uint8_t Flags = (VersionAndFlags >> 3) & 0x1F;

            if (Version > 2) break;

            uint8_t SizeOfProlog = ReadU8FromRva(CurrentUnwindRva + 1);
            uint8_t CountOfCodes = ReadU8FromRva(CurrentUnwindRva + 2);
            uint8_t FrameRegAndOffset = ReadU8FromRva(CurrentUnwindRva + 3);

            uint32_t CodesArrayEnd = CurrentUnwindRva + 4 + CountOfCodes * 2;
            if (CountOfCodes % 2 != 0) {
                CodesArrayEnd += 2;
            }

            if (Flags & UNW_FLAG_CHAININFO) {
                uint32_t ChainBeginRva = ReadU32FromRva(CodesArrayEnd);
                uint32_t ChainEndRva = ReadU32FromRva(CodesArrayEnd + 4);
                uint32_t ChainUnwindRva = ReadU32FromRva(CodesArrayEnd + 8);
                CurrentUnwindRva = ChainUnwindRva;
                continue;
            }

            if ((Flags & UNW_FLAG_EHANDLER) || (Flags & UNW_FLAG_UHANDLER)) {
                uint32_t HandlerRva = ReadU32FromRva(CodesArrayEnd);
                if (HandlerRva != 0) {
                    Address HandlerAddr = Info.ImageBase + HandlerRva;

                    if (Db->IsAddressValid(HandlerAddr)) {
                        FunctionStarts.insert(HandlerAddr);

                        if (!Db->HasFunction(HandlerAddr)) {
                            AnalyzedFunction HandlerFunc;
                            HandlerFunc.Name = QString("__exception_handler_%1").arg(HandlerAddr, 0, 16);
                            HandlerFunc.Start = HandlerAddr;
                            HandlerFunc.End = HandlerAddr;
                            HandlerFunc.Size = 0;
                            HandlerFunc.InstructionCount = 0;
                            HandlerFunc.BasicBlockCount = 0;
                            HandlerFunc.StackFrameSize = 0;
                            HandlerFunc.ArgCount = 0;
                            HandlerFunc.IsImported = false;
                            HandlerFunc.IsExported = false;
                            HandlerFunc.IsThunk = false;
                            HandlerFunc.HasExceptionHandler = false;
                            HandlerFunc.ExceptionHandler = 0;
                            Db->AddFunction(HandlerFunc);
                        }

                        Db->SetComment(HandlerAddr, "Exception Handler");

                        if (Db->HasFunction(FuncStart)) {
                            AnalyzedFunction Func = Db->GetFunction(FuncStart);
                            Func.HasExceptionHandler = true;
                            Func.ExceptionHandler = HandlerAddr;
                            Db->UpdateFunction(FuncStart, Func);
                        }

                        HandlersFound++;
                    }
                }
            }

            break;
        }
    }

    emit LogMessage(QString("SEH parsing: %1 exception handlers found from %2 .pdata entries")
        .arg(HandlersFound).arg(EntryCount));
}

void AnalysisWorker::LoadMachO(const QByteArray& Data) {
    if (Data.size() < 32) return;

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    size_t FileSize = static_cast<size_t>(Data.size());

    uint32_t Magic = 0;
    std::memcpy(&Magic, Raw, 4);

    bool NeedSwap = (Magic == 0xCEFAEDFE || Magic == 0xCFFAEDFE || Magic == 0xBEBAFECA);

    auto SwapU32 = [](uint32_t Val) -> uint32_t {
        return ((Val >> 24) & 0xFF) | ((Val >> 8) & 0xFF00) |
               ((Val << 8) & 0xFF0000) | ((Val << 24) & 0xFF000000);
    };

    auto SwapU64 = [](uint64_t Val) -> uint64_t {
        return ((Val >> 56) & 0xFFULL) | ((Val >> 40) & 0xFF00ULL) |
               ((Val >> 24) & 0xFF0000ULL) | ((Val >> 8) & 0xFF000000ULL) |
               ((Val << 8) & 0xFF00000000ULL) | ((Val << 24) & 0xFF0000000000ULL) |
               ((Val << 40) & 0xFF000000000000ULL) | ((Val << 56) & 0xFF00000000000000ULL);
    };

    auto ReadU32 = [&](const uint8_t* Ptr) -> uint32_t {
        uint32_t Val = 0;
        std::memcpy(&Val, Ptr, 4);
        return NeedSwap ? SwapU32(Val) : Val;
    };

    auto ReadU64 = [&](const uint8_t* Ptr) -> uint64_t {
        uint64_t Val = 0;
        std::memcpy(&Val, Ptr, 8);
        return NeedSwap ? SwapU64(Val) : Val;
    };

    uint32_t NormalMagic = NeedSwap ? SwapU32(Magic) : Magic;

    size_t ArchOffset = 0;
    size_t ArchSize = FileSize;

    if (NormalMagic == 0xCAFEBABE) {
        if (FileSize < 8) return;
        uint32_t NumArchs = ReadU32(Raw + 4);
        if (NumArchs > 16) NumArchs = 16;

        bool FoundArch = false;
        for (uint32_t A = 0; A < NumArchs; ++A) {
            size_t FatOff = 8 + A * 20;
            if (FatOff + 20 > FileSize) break;

            uint32_t CpuType = ReadU32(Raw + FatOff);
            uint32_t FatOffset = ReadU32(Raw + FatOff + 8);
            uint32_t FatSize = ReadU32(Raw + FatOff + 12);

            if (CpuType == 0x01000007 || CpuType == 0x0100000C) {
                ArchOffset = FatOffset;
                ArchSize = FatSize;
                FoundArch = true;
                break;
            }
        }

        if (!FoundArch && NumArchs > 0) {
            size_t FatOff = 8;
            ArchOffset = ReadU32(Raw + FatOff + 8);
            ArchSize = ReadU32(Raw + FatOff + 12);
        }

        if (ArchOffset + ArchSize > FileSize) return;
        Raw = reinterpret_cast<const uint8_t*>(Data.constData()) + ArchOffset;
        FileSize = ArchSize;

        std::memcpy(&Magic, Raw, 4);
        NeedSwap = (Magic == 0xCEFAEDFE || Magic == 0xCFFAEDFE);
        NormalMagic = NeedSwap ? SwapU32(Magic) : Magic;
    }

    bool Is64 = (NormalMagic == 0xFEEDFACF);
    size_t HeaderSize = Is64 ? 32 : 28;
    if (FileSize < HeaderSize) return;

    uint32_t CpuType = ReadU32(Raw + 4);
    uint32_t NcMds = ReadU32(Raw + (Is64 ? 16 : 16));
    uint32_t SizeOfCmds = ReadU32(Raw + (Is64 ? 20 : 20));

    BinaryInfo Info = Db->GetBinaryInfo();
    Info.Is64Bit = Is64;
    Info.IsDll = false;
    Info.IsDriver = false;
    Info.TimeDateStamp = 0;

    uint32_t MaskedCpuType = CpuType & 0x00FFFFFF;
    if (MaskedCpuType == 7) {
        Info.Arch = Is64 ? Architecture::X64 : Architecture::X86;
    } else if (MaskedCpuType == 12) {
        Info.Arch = Is64 ? Architecture::ARM64 : Architecture::ARM;
    } else {
        Info.Arch = Is64 ? Architecture::X64 : Architecture::X86;
    }

    Info.EntryPoint = 0;
    Info.ImageBase = 0;
    Info.ImageSize = 0;

    size_t CmdOffset = HeaderSize;
    Address MinAddr = UINT64_MAX;
    Address MaxAddr = 0;

    constexpr uint32_t LC_SEGMENT = 0x01;
    constexpr uint32_t LC_SYMTAB = 0x02;
    constexpr uint32_t LC_DYSYMTAB = 0x0B;
    constexpr uint32_t LC_SEGMENT_64 = 0x19;
    constexpr uint32_t LC_MAIN = 0x80000028;
    constexpr uint32_t LC_UNIXTHREAD = 0x05;

    struct SymtabInfo {
        uint32_t SymOff;
        uint32_t Nsyms;
        uint32_t StrOff;
        uint32_t StrSize;
    };
    SymtabInfo SymInfo = {0, 0, 0, 0};

    struct DysymtabInfo {
        uint32_t IndirectSymOff;
        uint32_t NIndirectSyms;
    };
    DysymtabInfo DysymInfo = {0, 0};

    struct SectionRecord {
        QString SegName;
        QString SectName;
        uint64_t Addr;
        uint64_t Size;
        uint32_t FileOffset;
        uint32_t Reserved1;
    };
    QList<SectionRecord> AllSections;

    for (uint32_t Cmd = 0; Cmd < NcMds; ++Cmd) {
        if (Cancelled.loadRelaxed()) return;
        if (CmdOffset + 8 > FileSize) break;

        uint32_t CmdType = ReadU32(Raw + CmdOffset);
        uint32_t CmdSize = ReadU32(Raw + CmdOffset + 4);
        if (CmdSize < 8 || CmdOffset + CmdSize > FileSize) break;

        if (CmdType == LC_SEGMENT_64 && Is64) {
            if (CmdSize < 72) { CmdOffset += CmdSize; continue; }

            char SegNameBuf[17] = {};
            std::memcpy(SegNameBuf, Raw + CmdOffset + 8, 16);
            QString SegName = QString::fromLatin1(SegNameBuf).trimmed();

            uint64_t VmAddr = ReadU64(Raw + CmdOffset + 24);
            uint64_t VmSize = ReadU64(Raw + CmdOffset + 32);
            uint64_t FileOff = ReadU64(Raw + CmdOffset + 40);
            uint64_t FileSz = ReadU64(Raw + CmdOffset + 48);
            uint32_t MaxProt = ReadU32(Raw + CmdOffset + 56);
            uint32_t InitProt = ReadU32(Raw + CmdOffset + 60);
            uint32_t Nsects = ReadU32(Raw + CmdOffset + 64);

            if (VmAddr > 0 && VmAddr < MinAddr) MinAddr = VmAddr;
            if (VmAddr + VmSize > MaxAddr) MaxAddr = VmAddr + VmSize;

            size_t SectStart = CmdOffset + 72;
            for (uint32_t S = 0; S < Nsects; ++S) {
                size_t SectOff = SectStart + S * 80;
                if (SectOff + 80 > FileSize) break;

                char SectNameBuf[17] = {};
                std::memcpy(SectNameBuf, Raw + SectOff, 16);
                char SectSegNameBuf[17] = {};
                std::memcpy(SectSegNameBuf, Raw + SectOff + 16, 16);

                uint64_t SectAddr = ReadU64(Raw + SectOff + 32);
                uint64_t SectSize = ReadU64(Raw + SectOff + 40);
                uint32_t SectFileOff = ReadU32(Raw + SectOff + 48);
                uint32_t SectFlags = ReadU32(Raw + SectOff + 64);
                uint32_t Reserved1 = ReadU32(Raw + SectOff + 68);

                QString SectName = QString::fromLatin1(SectNameBuf).trimmed();
                QString FullName = SegName + "/" + SectName;

                Segment Seg;
                Seg.Name = FullName;
                Seg.VirtualAddress = SectAddr;
                Seg.VirtualSize = static_cast<size_t>(SectSize);
                Seg.RawOffset = SectFileOff;
                Seg.Characteristics = SectFlags;

                Seg.IsReadable = (InitProt & 0x01) != 0;
                Seg.IsWritable = (InitProt & 0x02) != 0;
                Seg.IsExecutable = (InitProt & 0x04) != 0;

                uint8_t SectType = SectFlags & 0xFF;

                if (SegName == "__TEXT" && SectName == "__text") {
                    Seg.Type = SegmentType::Code;
                    Seg.IsExecutable = true;
                } else if (SegName == "__TEXT" && SectName == "__stubs") {
                    Seg.Type = SegmentType::Code;
                    Seg.IsExecutable = true;
                } else if (SegName == "__TEXT" && SectName == "__stub_helper") {
                    Seg.Type = SegmentType::Code;
                    Seg.IsExecutable = true;
                } else if (SegName == "__DATA" && SectName == "__bss") {
                    Seg.Type = SegmentType::Bss;
                } else if (SegName == "__DATA") {
                    Seg.Type = SegmentType::Data;
                } else if (SegName == "__DATA_CONST") {
                    Seg.Type = SegmentType::Data;
                } else if (Seg.IsExecutable) {
                    Seg.Type = SegmentType::Code;
                } else if (SectType == 1) {
                    Seg.Type = SegmentType::Bss;
                } else {
                    Seg.Type = SegmentType::Data;
                }

                if (SectType != 1 && SectFileOff > 0 && SectSize > 0 &&
                    ArchOffset + SectFileOff + SectSize <= static_cast<size_t>(Data.size())) {
                    Seg.Data = Data.mid(static_cast<int>(ArchOffset + SectFileOff), static_cast<int>(SectSize));
                    Seg.RawSize = static_cast<size_t>(SectSize);
                } else {
                    Seg.Data = QByteArray(static_cast<int>(SectSize), '\0');
                    Seg.RawSize = 0;
                }

                Info.Segments.append(Seg);

                SectionRecord Rec;
                Rec.SegName = SegName;
                Rec.SectName = SectName;
                Rec.Addr = SectAddr;
                Rec.Size = SectSize;
                Rec.FileOffset = SectFileOff;
                Rec.Reserved1 = Reserved1;
                AllSections.append(Rec);
            }
        } else if (CmdType == LC_SEGMENT && !Is64) {
            if (CmdSize < 56) { CmdOffset += CmdSize; continue; }

            char SegNameBuf[17] = {};
            std::memcpy(SegNameBuf, Raw + CmdOffset + 8, 16);
            QString SegName = QString::fromLatin1(SegNameBuf).trimmed();

            uint32_t VmAddr = ReadU32(Raw + CmdOffset + 24);
            uint32_t VmSize = ReadU32(Raw + CmdOffset + 28);
            uint32_t FileOff = ReadU32(Raw + CmdOffset + 32);
            uint32_t FileSz = ReadU32(Raw + CmdOffset + 36);
            uint32_t MaxProt = ReadU32(Raw + CmdOffset + 40);
            uint32_t InitProt = ReadU32(Raw + CmdOffset + 44);
            uint32_t Nsects = ReadU32(Raw + CmdOffset + 48);

            if (VmAddr > 0 && VmAddr < MinAddr) MinAddr = VmAddr;
            if (static_cast<uint64_t>(VmAddr) + VmSize > MaxAddr)
                MaxAddr = static_cast<uint64_t>(VmAddr) + VmSize;

            size_t SectStart = CmdOffset + 56;
            for (uint32_t S = 0; S < Nsects; ++S) {
                size_t SectOff = SectStart + S * 68;
                if (SectOff + 68 > FileSize) break;

                char SectNameBuf[17] = {};
                std::memcpy(SectNameBuf, Raw + SectOff, 16);
                char SectSegNameBuf[17] = {};
                std::memcpy(SectSegNameBuf, Raw + SectOff + 16, 16);

                uint32_t SectAddr = ReadU32(Raw + SectOff + 32);
                uint32_t SectSize = ReadU32(Raw + SectOff + 36);
                uint32_t SectFileOff = ReadU32(Raw + SectOff + 40);
                uint32_t SectFlags = ReadU32(Raw + SectOff + 52);
                uint32_t Reserved1 = ReadU32(Raw + SectOff + 56);

                QString SectName = QString::fromLatin1(SectNameBuf).trimmed();
                QString FullName = SegName + "/" + SectName;

                Segment Seg;
                Seg.Name = FullName;
                Seg.VirtualAddress = SectAddr;
                Seg.VirtualSize = SectSize;
                Seg.RawOffset = SectFileOff;
                Seg.Characteristics = SectFlags;
                Seg.IsReadable = (InitProt & 0x01) != 0;
                Seg.IsWritable = (InitProt & 0x02) != 0;
                Seg.IsExecutable = (InitProt & 0x04) != 0;

                uint8_t SectType = SectFlags & 0xFF;

                if (SegName == "__TEXT" && SectName == "__text") {
                    Seg.Type = SegmentType::Code;
                    Seg.IsExecutable = true;
                } else if (SegName == "__DATA" && SectName == "__bss") {
                    Seg.Type = SegmentType::Bss;
                } else if (SegName == "__DATA") {
                    Seg.Type = SegmentType::Data;
                } else if (Seg.IsExecutable) {
                    Seg.Type = SegmentType::Code;
                } else {
                    Seg.Type = SegmentType::Data;
                }

                if (SectType != 1 && SectFileOff > 0 && SectSize > 0 &&
                    ArchOffset + SectFileOff + SectSize <= static_cast<size_t>(Data.size())) {
                    Seg.Data = Data.mid(static_cast<int>(ArchOffset + SectFileOff), static_cast<int>(SectSize));
                    Seg.RawSize = SectSize;
                } else {
                    Seg.Data = QByteArray(static_cast<int>(SectSize), '\0');
                    Seg.RawSize = 0;
                }

                Info.Segments.append(Seg);

                SectionRecord Rec;
                Rec.SegName = SegName;
                Rec.SectName = SectName;
                Rec.Addr = SectAddr;
                Rec.Size = SectSize;
                Rec.FileOffset = SectFileOff;
                Rec.Reserved1 = Reserved1;
                AllSections.append(Rec);
            }
        } else if (CmdType == LC_SYMTAB) {
            if (CmdSize < 24) { CmdOffset += CmdSize; continue; }
            SymInfo.SymOff = ReadU32(Raw + CmdOffset + 8);
            SymInfo.Nsyms = ReadU32(Raw + CmdOffset + 12);
            SymInfo.StrOff = ReadU32(Raw + CmdOffset + 16);
            SymInfo.StrSize = ReadU32(Raw + CmdOffset + 20);
        } else if (CmdType == LC_DYSYMTAB) {
            if (CmdSize < 80) { CmdOffset += CmdSize; continue; }
            DysymInfo.IndirectSymOff = ReadU32(Raw + CmdOffset + 56);
            DysymInfo.NIndirectSyms = ReadU32(Raw + CmdOffset + 60);
        } else if (CmdType == LC_MAIN) {
            if (CmdSize < 24) { CmdOffset += CmdSize; continue; }
            uint64_t EntryOffset = ReadU64(Raw + CmdOffset + 8);
            Info.EntryPoint = EntryOffset;
        } else if (CmdType == LC_UNIXTHREAD) {
            if (Is64 && CmdSize >= 184) {
                uint64_t Rip = ReadU64(Raw + CmdOffset + 144);
                if (Info.EntryPoint == 0) {
                    Info.EntryPoint = Rip;
                }
            } else if (!Is64 && CmdSize >= 72) {
                uint32_t Eip = ReadU32(Raw + CmdOffset + 56);
                if (Info.EntryPoint == 0) {
                    Info.EntryPoint = Eip;
                }
            }
        }

        CmdOffset += CmdSize;
    }

    if (MinAddr != UINT64_MAX) {
        Info.ImageBase = MinAddr;
    }
    if (MaxAddr > MinAddr) {
        Info.ImageSize = static_cast<size_t>(MaxAddr - MinAddr);
    }

    if (Info.EntryPoint != 0 && Info.EntryPoint < Info.ImageBase) {
        Info.EntryPoint += Info.ImageBase;
    }

    const uint8_t* OrigRaw = reinterpret_cast<const uint8_t*>(Data.constData());
    size_t OrigSize = static_cast<size_t>(Data.size());

    if (SymInfo.Nsyms > 0 && SymInfo.SymOff > 0 && SymInfo.StrOff > 0) {
        size_t RealSymOff = ArchOffset + SymInfo.SymOff;
        size_t RealStrOff = ArchOffset + SymInfo.StrOff;

        if (RealStrOff + SymInfo.StrSize <= OrigSize) {
            QByteArray StrTable = Data.mid(static_cast<int>(RealStrOff), static_cast<int>(SymInfo.StrSize));

            int NlistSize = Is64 ? 16 : 12;
            for (uint32_t Idx = 0; Idx < SymInfo.Nsyms; ++Idx) {
                if (Cancelled.loadRelaxed()) return;
                size_t SymOff = RealSymOff + Idx * NlistSize;
                if (SymOff + NlistSize > OrigSize) break;

                uint32_t NStrx = ReadU32(OrigRaw + SymOff);
                uint8_t NType = OrigRaw[SymOff + 4];
                uint8_t NSect = OrigRaw[SymOff + 5];
                uint64_t NValue = 0;

                if (Is64) {
                    NValue = ReadU64(OrigRaw + SymOff + 8);
                } else {
                    NValue = ReadU32(OrigRaw + SymOff + 8);
                }

                if (NStrx == 0 || NStrx >= SymInfo.StrSize) continue;
                if (NValue == 0) continue;

                QString SymName = QString::fromLatin1(StrTable.constData() + NStrx);
                if (SymName.isEmpty()) continue;
                if (SymName.startsWith("_")) SymName = SymName.mid(1);

                bool IsExtern = (NType & 0x01) != 0;
                uint8_t TypeField = (NType & 0x0E) >> 1;
                bool IsDefined = (TypeField == 0x07 || TypeField == 0x06);
                bool IsUndefined = (TypeField == 0x00);

                if (IsUndefined && IsExtern) {
                    ImportEntry Imp;
                    Imp.DllName = QString();
                    Imp.FuncName = SymName;
                    Imp.Ordinal = 0;
                    Imp.IatAddress = NValue;
                    Imp.ThunkAddress = NValue;
                    Imp.IsBound = false;
                    Info.Imports.append(Imp);
                } else if (NValue != 0 && NSect != 0) {
                    ExportEntry Exp;
                    Exp.Name = SymName;
                    Exp.Ordinal = 0;
                    Exp.Addr = NValue;
                    Exp.Rva = static_cast<uint32_t>(NValue - Info.ImageBase);
                    Exp.IsForwarder = false;
                    Info.Exports.append(Exp);
                }
            }
        }
    }

    if (DysymInfo.NIndirectSyms > 0 && DysymInfo.IndirectSymOff > 0 && SymInfo.Nsyms > 0) {
        size_t RealIndOff = ArchOffset + DysymInfo.IndirectSymOff;
        size_t RealSymOff = ArchOffset + SymInfo.SymOff;
        size_t RealStrOff = ArchOffset + SymInfo.StrOff;
        int NlistSize = Is64 ? 16 : 12;

        if (RealStrOff + SymInfo.StrSize <= OrigSize) {
            QByteArray StrTable = Data.mid(static_cast<int>(RealStrOff), static_cast<int>(SymInfo.StrSize));

            for (const auto& Sec : AllSections) {
                uint8_t SectType = 0;
                for (const auto& Seg : Info.Segments) {
                    if (Seg.Name == Sec.SegName + "/" + Sec.SectName) {
                        SectType = Seg.Characteristics & 0xFF;
                        break;
                    }
                }

                if (SectType != 0x06 && SectType != 0x08) continue;

                uint32_t IndirectBase = Sec.Reserved1;
                uint32_t PtrSize = Is64 ? 8 : 4;
                uint32_t StubCount = static_cast<uint32_t>(Sec.Size / PtrSize);

                for (uint32_t J = 0; J < StubCount; ++J) {
                    uint32_t IndIdx = IndirectBase + J;
                    if (IndIdx >= DysymInfo.NIndirectSyms) break;

                    size_t IndEntryOff = RealIndOff + IndIdx * 4;
                    if (IndEntryOff + 4 > OrigSize) break;

                    uint32_t SymIdx = ReadU32(OrigRaw + IndEntryOff);
                    if (SymIdx == 0x80000000 || SymIdx == 0x40000000) continue;
                    if (SymIdx >= SymInfo.Nsyms) continue;

                    size_t SymOff = RealSymOff + SymIdx * NlistSize;
                    if (SymOff + NlistSize > OrigSize) continue;

                    uint32_t NStrx = ReadU32(OrigRaw + SymOff);
                    if (NStrx == 0 || NStrx >= SymInfo.StrSize) continue;

                    QString SymName = QString::fromLatin1(StrTable.constData() + NStrx);
                    if (SymName.startsWith("_")) SymName = SymName.mid(1);

                    Address StubAddr = Sec.Addr + J * PtrSize;
                    Db->SetName(StubAddr, SymName);
                }
            }
        }
    }

    emit LogMessage(QString("Mach-O loaded: %1 sections, %2 imports, %3 exports, entry=0x%4, base=0x%5")
        .arg(Info.Segments.size())
        .arg(Info.Imports.size())
        .arg(Info.Exports.size())
        .arg(Info.EntryPoint, 0, 16)
        .arg(Info.ImageBase, 0, 16));

    Db->SetBinaryInfo(Info);
}

void AnalysisWorker::GenerateAutoComments() {
    BinaryInfo Info = Db->GetBinaryInfo();

    struct ApiParam {
        QString Name;
        QString Signature;
    };

    QMap<QString, ApiParam> KnownApis;

    KnownApis["malloc"] = {"malloc", "malloc(size_t Size)"};
    KnownApis["free"] = {"free", "free(void* Ptr)"};
    KnownApis["calloc"] = {"calloc", "calloc(size_t Nmemb, size_t Size)"};
    KnownApis["realloc"] = {"realloc", "realloc(void* Ptr, size_t Size)"};
    KnownApis["memcpy"] = {"memcpy", "memcpy(void* Dst, const void* Src, size_t N)"};
    KnownApis["memmove"] = {"memmove", "memmove(void* Dst, const void* Src, size_t N)"};
    KnownApis["memset"] = {"memset", "memset(void* S, int C, size_t N)"};
    KnownApis["memcmp"] = {"memcmp", "memcmp(const void* S1, const void* S2, size_t N)"};
    KnownApis["strcmp"] = {"strcmp", "strcmp(const char* S1, const char* S2)"};
    KnownApis["strncmp"] = {"strncmp", "strncmp(const char* S1, const char* S2, size_t N)"};
    KnownApis["strcpy"] = {"strcpy", "strcpy(char* Dst, const char* Src)"};
    KnownApis["strncpy"] = {"strncpy", "strncpy(char* Dst, const char* Src, size_t N)"};
    KnownApis["strlen"] = {"strlen", "strlen(const char* S)"};
    KnownApis["strcat"] = {"strcat", "strcat(char* Dst, const char* Src)"};
    KnownApis["printf"] = {"printf", "printf(const char* Fmt, ...)"};
    KnownApis["fprintf"] = {"fprintf", "fprintf(FILE* Stream, const char* Fmt, ...)"};
    KnownApis["sprintf"] = {"sprintf", "sprintf(char* Str, const char* Fmt, ...)"};
    KnownApis["snprintf"] = {"snprintf", "snprintf(char* Str, size_t Size, const char* Fmt, ...)"};
    KnownApis["open"] = {"open", "open(const char* Path, int Flags, ...)"};
    KnownApis["close"] = {"close", "close(int Fd)"};
    KnownApis["read"] = {"read", "read(int Fd, void* Buf, size_t Count)"};
    KnownApis["write"] = {"write", "write(int Fd, const void* Buf, size_t Count)"};
    KnownApis["lseek"] = {"lseek", "lseek(int Fd, off_t Offset, int Whence)"};
    KnownApis["mmap"] = {"mmap", "mmap(void* Addr, size_t Len, int Prot, int Flags, int Fd, off_t Off)"};
    KnownApis["munmap"] = {"munmap", "munmap(void* Addr, size_t Len)"};
    KnownApis["mprotect"] = {"mprotect", "mprotect(void* Addr, size_t Len, int Prot)"};
    KnownApis["socket"] = {"socket", "socket(int Domain, int Type, int Proto)"};
    KnownApis["connect"] = {"connect", "connect(int Fd, const struct sockaddr* Addr, socklen_t Len)"};
    KnownApis["bind"] = {"bind", "bind(int Fd, const struct sockaddr* Addr, socklen_t Len)"};
    KnownApis["listen"] = {"listen", "listen(int Fd, int Backlog)"};
    KnownApis["accept"] = {"accept", "accept(int Fd, struct sockaddr* Addr, socklen_t* Len)"};
    KnownApis["send"] = {"send", "send(int Fd, const void* Buf, size_t Len, int Flags)"};
    KnownApis["recv"] = {"recv", "recv(int Fd, void* Buf, size_t Len, int Flags)"};
    KnownApis["sendto"] = {"sendto", "sendto(int Fd, const void* Buf, size_t Len, int Flags, const struct sockaddr* Addr, socklen_t Addrlen)"};
    KnownApis["recvfrom"] = {"recvfrom", "recvfrom(int Fd, void* Buf, size_t Len, int Flags, struct sockaddr* Addr, socklen_t* Addrlen)"};
    KnownApis["fopen"] = {"fopen", "fopen(const char* Path, const char* Mode)"};
    KnownApis["fclose"] = {"fclose", "fclose(FILE* Stream)"};
    KnownApis["fread"] = {"fread", "fread(void* Ptr, size_t Size, size_t Nmemb, FILE* Stream)"};
    KnownApis["fwrite"] = {"fwrite", "fwrite(const void* Ptr, size_t Size, size_t Nmemb, FILE* Stream)"};
    KnownApis["execve"] = {"execve", "execve(const char* Path, char* const Argv[], char* const Envp[])"};
    KnownApis["fork"] = {"fork", "fork(void)"};
    KnownApis["exit"] = {"exit", "exit(int Status)"};
    KnownApis["_exit"] = {"_exit", "_exit(int Status)"};
    KnownApis["ioctl"] = {"ioctl", "ioctl(int Fd, unsigned long Request, ...)"};
    KnownApis["dlopen"] = {"dlopen", "dlopen(const char* Filename, int Flags)"};
    KnownApis["dlsym"] = {"dlsym", "dlsym(void* Handle, const char* Symbol)"};
    KnownApis["dlclose"] = {"dlclose", "dlclose(void* Handle)"};
    KnownApis["pthread_create"] = {"pthread_create", "pthread_create(pthread_t* Thread, const pthread_attr_t* Attr, void* (*Start)(void*), void* Arg)"};
    KnownApis["pthread_join"] = {"pthread_join", "pthread_join(pthread_t Thread, void** Retval)"};

    KnownApis["CreateFileA"] = {"CreateFileA", "CreateFileA(LPCSTR FileName, DWORD Access, DWORD ShareMode, LPSECURITY_ATTRIBUTES Sec, DWORD Disposition, DWORD Flags, HANDLE Template)"};
    KnownApis["CreateFileW"] = {"CreateFileW", "CreateFileW(LPCWSTR FileName, DWORD Access, DWORD ShareMode, LPSECURITY_ATTRIBUTES Sec, DWORD Disposition, DWORD Flags, HANDLE Template)"};
    KnownApis["ReadFile"] = {"ReadFile", "ReadFile(HANDLE File, LPVOID Buf, DWORD ToRead, LPDWORD Read, LPOVERLAPPED Overlapped)"};
    KnownApis["WriteFile"] = {"WriteFile", "WriteFile(HANDLE File, LPCVOID Buf, DWORD ToWrite, LPDWORD Written, LPOVERLAPPED Overlapped)"};
    KnownApis["CloseHandle"] = {"CloseHandle", "CloseHandle(HANDLE Object)"};
    KnownApis["VirtualAlloc"] = {"VirtualAlloc", "VirtualAlloc(LPVOID Addr, SIZE_T Size, DWORD AllocType, DWORD Protect)"};
    KnownApis["VirtualAllocEx"] = {"VirtualAllocEx", "VirtualAllocEx(HANDLE Process, LPVOID Addr, SIZE_T Size, DWORD AllocType, DWORD Protect)"};
    KnownApis["VirtualFree"] = {"VirtualFree", "VirtualFree(LPVOID Addr, SIZE_T Size, DWORD FreeType)"};
    KnownApis["VirtualProtect"] = {"VirtualProtect", "VirtualProtect(LPVOID Addr, SIZE_T Size, DWORD NewProtect, PDWORD OldProtect)"};
    KnownApis["VirtualProtectEx"] = {"VirtualProtectEx", "VirtualProtectEx(HANDLE Process, LPVOID Addr, SIZE_T Size, DWORD NewProtect, PDWORD OldProtect)"};
    KnownApis["LoadLibraryA"] = {"LoadLibraryA", "LoadLibraryA(LPCSTR LibFileName)"};
    KnownApis["LoadLibraryW"] = {"LoadLibraryW", "LoadLibraryW(LPCWSTR LibFileName)"};
    KnownApis["LoadLibraryExA"] = {"LoadLibraryExA", "LoadLibraryExA(LPCSTR LibFileName, HANDLE File, DWORD Flags)"};
    KnownApis["LoadLibraryExW"] = {"LoadLibraryExW", "LoadLibraryExW(LPCWSTR LibFileName, HANDLE File, DWORD Flags)"};
    KnownApis["GetProcAddress"] = {"GetProcAddress", "GetProcAddress(HMODULE Module, LPCSTR ProcName)"};
    KnownApis["FreeLibrary"] = {"FreeLibrary", "FreeLibrary(HMODULE Module)"};
    KnownApis["CreateThread"] = {"CreateThread", "CreateThread(LPSECURITY_ATTRIBUTES Sec, SIZE_T StackSize, LPTHREAD_START_ROUTINE Start, LPVOID Param, DWORD Flags, LPDWORD ThreadId)"};
    KnownApis["CreateRemoteThread"] = {"CreateRemoteThread", "CreateRemoteThread(HANDLE Process, LPSECURITY_ATTRIBUTES Sec, SIZE_T StackSize, LPTHREAD_START_ROUTINE Start, LPVOID Param, DWORD Flags, LPDWORD ThreadId)"};
    KnownApis["NtQueryInformationProcess"] = {"NtQueryInformationProcess", "NtQueryInformationProcess(HANDLE Process, PROCESSINFOCLASS InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen)"};
    KnownApis["NtQuerySystemInformation"] = {"NtQuerySystemInformation", "NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID Info, ULONG InfoLen, PULONG RetLen)"};
    KnownApis["ReadProcessMemory"] = {"ReadProcessMemory", "ReadProcessMemory(HANDLE Process, LPCVOID BaseAddr, LPVOID Buf, SIZE_T Size, SIZE_T* Read)"};
    KnownApis["WriteProcessMemory"] = {"WriteProcessMemory", "WriteProcessMemory(HANDLE Process, LPVOID BaseAddr, LPCVOID Buf, SIZE_T Size, SIZE_T* Written)"};
    KnownApis["OpenProcess"] = {"OpenProcess", "OpenProcess(DWORD Access, BOOL Inherit, DWORD Pid)"};
    KnownApis["GetModuleHandleA"] = {"GetModuleHandleA", "GetModuleHandleA(LPCSTR ModuleName)"};
    KnownApis["GetModuleHandleW"] = {"GetModuleHandleW", "GetModuleHandleW(LPCWSTR ModuleName)"};
    KnownApis["HeapAlloc"] = {"HeapAlloc", "HeapAlloc(HANDLE Heap, DWORD Flags, SIZE_T Bytes)"};
    KnownApis["HeapFree"] = {"HeapFree", "HeapFree(HANDLE Heap, DWORD Flags, LPVOID Mem)"};
    KnownApis["GetLastError"] = {"GetLastError", "GetLastError(void)"};
    KnownApis["SetLastError"] = {"SetLastError", "SetLastError(DWORD ErrCode)"};
    KnownApis["ExitProcess"] = {"ExitProcess", "ExitProcess(UINT ExitCode)"};
    KnownApis["TerminateProcess"] = {"TerminateProcess", "TerminateProcess(HANDLE Process, UINT ExitCode)"};
    KnownApis["RegOpenKeyExA"] = {"RegOpenKeyExA", "RegOpenKeyExA(HKEY Key, LPCSTR SubKey, DWORD Options, REGSAM Desired, PHKEY Result)"};
    KnownApis["RegOpenKeyExW"] = {"RegOpenKeyExW", "RegOpenKeyExW(HKEY Key, LPCWSTR SubKey, DWORD Options, REGSAM Desired, PHKEY Result)"};
    KnownApis["RegQueryValueExA"] = {"RegQueryValueExA", "RegQueryValueExA(HKEY Key, LPCSTR ValueName, LPDWORD Reserved, LPDWORD Type, LPBYTE Data, LPDWORD CbData)"};
    KnownApis["RegQueryValueExW"] = {"RegQueryValueExW", "RegQueryValueExW(HKEY Key, LPCWSTR ValueName, LPDWORD Reserved, LPDWORD Type, LPBYTE Data, LPDWORD CbData)"};

    struct ConstInfo {
        uint64_t Value;
        QString Name;
    };

    QList<ConstInfo> KnownConstants;
    KnownConstants.append({0x40, "PAGE_EXECUTE_READWRITE"});
    KnownConstants.append({0x20, "PAGE_EXECUTE_READ"});
    KnownConstants.append({0x10, "PAGE_EXECUTE"});
    KnownConstants.append({0x04, "PAGE_READWRITE"});
    KnownConstants.append({0x02, "PAGE_READONLY"});
    KnownConstants.append({0x01, "PAGE_NOACCESS"});
    KnownConstants.append({0x1000, "MEM_COMMIT"});
    KnownConstants.append({0x2000, "MEM_RESERVE"});
    KnownConstants.append({0x3000, "MEM_COMMIT|MEM_RESERVE"});
    KnownConstants.append({0x8000, "MEM_RELEASE"});
    KnownConstants.append({0x80000000ULL, "GENERIC_READ"});
    KnownConstants.append({0x40000000ULL, "GENERIC_WRITE"});
    KnownConstants.append({0xC0000000ULL, "GENERIC_READ|GENERIC_WRITE"});
    KnownConstants.append({0x10000000ULL, "GENERIC_ALL"});
    KnownConstants.append({0x01, "CREATE_NEW"});
    KnownConstants.append({0x02, "CREATE_ALWAYS"});
    KnownConstants.append({0x03, "OPEN_EXISTING"});
    KnownConstants.append({0x04, "OPEN_ALWAYS"});

    QMap<Address, QString> FuncNamesByAddr;
    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    for (const auto& Func : AllFuncs) {
        FuncNamesByAddr[Func.Start] = Func.Name;
        if (!Func.DemangledName.isEmpty()) {
            FuncNamesByAddr[Func.Start] = Func.DemangledName;
        }
    }

    QMap<Address, QString> AllNames = Db->GetAllNames();
    for (auto It = AllNames.constBegin(); It != AllNames.constEnd(); ++It) {
        if (!FuncNamesByAddr.contains(It.key())) {
            FuncNamesByAddr[It.key()] = It.value();
        }
    }

    int CommentsAdded = 0;

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Cancelled.loadRelaxed()) return;
            if (!Insn.IsCall) continue;
            if (!Insn.Comment.isEmpty()) continue;

            Address Target = Insn.BranchTarget;
            if (Target == 0 && Insn.MemoryRef != 0) {
                Target = Insn.MemoryRef;
            }
            if (Target == 0) continue;

            QString TargetName;
            if (FuncNamesByAddr.contains(Target)) {
                TargetName = FuncNamesByAddr[Target];
            }

            if (TargetName.isEmpty()) continue;

            QString BaseName = TargetName;
            int DotIdx = BaseName.lastIndexOf('.');
            if (DotIdx >= 0) BaseName = BaseName.mid(DotIdx + 1);
            int ColonIdx = BaseName.lastIndexOf("::");
            if (ColonIdx >= 0) BaseName = BaseName.mid(ColonIdx + 2);

            if (KnownApis.contains(BaseName)) {
                AnalyzedInstruction Modified = Insn;
                Modified.Comment = KnownApis[BaseName].Signature;
                Db->AddInstruction(Modified);
                CommentsAdded++;
            }
        }
    }

    for (const Segment& Seg : Info.Segments) {
        if (Cancelled.loadRelaxed()) return;
        if (Seg.Type != SegmentType::Code) continue;

        QList<AnalyzedInstruction> Insns = Db->GetInstructions(
            Seg.VirtualAddress, Seg.VirtualAddress + Seg.VirtualSize);

        for (const auto& Insn : Insns) {
            if (Cancelled.loadRelaxed()) return;

            if (Insn.Mnemonic == "syscall" || Insn.Mnemonic == "int" || Insn.Mnemonic == "sysenter") {
                if (!Insn.Comment.isEmpty()) continue;

                AnalyzedInstruction Modified = Insn;
                Modified.Comment = "syscall (check RAX for syscall number)";
                Db->AddInstruction(Modified);
                CommentsAdded++;
                continue;
            }

            if (!Insn.Comment.isEmpty()) continue;
            if (Insn.IsCall || Insn.IsJump || Insn.IsRet) continue;

            QString Ops = Insn.Operands;
            bool FoundConst = false;

            for (const auto& Const : KnownConstants) {
                if (FoundConst) break;

                QString HexStr = QString("0x%1").arg(Const.Value, 0, 16);
                QString HexStrLower = HexStr.toLower();

                if (Ops.contains(HexStr, Qt::CaseInsensitive) ||
                    Ops.contains(QString::number(Const.Value))) {

                    if (Const.Value <= 4) continue;

                    AnalyzedInstruction Modified = Insn;
                    Modified.Comment = Const.Name;
                    Db->AddInstruction(Modified);
                    CommentsAdded++;
                    FoundConst = true;
                }
            }
        }
    }

    emit LogMessage(QString("Auto-comments: %1 comments added").arg(CommentsAdded));
}

void AnalysisWorker::DemangleExtended() {
    int DemangledCount = 0;

    auto DemangleRustV0 = [](const QString& Name) -> QString {
        if (!Name.startsWith("_R")) return QString();

        QString Work = Name.mid(2);
        QString Result;
        int Idx = 0;

        if (Idx < Work.size() && Work[Idx] == 'N') {
            Idx++;

            while (Idx < Work.size()) {
                if (Work[Idx] == 'C' || Work[Idx] == 'M' || Work[Idx] == 'X' ||
                    Work[Idx] == 'Y' || Work[Idx] == 'I' || Work[Idx] == 'B') {
                    Idx++;
                }

                int SegLen = 0;
                bool HasPrefix = false;
                if (Idx < Work.size() && Work[Idx] == 'u') {
                    Idx++;
                    HasPrefix = true;
                }

                while (Idx < Work.size() && Work[Idx].isDigit()) {
                    SegLen = SegLen * 10 + Work[Idx].digitValue();
                    Idx++;
                }

                if (SegLen > 0 && Idx + SegLen <= Work.size()) {
                    if (Idx < Work.size() && Work[Idx] == '_') Idx++;
                    QString Segment = Work.mid(Idx, SegLen);
                    if (!Result.isEmpty()) Result += "::";
                    Result += Segment;
                    Idx += SegLen;
                } else {
                    break;
                }

                if (Idx < Work.size() && Work[Idx] == 'E') {
                    break;
                }
            }
        }

        if (Result.isEmpty()) return QString();
        return Result;
    };

    auto DemangleRustLegacy = [](const QString& Name) -> QString {
        if (!Name.startsWith("_ZN")) return QString();

        QString Work = Name.mid(3);
        QString Result;
        int Idx = 0;

        while (Idx < Work.size() && Work[Idx].isDigit()) {
            int SegLen = 0;
            while (Idx < Work.size() && Work[Idx].isDigit()) {
                SegLen = SegLen * 10 + Work[Idx].digitValue();
                Idx++;
            }

            if (SegLen > 0 && Idx + SegLen <= Work.size()) {
                QString Segment = Work.mid(Idx, SegLen);

                if (Segment.startsWith("17h") && Segment.size() == 19) {
                    Idx += SegLen;
                    continue;
                }

                Segment.replace("$SP$", "@");
                Segment.replace("$BP$", "*");
                Segment.replace("$RF$", "&");
                Segment.replace("$LT$", "<");
                Segment.replace("$GT$", ">");
                Segment.replace("$LP$", "(");
                Segment.replace("$RP$", ")");
                Segment.replace("$C$", ",");
                Segment.replace("..", "::");

                if (!Result.isEmpty()) Result += "::";
                Result += Segment;
                Idx += SegLen;
            } else {
                break;
            }
        }

        if (Result.isEmpty()) return QString();
        return Result;
    };

    auto DemangleGo = [](const QString& Name) -> QString {
        if (!Name.contains('.')) return QString();

        bool LooksLikeGo = false;
        if (Name.startsWith("go.") || Name.startsWith("type.") ||
            Name.startsWith("runtime.") || Name.startsWith("main.") ||
            Name.startsWith("fmt.") || Name.startsWith("os.") ||
            Name.startsWith("net.") || Name.startsWith("sync.") ||
            Name.startsWith("io.") || Name.startsWith("bufio.") ||
            Name.startsWith("bytes.") || Name.startsWith("strings.") ||
            Name.startsWith("encoding.") || Name.startsWith("crypto.") ||
            Name.startsWith("math.") || Name.startsWith("reflect.") ||
            Name.startsWith("syscall.") || Name.startsWith("internal.") ||
            Name.startsWith("unicode.") || Name.startsWith("strconv.") ||
            Name.startsWith("sort.") || Name.startsWith("errors.") ||
            Name.startsWith("context.") || Name.startsWith("path.") ||
            Name.startsWith("time.")) {
            LooksLikeGo = true;
        }

        if (!LooksLikeGo) {
            int DotCount = 0;
            for (const QChar& C : Name) {
                if (C == '.') DotCount++;
            }
            if (DotCount >= 1 && DotCount <= 5) {
                bool AllValid = true;
                for (const QChar& C : Name) {
                    if (!C.isLetterOrNumber() && C != '.' && C != '_' && C != '*' && C != '(' && C != ')') {
                        AllValid = false;
                        break;
                    }
                }
                if (AllValid) LooksLikeGo = true;
            }
        }

        if (!LooksLikeGo) return QString();

        QString Result = Name;
        Result.replace(".", "::");
        return Result;
    };

    auto DemangleSwift = [](const QString& Name) -> QString {
        QString Work = Name;
        if (Work.startsWith("_$s") || Work.startsWith("_$S")) {
            Work = Work.mid(1);
        }
        if (!Work.startsWith("$s") && !Work.startsWith("$S")) return QString();

        Work = Work.mid(2);
        QString Result;
        int Idx = 0;

        while (Idx < Work.size()) {
            int SegLen = 0;
            while (Idx < Work.size() && Work[Idx].isDigit()) {
                SegLen = SegLen * 10 + Work[Idx].digitValue();
                Idx++;
            }

            if (SegLen > 0 && Idx + SegLen <= Work.size()) {
                QString Segment = Work.mid(Idx, SegLen);
                if (!Result.isEmpty()) Result += "::";
                Result += Segment;
                Idx += SegLen;
            } else {
                break;
            }
        }

        if (Result.isEmpty()) return QString();
        return Result;
    };

    auto DemangleDlang = [](const QString& Name) -> QString {
        if (!Name.startsWith("_D")) return QString();

        QString Work = Name.mid(2);
        QString Result;
        int Idx = 0;

        while (Idx < Work.size() && Work[Idx].isDigit()) {
            int SegLen = 0;
            while (Idx < Work.size() && Work[Idx].isDigit()) {
                SegLen = SegLen * 10 + Work[Idx].digitValue();
                Idx++;
            }

            if (SegLen > 0 && Idx + SegLen <= Work.size()) {
                QString Segment = Work.mid(Idx, SegLen);
                if (!Result.isEmpty()) Result += ".";
                Result += Segment;
                Idx += SegLen;
            } else {
                break;
            }
        }

        if (Result.isEmpty()) return QString();
        return Result;
    };

    QList<AnalyzedFunction> AllFuncs = Db->GetAllFunctions();
    for (auto& Func : AllFuncs) {
        if (Cancelled.loadRelaxed()) return;
        if (!Func.DemangledName.isEmpty()) continue;

        QString Name = Func.Name;
        QString Demangled;

        if (Name.startsWith("_R")) {
            Demangled = DemangleRustV0(Name);
        }

        if (Demangled.isEmpty() && Name.startsWith("_ZN")) {
            bool HasRustHash = false;
            QRegularExpression RustHashRe("\\d+h[0-9a-f]{16}E");
            if (RustHashRe.match(Name).hasMatch()) {
                HasRustHash = true;
            }
            if (HasRustHash || Name.contains("$")) {
                Demangled = DemangleRustLegacy(Name);
            }
        }

        if (Demangled.isEmpty() && (Name.startsWith("$s") || Name.startsWith("_$s") ||
                                     Name.startsWith("$S") || Name.startsWith("_$S"))) {
            Demangled = DemangleSwift(Name);
        }

        if (Demangled.isEmpty() && Name.startsWith("_D") && !Name.startsWith("_Z")) {
            Demangled = DemangleDlang(Name);
        }

        if (Demangled.isEmpty() && Name.contains('.') && !Name.startsWith("_Z") &&
            !Name.startsWith("sub_") && !Name.startsWith("fn_")) {
            Demangled = DemangleGo(Name);
        }

        if (!Demangled.isEmpty() && Demangled != Name) {
            Func.DemangledName = Demangled;
            Db->UpdateFunction(Func.Start, Func);
            Db->SetName(Func.Start, Demangled);
            DemangledCount++;
        }
    }

    QMap<Address, QString> AllNames = Db->GetAllNames();
    for (auto It = AllNames.constBegin(); It != AllNames.constEnd(); ++It) {
        if (Cancelled.loadRelaxed()) return;
        const QString& Name = It.value();
        if (Db->HasFunction(It.key())) continue;

        QString Demangled;

        if (Name.startsWith("_R")) {
            Demangled = DemangleRustV0(Name);
        }

        if (Demangled.isEmpty() && Name.startsWith("_ZN")) {
            QRegularExpression RustHashRe("\\d+h[0-9a-f]{16}E");
            if (RustHashRe.match(Name).hasMatch() || Name.contains("$")) {
                Demangled = DemangleRustLegacy(Name);
            }
        }

        if (Demangled.isEmpty() && (Name.startsWith("$s") || Name.startsWith("_$s") ||
                                     Name.startsWith("$S") || Name.startsWith("_$S"))) {
            Demangled = DemangleSwift(Name);
        }

        if (Demangled.isEmpty() && Name.startsWith("_D") && !Name.startsWith("_Z")) {
            Demangled = DemangleDlang(Name);
        }

        if (Demangled.isEmpty() && Name.contains('.') && !Name.startsWith("_Z") &&
            !Name.startsWith("sub_") && !Name.startsWith("fn_")) {
            Demangled = DemangleGo(Name);
        }

        if (!Demangled.isEmpty() && Demangled != Name) {
            Db->SetName(It.key(), Demangled);
            DemangledCount++;
        }
    }

    emit LogMessage(QString("Extended demangling: %1 Rust/Go/Swift/D names demangled").arg(DemangledCount));
}

void AnalysisWorker::DetectPackerCompiler() {
    BinaryInfo Info = Db->GetBinaryInfo();

    auto CalcEntropy = [](const QByteArray& Data) -> double {
        if (Data.isEmpty()) return 0.0;
        int Freq[256] = {};
        for (int I = 0; I < Data.size(); ++I) {
            Freq[static_cast<uint8_t>(Data[I])]++;
        }
        double Entropy = 0.0;
        double Size = static_cast<double>(Data.size());
        for (int I = 0; I < 256; ++I) {
            if (Freq[I] == 0) continue;
            double P = static_cast<double>(Freq[I]) / Size;
            Entropy -= P * std::log2(P);
        }
        return Entropy;
    };

    QFile BinaryFile(Info.FilePath);
    QByteArray FullData;
    if (BinaryFile.open(QIODevice::ReadOnly)) {
        FullData = BinaryFile.readAll();
        BinaryFile.close();
    }

    const uint8_t* Raw = nullptr;
    size_t FileSize = 0;
    if (!FullData.isEmpty()) {
        Raw = reinterpret_cast<const uint8_t*>(FullData.constData());
        FileSize = static_cast<size_t>(FullData.size());
    }

    bool IsPe = false;
    uint32_t PeOffset = 0;
    if (FileSize >= 64) {
        uint16_t Mz = 0;
        std::memcpy(&Mz, Raw, 2);
        if (Mz == 0x5A4D) {
            IsPe = true;
            std::memcpy(&PeOffset, Raw + 0x3C, 4);
        }
    }

    bool IsElf = false;
    if (FileSize >= 4) {
        uint32_t ElfMagic = 0;
        std::memcpy(&ElfMagic, Raw, 4);
        if (ElfMagic == 0x464C457F) IsElf = true;
    }

    if (IsPe && PeOffset + 24 < FileSize) {
        size_t RichSearchEnd = std::min(static_cast<size_t>(PeOffset), FileSize);
        size_t RichSignOff = 0;
        for (size_t I = 0; I + 4 <= RichSearchEnd; I += 4) {
            uint32_t Val = 0;
            std::memcpy(&Val, Raw + I, 4);
            if (Val == 0x68636952) {
                RichSignOff = I;
                break;
            }
        }

        if (RichSignOff > 0 && RichSignOff + 8 <= FileSize) {
            uint32_t RichKey = 0;
            std::memcpy(&RichKey, Raw + RichSignOff + 4, 4);

            size_t DansOff = 0;
            for (size_t I = 0; I + 4 <= RichSignOff; I += 4) {
                uint32_t Val = 0;
                std::memcpy(&Val, Raw + I, 4);
                if ((Val ^ RichKey) == 0x536E6144) {
                    DansOff = I;
                    break;
                }
            }

            if (DansOff > 0 && DansOff + 16 <= RichSignOff) {
                struct CompId {
                    uint16_t BuildId;
                    uint16_t ProdId;
                    uint32_t Count;
                };

                QList<CompId> CompIds;
                for (size_t Off = DansOff + 16; Off + 8 <= RichSignOff; Off += 8) {
                    uint32_t DwA = 0, DwB = 0;
                    std::memcpy(&DwA, Raw + Off, 4);
                    std::memcpy(&DwB, Raw + Off + 4, 4);
                    DwA ^= RichKey;
                    DwB ^= RichKey;

                    CompId Id;
                    Id.BuildId = static_cast<uint16_t>(DwA & 0xFFFF);
                    Id.ProdId = static_cast<uint16_t>((DwA >> 16) & 0xFFFF);
                    Id.Count = DwB;
                    if (Id.ProdId != 0 || Id.BuildId != 0) {
                        CompIds.append(Id);
                    }
                }

                uint16_t MaxBuild = 0;
                for (const auto& Cid : CompIds) {
                    if (Cid.BuildId > MaxBuild) MaxBuild = Cid.BuildId;
                }

                if (MaxBuild >= 30000 && MaxBuild < 33000) {
                    Info.Compiler = QString("MSVC 2022 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 29000 && MaxBuild < 30000) {
                    Info.Compiler = QString("MSVC 2019 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 27000 && MaxBuild < 29000) {
                    Info.Compiler = QString("MSVC 2017 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 25000 && MaxBuild < 27000) {
                    Info.Compiler = QString("MSVC 2015 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 21000 && MaxBuild < 25000) {
                    Info.Compiler = QString("MSVC 2013 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 18000 && MaxBuild < 21000) {
                    Info.Compiler = QString("MSVC 2012 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 16000 && MaxBuild < 18000) {
                    Info.Compiler = QString("MSVC 2010 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 15000 && MaxBuild < 16000) {
                    Info.Compiler = QString("MSVC 2008 (build %1)").arg(MaxBuild);
                } else if (MaxBuild >= 14000 && MaxBuild < 15000) {
                    Info.Compiler = QString("MSVC 2005 (build %1)").arg(MaxBuild);
                } else if (MaxBuild > 0) {
                    Info.Compiler = QString("MSVC (build %1)").arg(MaxBuild);
                }
            }
        }

        if (Info.Compiler.isEmpty() && !Info.LinkerVersion.isEmpty()) {
            QStringList Parts = Info.LinkerVersion.split('.');
            if (Parts.size() >= 1) {
                int Major = Parts[0].toInt();
                if (Major == 14) Info.Compiler = "MSVC 2015-2022";
                else if (Major == 12) Info.Compiler = "MSVC 2013";
                else if (Major == 11) Info.Compiler = "MSVC 2012";
                else if (Major == 10) Info.Compiler = "MSVC 2010";
                else if (Major == 9) Info.Compiler = "MSVC 2008";
                else if (Major == 8) Info.Compiler = "MSVC 2005";
                else if (Major == 7) Info.Compiler = "MSVC 2003";
                else if (Major == 6) Info.Compiler = "MSVC 6.0";
            }
        }
    }

    for (const auto& Seg : Info.Segments) {
        QString SName = Seg.Name.toUpper();

        if (SName == "UPX0" || SName == "UPX1" || SName == "UPX2" ||
            SName == ".UPX0" || SName == ".UPX1" || SName == ".UPX2") {
            Info.Packer = "UPX";
            Info.IsPacked = true;
        }
        if (SName == ".ASPACK" || SName == ".ADATA") {
            Info.Packer = "ASPack";
            Info.IsPacked = true;
        }
        if (SName == ".VMP0" || SName == ".VMP1" || SName == ".VMP2") {
            Info.Packer = "VMProtect";
            Info.IsPacked = true;
        }
        if (SName == ".THEMIDA" || SName == ".WINLICE") {
            Info.Packer = "Themida/WinLicense";
            Info.IsPacked = true;
        }
        if (SName == ".ENIGMA1" || SName == ".ENIGMA2") {
            Info.Packer = "Enigma Protector";
            Info.IsPacked = true;
        }
        if (SName == ".NDATA") {
            Info.Packer = "NSIS Installer";
        }
        if (SName == ".PETITE") {
            Info.Packer = "Petite";
            Info.IsPacked = true;
        }
    }

    bool HasMscoree = false;
    bool HasTurboFloat = false;
    bool HasMingwCrt = false;
    bool HasCygwin = false;
    for (const auto& Imp : Info.Imports) {
        QString DllLower = Imp.DllName.toLower();
        QString FuncLower = Imp.FuncName.toLower();

        if (DllLower == "mscoree.dll") HasMscoree = true;
        if (FuncLower == "__turbofloat") HasTurboFloat = true;
        if (FuncLower == "__mingw_crtstartup" || FuncLower == "__mingw_invalidparameterhandler") HasMingwCrt = true;
        if (DllLower.contains("cygwin")) HasCygwin = true;
    }

    if (HasMscoree && Info.Packer.isEmpty()) {
        Info.Compiler = ".NET (CLR)";
    }
    if (HasTurboFloat && Info.Compiler.isEmpty()) {
        Info.Compiler = "Borland/Embarcadero";
    }
    if (HasMingwCrt) {
        Info.Compiler = "MinGW (GCC)";
    }
    if (HasCygwin && Info.Compiler.isEmpty()) {
        Info.Compiler = "Cygwin (GCC)";
    }

    if (IsPe && Info.EntryPoint != 0 && !Info.Segments.isEmpty()) {
        Address FirstCodeAddr = 0;
        for (const auto& Seg : Info.Segments) {
            if (Seg.Type == SegmentType::Code || Seg.IsExecutable) {
                FirstCodeAddr = Seg.VirtualAddress;
                break;
            }
        }

        if (FirstCodeAddr != 0 && Info.EntryPoint != 0) {
            bool EntryInFirstCode = false;
            for (const auto& Seg : Info.Segments) {
                if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
                if (Info.EntryPoint >= Seg.VirtualAddress &&
                    Info.EntryPoint < Seg.VirtualAddress + Seg.VirtualSize) {
                    if (Seg.VirtualAddress == FirstCodeAddr) {
                        EntryInFirstCode = true;
                    }
                    break;
                }
            }

            if (!EntryInFirstCode && Info.Packer.isEmpty()) {
                Info.Packer = "Unknown (entry not in first code section)";
                Info.IsPacked = true;
            }
        }
    }

    double MaxEntropy = 0.0;
    QString MaxEntropySeg;
    for (const auto& Seg : Info.Segments) {
        if (Seg.Type != SegmentType::Code && !Seg.IsExecutable) continue;
        if (Seg.Data.isEmpty()) continue;

        double Entropy = CalcEntropy(Seg.Data);
        if (Entropy > MaxEntropy) {
            MaxEntropy = Entropy;
            MaxEntropySeg = Seg.Name;
        }

        if (Entropy > 7.0 && Info.Packer.isEmpty()) {
            Info.Packer = QString("Possibly packed (section %1, entropy %.2f)").arg(Seg.Name).arg(Entropy);
            Info.IsPacked = true;
        }
    }

    if (IsElf && Raw && FileSize > 0) {
        uint8_t EiClass = Raw[4];
        bool Is64 = (EiClass == 2);

        if (Is64 && FileSize >= 64) {
            uint64_t EShoff = 0;
            std::memcpy(&EShoff, Raw + 40, 8);
            uint16_t EShentsize = 0;
            std::memcpy(&EShentsize, Raw + 58, 2);
            uint16_t EShnum = 0;
            std::memcpy(&EShnum, Raw + 60, 2);
            uint16_t EShstrndx = 0;
            std::memcpy(&EShstrndx, Raw + 62, 2);

            QByteArray ShStrTab;
            if (EShstrndx < EShnum) {
                size_t StrSecOff = static_cast<size_t>(EShoff) + EShstrndx * EShentsize;
                if (StrSecOff + EShentsize <= FileSize) {
                    uint64_t ShOffset = 0;
                    std::memcpy(&ShOffset, Raw + StrSecOff + 24, 8);
                    uint64_t ShSize = 0;
                    std::memcpy(&ShSize, Raw + StrSecOff + 32, 8);
                    if (ShOffset + ShSize <= FileSize) {
                        ShStrTab = FullData.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                    }
                }
            }

            for (uint16_t I = 0; I < EShnum; ++I) {
                size_t SecOff = static_cast<size_t>(EShoff) + I * EShentsize;
                if (SecOff + EShentsize > FileSize) break;

                uint32_t ShName = 0;
                std::memcpy(&ShName, Raw + SecOff, 4);
                uint32_t ShType = 0;
                std::memcpy(&ShType, Raw + SecOff + 4, 4);
                uint64_t ShOffset = 0;
                std::memcpy(&ShOffset, Raw + SecOff + 24, 8);
                uint64_t ShSize = 0;
                std::memcpy(&ShSize, Raw + SecOff + 32, 8);

                QString SectName;
                if (ShName < static_cast<uint32_t>(ShStrTab.size())) {
                    SectName = QString::fromLatin1(ShStrTab.constData() + ShName);
                }

                if (SectName == ".comment" && ShOffset + ShSize <= FileSize && ShSize < 4096) {
                    QByteArray CommentData = FullData.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                    QString CommentStr = QString::fromLatin1(CommentData).trimmed();

                    if (CommentStr.contains("GCC")) {
                        QRegularExpression GccRe("GCC:\\s*\\(.*?\\)\\s*([\\d.]+)");
                        auto Match = GccRe.match(CommentStr);
                        if (Match.hasMatch()) {
                            Info.Compiler = QString("GCC %1").arg(Match.captured(1));
                        } else {
                            Info.Compiler = "GCC";
                        }
                    } else if (CommentStr.contains("clang") || CommentStr.contains("Clang")) {
                        QRegularExpression ClangRe("clang version\\s*([\\d.]+)");
                        auto Match = ClangRe.match(CommentStr);
                        if (Match.hasMatch()) {
                            Info.Compiler = QString("Clang %1").arg(Match.captured(1));
                        } else {
                            Info.Compiler = "Clang/LLVM";
                        }
                    } else if (!CommentStr.isEmpty()) {
                        Info.Compiler = CommentStr.left(64);
                    }
                }

                if (SectName == ".note.go.buildid" && Info.Compiler.isEmpty()) {
                    Info.Compiler = "Go";
                }

                if (SectName == ".note.rustc" && Info.Compiler.isEmpty()) {
                    Info.Compiler = "Rust";
                }
            }
        } else if (!Is64 && FileSize >= 52) {
            uint32_t EShoff = 0;
            std::memcpy(&EShoff, Raw + 32, 4);
            uint16_t EShentsize = 0;
            std::memcpy(&EShentsize, Raw + 46, 2);
            uint16_t EShnum = 0;
            std::memcpy(&EShnum, Raw + 48, 2);
            uint16_t EShstrndx = 0;
            std::memcpy(&EShstrndx, Raw + 50, 2);

            QByteArray ShStrTab;
            if (EShstrndx < EShnum) {
                size_t StrSecOff = EShoff + EShstrndx * EShentsize;
                if (StrSecOff + EShentsize <= FileSize) {
                    uint32_t ShOff = 0;
                    std::memcpy(&ShOff, Raw + StrSecOff + 16, 4);
                    uint32_t ShSz = 0;
                    std::memcpy(&ShSz, Raw + StrSecOff + 20, 4);
                    if (ShOff + ShSz <= FileSize) {
                        ShStrTab = FullData.mid(static_cast<int>(ShOff), static_cast<int>(ShSz));
                    }
                }
            }

            for (uint16_t I = 0; I < EShnum; ++I) {
                size_t SecOff = EShoff + I * EShentsize;
                if (SecOff + EShentsize > FileSize) break;

                uint32_t ShName = 0;
                std::memcpy(&ShName, Raw + SecOff, 4);
                uint32_t ShType = 0;
                std::memcpy(&ShType, Raw + SecOff + 4, 4);
                uint32_t ShOffset = 0;
                std::memcpy(&ShOffset, Raw + SecOff + 16, 4);
                uint32_t ShSize = 0;
                std::memcpy(&ShSize, Raw + SecOff + 20, 4);

                QString SectName;
                if (ShName < static_cast<uint32_t>(ShStrTab.size())) {
                    SectName = QString::fromLatin1(ShStrTab.constData() + ShName);
                }

                if (SectName == ".comment" && ShOffset + ShSize <= FileSize && ShSize < 4096) {
                    QByteArray CommentData = FullData.mid(static_cast<int>(ShOffset), static_cast<int>(ShSize));
                    QString CommentStr = QString::fromLatin1(CommentData).trimmed();

                    if (CommentStr.contains("GCC")) {
                        QRegularExpression GccRe("GCC:\\s*\\(.*?\\)\\s*([\\d.]+)");
                        auto Match = GccRe.match(CommentStr);
                        if (Match.hasMatch()) {
                            Info.Compiler = QString("GCC %1").arg(Match.captured(1));
                        } else {
                            Info.Compiler = "GCC";
                        }
                    } else if (CommentStr.contains("clang") || CommentStr.contains("Clang")) {
                        QRegularExpression ClangRe("clang version\\s*([\\d.]+)");
                        auto Match = ClangRe.match(CommentStr);
                        if (Match.hasMatch()) {
                            Info.Compiler = QString("Clang %1").arg(Match.captured(1));
                        } else {
                            Info.Compiler = "Clang/LLVM";
                        }
                    }
                }

                if (SectName == ".note.go.buildid" && Info.Compiler.isEmpty()) {
                    Info.Compiler = "Go";
                }
            }
        }
    }

    Db->SetBinaryInfo(Info);

    QStringList DetectionParts;
    if (!Info.Compiler.isEmpty()) DetectionParts.append("compiler=" + Info.Compiler);
    if (!Info.Packer.isEmpty()) DetectionParts.append("packer=" + Info.Packer);
    if (Info.IsPacked) DetectionParts.append("packed=true");
    if (MaxEntropy > 0) DetectionParts.append(QString("max_entropy=%.2f in %1").arg(MaxEntropy).arg(MaxEntropySeg));

    if (DetectionParts.isEmpty()) {
        emit LogMessage("Packer/compiler detection: nothing detected");
    } else {
        emit LogMessage(QString("Packer/compiler detection: %1").arg(DetectionParts.join(", ")));
    }
}

void AnalysisWorker::EmitProgress(AnalysisState State, int Percentage, const QString& Message) {
    AnalysisProgress Progress;
    Progress.State = State;
    Progress.Percentage = Percentage;
    Progress.StatusMessage = Message;
    Progress.FunctionsFound = Db->FunctionCount();
    Progress.InstructionsDisassembled = Db->InstructionCount();
    Progress.StringsFound = Db->StringCount();
    Progress.XrefsBuilt = Db->XrefCount();
    emit ProgressChanged(Progress);
}

AnalysisEngine::AnalysisEngine(QObject* Parent)
    : QObject(Parent)
    , Db(new AnalysisDatabase(this))
    , WorkerThread(nullptr)
    , Worker(nullptr)
    , Analyzing(false) {
    LastProgress.State = AnalysisState::Idle;
    LastProgress.Percentage = 0;
    LastProgress.FunctionsFound = 0;
    LastProgress.InstructionsDisassembled = 0;
    LastProgress.StringsFound = 0;
    LastProgress.XrefsBuilt = 0;
}

AnalysisEngine::~AnalysisEngine() {
    CancelAnalysis();
    if (WorkerThread) {
        WorkerThread->quit();
        WorkerThread->wait(5000);
    }
}

bool AnalysisEngine::LoadFile(const QString& FilePath) {
    if (Analyzing) {
        CancelAnalysis();
        if (WorkerThread) {
            WorkerThread->quit();
            WorkerThread->wait(5000);
            delete WorkerThread;
            WorkerThread = nullptr;
            Worker = nullptr;
        }
    }

    Db->Clear();

    BinaryInfo Info;
    Info.FilePath = FilePath;
    Info.FileName = QFileInfo(FilePath).fileName();
    Info.Arch = Architecture::Unknown;
    Info.ImageBase = 0;
    Info.EntryPoint = 0;
    Info.ImageSize = 0;
    Info.Is64Bit = false;
    Info.IsDll = false;
    Info.IsDriver = false;
    Info.TimeDateStamp = 0;
    Info.Subsystem = 0;
    Db->SetBinaryInfo(Info);

    WorkerThread = new QThread(this);
    Worker = new AnalysisWorker(Db);
    Worker->moveToThread(WorkerThread);

    connect(WorkerThread, &QThread::started, Worker, &AnalysisWorker::Run);
    connect(Worker, &AnalysisWorker::Finished, this, [this](bool Success) {
        Analyzing = false;
        emit AnalysisFinished(Success);
    });
    connect(Worker, &AnalysisWorker::ProgressChanged, this, [this](AnalysisProgress Progress) {
        LastProgress = Progress;
        emit ProgressChanged(Progress);
    });
    connect(Worker, &AnalysisWorker::LogMessage, this, &AnalysisEngine::LogMessage);
    connect(Worker, &AnalysisWorker::Finished, WorkerThread, &QThread::quit);
    connect(WorkerThread, &QThread::finished, Worker, &QObject::deleteLater);

    Analyzing = true;
    emit AnalysisStarted(FilePath);
    WorkerThread->start(QThread::LowPriority);

    return true;
}

void AnalysisEngine::CancelAnalysis() {
    if (Worker) {
        Worker->Cancel();
    }
}

bool AnalysisEngine::IsAnalyzing() const {
    return Analyzing;
}

AnalysisDatabase* AnalysisEngine::Database() const {
    return Db;
}

AnalysisProgress AnalysisEngine::CurrentProgress() const {
    return LastProgress;
}

}
