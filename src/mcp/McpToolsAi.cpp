#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <capstone/capstone.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QDateTime>
#include <QTimeZone>
#include <QRegularExpression>

namespace Fidra {

static double CalcEntropy(const QByteArray& Data) {
    if (Data.isEmpty()) return 0.0;
    int Counts[256] = {};
    for (int I = 0; I < Data.size(); ++I)
        Counts[static_cast<uint8_t>(Data[I])]++;
    double Ent = 0.0;
    double Len = static_cast<double>(Data.size());
    for (int I = 0; I < 256; ++I) {
        if (Counts[I] == 0) continue;
        double P = static_cast<double>(Counts[I]) / Len;
        Ent -= P * std::log2(P);
    }
    return Ent;
}

static Address FindModuleBase(ICore* Core, const QString& ModName) {
    QList<MemoryRegion> Regions = Core->GetMemoryRegions();
    Address Base = 0;
    for (const auto& R : Regions) {
        if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
            if (Base == 0 || R.Base < Base) Base = R.Base;
        }
    }
    return Base;
}

static size_t FindModuleSize(ICore* Core, const QString& ModName) {
    QList<MemoryRegion> Regions = Core->GetMemoryRegions();
    Address MinBase = UINT64_MAX;
    Address MaxEnd = 0;
    for (const auto& R : Regions) {
        if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
            if (R.Base < MinBase) MinBase = R.Base;
            Address End = R.Base + R.Size;
            if (End > MaxEnd) MaxEnd = End;
        }
    }
    if (MinBase == UINT64_MAX) return 0;
    return static_cast<size_t>(MaxEnd - MinBase);
}

struct PeSectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t RawSize;
    uint32_t RawOffset;
    uint32_t Characteristics;
};

struct PeInfo {
    bool Valid;
    bool Is64;
    Address Base;
    uint32_t EntryPointRva;
    uint32_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint16_t Machine;
    uint16_t Subsystem;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t CheckSum;
    QVector<PeSectionHeader> Sections;
    uint32_t ImportDirRva;
    uint32_t ImportDirSize;
    uint32_t ExportDirRva;
    uint32_t ExportDirSize;
    uint32_t ResourceDirRva;
    uint32_t ResourceDirSize;
    uint32_t DebugDirRva;
    uint32_t DebugDirSize;
    uint32_t TlsDirRva;
    uint32_t TlsDirSize;
};

static PeInfo ReadPeInfo(ICore* Core, Address ModBase) {
    PeInfo Info = {};
    Info.Valid = false;
    Info.Base = ModBase;
    if (!ModBase) return Info;

    uint8_t DosHdr[64];
    if (!Core->ReadMemory(ModBase, DosHdr, sizeof(DosHdr))) return Info;
    if (*reinterpret_cast<uint16_t*>(DosHdr) != 0x5A4D) return Info;

    uint32_t PeOff = *reinterpret_cast<uint32_t*>(DosHdr + 0x3C);
    uint8_t PeHdr[4096];
    if (!Core->ReadMemory(ModBase + PeOff, PeHdr, sizeof(PeHdr))) return Info;
    if (*reinterpret_cast<uint32_t*>(PeHdr) != 0x00004550) return Info;

    Info.Machine = *reinterpret_cast<uint16_t*>(PeHdr + 4);
    Info.Is64 = (Info.Machine == 0x8664);
    Info.NumberOfSections = *reinterpret_cast<uint16_t*>(PeHdr + 6);
    Info.TimeDateStamp = *reinterpret_cast<uint32_t*>(PeHdr + 8);
    uint16_t OptHdrSize = *reinterpret_cast<uint16_t*>(PeHdr + 20);

    uint8_t* Opt = PeHdr + 24;
    Info.MajorLinkerVersion = Opt[2];
    Info.MinorLinkerVersion = Opt[3];
    Info.EntryPointRva = *reinterpret_cast<uint32_t*>(Opt + 16);

    if (Info.Is64) {
        Info.Subsystem = *reinterpret_cast<uint16_t*>(Opt + 68);
        Info.CheckSum = *reinterpret_cast<uint32_t*>(Opt + 64);
        Info.ExportDirRva = *reinterpret_cast<uint32_t*>(Opt + 112);
        Info.ExportDirSize = *reinterpret_cast<uint32_t*>(Opt + 116);
        Info.ImportDirRva = *reinterpret_cast<uint32_t*>(Opt + 120);
        Info.ImportDirSize = *reinterpret_cast<uint32_t*>(Opt + 124);
        Info.ResourceDirRva = *reinterpret_cast<uint32_t*>(Opt + 136);
        Info.ResourceDirSize = *reinterpret_cast<uint32_t*>(Opt + 140);
        Info.DebugDirRva = *reinterpret_cast<uint32_t*>(Opt + 160);
        Info.DebugDirSize = *reinterpret_cast<uint32_t*>(Opt + 164);
        Info.TlsDirRva = *reinterpret_cast<uint32_t*>(Opt + 176);
        Info.TlsDirSize = *reinterpret_cast<uint32_t*>(Opt + 180);
    } else {
        Info.Subsystem = *reinterpret_cast<uint16_t*>(Opt + 68);
        Info.CheckSum = *reinterpret_cast<uint32_t*>(Opt + 64);
        Info.ExportDirRva = *reinterpret_cast<uint32_t*>(Opt + 96);
        Info.ExportDirSize = *reinterpret_cast<uint32_t*>(Opt + 100);
        Info.ImportDirRva = *reinterpret_cast<uint32_t*>(Opt + 104);
        Info.ImportDirSize = *reinterpret_cast<uint32_t*>(Opt + 108);
        Info.ResourceDirRva = *reinterpret_cast<uint32_t*>(Opt + 120);
        Info.ResourceDirSize = *reinterpret_cast<uint32_t*>(Opt + 124);
        Info.DebugDirRva = *reinterpret_cast<uint32_t*>(Opt + 144);
        Info.DebugDirSize = *reinterpret_cast<uint32_t*>(Opt + 148);
        Info.TlsDirRva = *reinterpret_cast<uint32_t*>(Opt + 160);
        Info.TlsDirSize = *reinterpret_cast<uint32_t*>(Opt + 164);
    }

    uint8_t* SecStart = PeHdr + 24 + OptHdrSize;
    for (uint32_t I = 0; I < Info.NumberOfSections && I < 96; ++I) {
        uint8_t* S = SecStart + I * 40;
        if (S + 40 > PeHdr + sizeof(PeHdr)) break;
        PeSectionHeader Sec;
        std::memcpy(Sec.Name, S, 8);
        Sec.VirtualSize = *reinterpret_cast<uint32_t*>(S + 8);
        Sec.VirtualAddress = *reinterpret_cast<uint32_t*>(S + 12);
        Sec.RawSize = *reinterpret_cast<uint32_t*>(S + 16);
        Sec.RawOffset = *reinterpret_cast<uint32_t*>(S + 20);
        Sec.Characteristics = *reinterpret_cast<uint32_t*>(S + 36);
        Info.Sections.append(Sec);
    }

    Info.Valid = true;
    return Info;
}

static int CountImports(ICore* Core, Address ModBase, const PeInfo& Pe) {
    if (!Pe.ImportDirRva) return 0;
    int Count = 0;
    for (int I = 0; I < 256; ++I) {
        uint8_t Desc[20];
        if (!Core->ReadMemory(ModBase + Pe.ImportDirRva + static_cast<uint64_t>(I) * 20, Desc, 20))
            break;
        uint32_t NameRva = *reinterpret_cast<uint32_t*>(Desc + 12);
        if (NameRva == 0) break;
        Count++;
    }
    return Count;
}

static int CountExports(ICore* Core, Address ModBase, const PeInfo& Pe) {
    if (!Pe.ExportDirRva) return 0;
    uint8_t ExportDir[40];
    if (!Core->ReadMemory(ModBase + Pe.ExportDirRva, ExportDir, sizeof(ExportDir)))
        return 0;
    return static_cast<int>(*reinterpret_cast<uint32_t*>(ExportDir + 24));
}

static QStringList ReadImportDllNames(ICore* Core, Address ModBase, const PeInfo& Pe) {
    QStringList Dlls;
    if (!Pe.ImportDirRva) return Dlls;
    for (int I = 0; I < 256; ++I) {
        uint8_t Desc[20];
        if (!Core->ReadMemory(ModBase + Pe.ImportDirRva + static_cast<uint64_t>(I) * 20, Desc, 20))
            break;
        uint32_t NameRva = *reinterpret_cast<uint32_t*>(Desc + 12);
        if (NameRva == 0) break;
        char DllName[256] = {};
        Core->ReadMemory(ModBase + NameRva, DllName, 255);
        Dlls.append(QString::fromUtf8(DllName).toLower());
    }
    return Dlls;
}

static QStringList ReadImportFunctionNames(ICore* Core, Address ModBase, const PeInfo& Pe) {
    QStringList Funcs;
    if (!Pe.ImportDirRva) return Funcs;
    int EntrySize = Pe.Is64 ? 8 : 4;
    for (int I = 0; I < 256; ++I) {
        uint8_t Desc[20];
        if (!Core->ReadMemory(ModBase + Pe.ImportDirRva + static_cast<uint64_t>(I) * 20, Desc, 20))
            break;
        uint32_t NameRva = *reinterpret_cast<uint32_t*>(Desc + 12);
        uint32_t ThunkRva = *reinterpret_cast<uint32_t*>(Desc + 0);
        if (NameRva == 0) break;
        char DllName[256] = {};
        Core->ReadMemory(ModBase + NameRva, DllName, 255);
        QString Dll = QString::fromUtf8(DllName).toLower();
        if (ThunkRva) {
            Address ThunkAddr = ModBase + ThunkRva;
            for (int J = 0; J < 512; ++J) {
                uint64_t ThunkData = 0;
                if (!Core->ReadMemory(ThunkAddr + static_cast<uint64_t>(J) * EntrySize, &ThunkData, EntrySize))
                    break;
                if (ThunkData == 0) break;
                bool IsOrdinal = Pe.Is64 ? (ThunkData & 0x8000000000000000ULL) != 0
                                         : (ThunkData & 0x80000000UL) != 0;
                if (!IsOrdinal) {
                    uint32_t HintRva = static_cast<uint32_t>(ThunkData & 0x7FFFFFFF);
                    char FuncName[256] = {};
                    Core->ReadMemory(ModBase + HintRva + 2, FuncName, 255);
                    Funcs.append(Dll + QStringLiteral(".") + QString::fromUtf8(FuncName));
                }
            }
        }
    }
    return Funcs;
}

static QStringList ScanStrings(ICore* Core, Address Base, size_t Size, int MinLen = 4) {
    QStringList Result;
    constexpr size_t ChunkSize = 64 * 1024;
    size_t Remaining = Size;
    Address Cur = Base;
    while (Remaining > 0) {
        size_t ToRead = std::min(Remaining, ChunkSize);
        QByteArray Chunk(static_cast<int>(ToRead), '\0');
        if (!Core->ReadMemory(Cur, Chunk.data(), ToRead)) {
            Cur += ToRead;
            Remaining -= ToRead;
            continue;
        }
        QString Current;
        for (int I = 0; I < Chunk.size(); ++I) {
            char C = Chunk[I];
            if (C >= 0x20 && C <= 0x7E) {
                Current += QChar(C);
            } else {
                if (Current.size() >= MinLen) {
                    Result.append(Current);
                    if (Result.size() > 5000) return Result;
                }
                Current.clear();
            }
        }
        if (Current.size() >= MinLen) Result.append(Current);
        Cur += ToRead;
        Remaining -= ToRead;
    }
    return Result;
}

void McpToolRegistry::RegisterAiTools() {

    RegisterTool(QStringLiteral("summarize_binary"),
        QStringLiteral("Summarize a PE binary: headers, sections, imports, exports, entropy, entry point."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name to summarize"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found: ") + Mod);
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("base")] = Schema::FormatAddress(Base);
            R[QStringLiteral("architecture")] = Pe.Is64 ? QStringLiteral("x64") : QStringLiteral("x86");
            R[QStringLiteral("entry_point")] = Schema::FormatAddress(Base + Pe.EntryPointRva);
            R[QStringLiteral("entry_point_rva")] = Schema::FormatAddress(Pe.EntryPointRva);
            R[QStringLiteral("linker_version")] = QString::number(Pe.MajorLinkerVersion) + QStringLiteral(".") + QString::number(Pe.MinorLinkerVersion);
            R[QStringLiteral("timestamp")] = QDateTime::fromSecsSinceEpoch(Pe.TimeDateStamp, Qt::UTC).toString(Qt::ISODate);
            QString SubSys;
            switch (Pe.Subsystem) {
                case 1: SubSys = QStringLiteral("Native"); break;
                case 2: SubSys = QStringLiteral("WindowsGUI"); break;
                case 3: SubSys = QStringLiteral("WindowsCUI"); break;
                default: SubSys = QString::number(Pe.Subsystem); break;
            }
            R[QStringLiteral("subsystem")] = SubSys;
            R[QStringLiteral("import_dll_count")] = CountImports(CoreRef, Base, Pe);
            R[QStringLiteral("export_count")] = CountExports(CoreRef, Base, Pe);
            QJsonArray SecArr;
            for (const auto& S : Pe.Sections) {
                QJsonObject So;
                So[QStringLiteral("name")] = QString::fromLatin1(S.Name, static_cast<int>(strnlen(S.Name, 8)));
                So[QStringLiteral("virtual_address")] = Schema::FormatAddress(S.VirtualAddress);
                So[QStringLiteral("virtual_size")] = static_cast<int>(S.VirtualSize);
                So[QStringLiteral("raw_size")] = static_cast<int>(S.RawSize);
                So[QStringLiteral("characteristics")] = QStringLiteral("0x") + QString::number(S.Characteristics, 16).toUpper();
                QByteArray SecData(static_cast<int>(std::min(S.VirtualSize, 65536u)), '\0');
                if (CoreRef->ReadMemory(Base + S.VirtualAddress, SecData.data(), static_cast<size_t>(SecData.size()))) {
                    So[QStringLiteral("entropy")] = QString::number(CalcEntropy(SecData), 'f', 4);
                }
                bool Exec = (S.Characteristics & 0x20000000) != 0;
                bool Read = (S.Characteristics & 0x40000000) != 0;
                bool Write = (S.Characteristics & 0x80000000) != 0;
                QString Perms;
                if (Read) Perms += QStringLiteral("R");
                if (Write) Perms += QStringLiteral("W");
                if (Exec) Perms += QStringLiteral("X");
                So[QStringLiteral("permissions")] = Perms;
                SecArr.append(So);
            }
            R[QStringLiteral("sections")] = SecArr;
            return R;
        });

    RegisterTool(QStringLiteral("summarize_function"),
        QStringLiteral("Disassemble function and return metrics: instruction count, calls, branches, stack usage."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
                       {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions to analyze"), 1, 10000)}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsn = A.value(QStringLiteral("max_instructions")).toInt(500);
            size_t ReadSize = static_cast<size_t>(MaxInsn) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     ReadSize, Addr, static_cast<size_t>(MaxInsn), &Insns);
            int CallCount = 0, BranchCount = 0, RetCount = 0, NopCount = 0;
            int StackSize = 0;
            Address LastAddr = Addr;
            QJsonArray Calls;
            for (size_t I = 0; I < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                LastAddr = Insns[I].address + Insns[I].size;
                if (Mn == QStringLiteral("call")) {
                    CallCount++;
                    Calls.append(Schema::FormatAddress(Insns[I].detail->x86.operands[0].imm));
                }
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) {
                    RetCount++;
                    if (RetCount == 1 && I > 0) break;
                }
                if (Mn.startsWith(QStringLiteral("j")) && Mn != QStringLiteral("jmp"))
                    BranchCount++;
                if (Mn == QStringLiteral("nop")) NopCount++;
                if (Mn == QStringLiteral("sub") && QString::fromUtf8(Insns[I].op_str).contains(QStringLiteral("rsp"))) {
                    if (Insns[I].detail->x86.op_count >= 2 && Insns[I].detail->x86.operands[1].type == X86_OP_IMM)
                        StackSize = static_cast<int>(Insns[I].detail->x86.operands[1].imm);
                }
            }
            size_t TotalInsns = std::min(Count, static_cast<size_t>(RetCount > 0 ? Count : Count));
            size_t FuncSize = (Count > 0) ? (Insns[TotalInsns - 1].address + Insns[TotalInsns - 1].size - Addr) : 0;
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("instruction_count")] = static_cast<int>(TotalInsns);
            R[QStringLiteral("size_bytes")] = static_cast<qint64>(FuncSize);
            R[QStringLiteral("call_count")] = CallCount;
            R[QStringLiteral("branch_count")] = BranchCount;
            R[QStringLiteral("nop_count")] = NopCount;
            R[QStringLiteral("stack_frame_size")] = StackSize;
            R[QStringLiteral("cyclomatic_complexity")] = BranchCount + 1;
            R[QStringLiteral("call_targets")] = Calls;
            return R;
        });

    RegisterTool(QStringLiteral("summarize_module"),
        QStringLiteral("Summarize a loaded module: base, size, entry point, import/export count, sections."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found: ") + Mod);
            size_t Size = FindModuleSize(CoreRef, Mod);
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("base")] = Schema::FormatAddress(Base);
            R[QStringLiteral("size")] = static_cast<qint64>(Size);
            R[QStringLiteral("size_hex")] = QStringLiteral("0x") + QString::number(Size, 16).toUpper();
            if (Pe.Valid) {
                R[QStringLiteral("entry_point")] = Schema::FormatAddress(Base + Pe.EntryPointRva);
                R[QStringLiteral("architecture")] = Pe.Is64 ? QStringLiteral("x64") : QStringLiteral("x86");
                R[QStringLiteral("import_dll_count")] = CountImports(CoreRef, Base, Pe);
                R[QStringLiteral("export_count")] = CountExports(CoreRef, Base, Pe);
                R[QStringLiteral("section_count")] = static_cast<int>(Pe.NumberOfSections);
                QJsonArray Secs;
                for (const auto& S : Pe.Sections) {
                    QJsonObject So;
                    So[QStringLiteral("name")] = QString::fromLatin1(S.Name, static_cast<int>(strnlen(S.Name, 8)));
                    So[QStringLiteral("virtual_size")] = static_cast<int>(S.VirtualSize);
                    So[QStringLiteral("virtual_address")] = Schema::FormatAddress(S.VirtualAddress);
                    Secs.append(So);
                }
                R[QStringLiteral("sections")] = Secs;
            }
            return R;
        });

    RegisterTool(QStringLiteral("describe_memory_region"),
        QStringLiteral("Describe the memory region containing a given address."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            for (const auto& Reg : Regions) {
                if (Addr >= Reg.Base && Addr < Reg.Base + Reg.Size) {
                    QJsonObject R;
                    R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                    R[QStringLiteral("region_base")] = Schema::FormatAddress(Reg.Base);
                    R[QStringLiteral("region_size")] = static_cast<qint64>(Reg.Size);
                    R[QStringLiteral("offset_in_region")] = static_cast<qint64>(Addr - Reg.Base);
                    R[QStringLiteral("protection")] = static_cast<int>(Reg.Protection);
                    if (!Reg.ModuleName.isEmpty())
                        R[QStringLiteral("module")] = Reg.ModuleName;
                    QByteArray Preview(64, '\0');
                    if (CoreRef->ReadMemory(Addr, Preview.data(), 64))
                        R[QStringLiteral("first_64_bytes")] = QString::fromLatin1(Preview.toHex(' '));
                    return R;
                }
            }
            return Schema::Err(QStringLiteral("Address not in any mapped region"));
        });

    RegisterTool(QStringLiteral("suggest_breakpoints"),
        QStringLiteral("Analyze function and suggest interesting breakpoint locations (calls, branches, loops)."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
                       {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions"), 1, 5000)}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsn = A.value(QStringLiteral("max_instructions")).toInt(200);
            QByteArray Buf(MaxInsn * 15, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, static_cast<size_t>(MaxInsn), &Insns);
            QJsonArray Suggestions;
            for (size_t I = 0; I < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) break;
                if (Mn == QStringLiteral("call")) {
                    QJsonObject Bp;
                    Bp[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    Bp[QStringLiteral("reason")] = QStringLiteral("Function call");
                    Bp[QStringLiteral("instruction")] = Mn + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                    Suggestions.append(Bp);
                }
                if (Mn.startsWith(QStringLiteral("j")) && Mn != QStringLiteral("jmp")) {
                    uint64_t Target = 0;
                    if (Insns[I].detail->x86.op_count > 0 && Insns[I].detail->x86.operands[0].type == X86_OP_IMM)
                        Target = static_cast<uint64_t>(Insns[I].detail->x86.operands[0].imm);
                    if (Target != 0 && Target < Insns[I].address) {
                        QJsonObject Bp;
                        Bp[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Bp[QStringLiteral("reason")] = QStringLiteral("Loop back-edge");
                        Bp[QStringLiteral("instruction")] = Mn + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        Suggestions.append(Bp);
                    } else {
                        QJsonObject Bp;
                        Bp[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Bp[QStringLiteral("reason")] = QStringLiteral("Conditional branch");
                        Bp[QStringLiteral("instruction")] = Mn + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        Suggestions.append(Bp);
                    }
                }
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("function_address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("suggestion_count")] = Suggestions.size();
            R[QStringLiteral("breakpoints")] = Suggestions;
            return R;
        });

    RegisterTool(QStringLiteral("suggest_next_analysis"),
        QStringLiteral("Suggest what to analyze next based on current state."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonObject R;
            QJsonArray Suggestions;
            if (!CoreRef) {
                R[QStringLiteral("state")] = QStringLiteral("not_initialized");
                Suggestions.append(QStringLiteral("Initialize the core first"));
                R[QStringLiteral("suggestions")] = Suggestions;
                return R;
            }
            if (!CoreRef->IsAttached()) {
                R[QStringLiteral("state")] = QStringLiteral("no_process");
                Suggestions.append(QStringLiteral("Use attach_process or get_process_list to select a target"));
                R[QStringLiteral("suggestions")] = Suggestions;
                return R;
            }
            ProcessInfo Proc = CoreRef->CurrentProcess();
            R[QStringLiteral("state")] = QStringLiteral("attached");
            R[QStringLiteral("process")] = Proc.Name;
            R[QStringLiteral("pid")] = static_cast<int>(Proc.Pid);
            Suggestions.append(QStringLiteral("Run summarize_binary to get PE overview of main module"));
            Suggestions.append(QStringLiteral("Run find_interesting_functions to find security-relevant imports"));
            Suggestions.append(QStringLiteral("Run find_interesting_strings to scan for credentials/URLs"));
            Suggestions.append(QStringLiteral("Run get_import_hash to fingerprint the binary"));
            Suggestions.append(QStringLiteral("Run detect_packing on the main module to check for packers"));
            Suggestions.append(QStringLiteral("Run map_api_usage to categorize imported APIs"));
            R[QStringLiteral("suggestions")] = Suggestions;
            return R;
        });

    RegisterTool(QStringLiteral("find_interesting_functions"),
        QStringLiteral("Find security-relevant imported functions: crypto, network, file I/O, registry, process."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name to scan"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList AllFuncs = ReadImportFunctionNames(CoreRef, Base, Pe);
            QMap<QString, QJsonArray> Categories;
            QStringList CryptoKeys = {QStringLiteral("crypt"), QStringLiteral("aes"), QStringLiteral("rsa"),
                QStringLiteral("sha"), QStringLiteral("md5"), QStringLiteral("hash"), QStringLiteral("encrypt"),
                QStringLiteral("decrypt"), QStringLiteral("bcrypt"), QStringLiteral("ssl"), QStringLiteral("tls")};
            QStringList NetKeys = {QStringLiteral("socket"), QStringLiteral("connect"), QStringLiteral("send"),
                QStringLiteral("recv"), QStringLiteral("bind"), QStringLiteral("listen"), QStringLiteral("accept"),
                QStringLiteral("http"), QStringLiteral("internet"), QStringLiteral("winsock"), QStringLiteral("ws2"),
                QStringLiteral("winhttp"), QStringLiteral("wininet"), QStringLiteral("urldownload")};
            QStringList FileKeys = {QStringLiteral("createfile"), QStringLiteral("readfile"), QStringLiteral("writefile"),
                QStringLiteral("deletefile"), QStringLiteral("movefile"), QStringLiteral("copyfile"),
                QStringLiteral("findfirstfile"), QStringLiteral("findnextfile"), QStringLiteral("getfilesize"),
                QStringLiteral("setfilepointer"), QStringLiteral("fopen"), QStringLiteral("fread"), QStringLiteral("fwrite")};
            QStringList ProcKeys = {QStringLiteral("createprocess"), QStringLiteral("openprocess"),
                QStringLiteral("terminateprocess"), QStringLiteral("readprocessmemory"),
                QStringLiteral("writeprocessmemory"), QStringLiteral("virtualalloc"), QStringLiteral("virtualprotect"),
                QStringLiteral("createremotethread"), QStringLiteral("ntqueryinformation"),
                QStringLiteral("shellexecute"), QStringLiteral("wow64")};
            QStringList RegKeys = {QStringLiteral("regopen"), QStringLiteral("regquery"), QStringLiteral("regset"),
                QStringLiteral("regcreate"), QStringLiteral("regdelete"), QStringLiteral("regenum")};
            QStringList DbgKeys = {QStringLiteral("isdebuggerpresent"), QStringLiteral("checkremotedebugger"),
                QStringLiteral("outputdebugstring"), QStringLiteral("debugbreak")};

            auto Categorize = [&](const QString& Func, const QStringList& Keys, const QString& Cat) {
                QString Lower = Func.toLower();
                for (const auto& K : Keys) {
                    if (Lower.contains(K)) {
                        Categories[Cat].append(Func);
                        return true;
                    }
                }
                return false;
            };

            for (const auto& F : AllFuncs) {
                if (Categorize(F, CryptoKeys, QStringLiteral("crypto"))) continue;
                if (Categorize(F, NetKeys, QStringLiteral("network"))) continue;
                if (Categorize(F, FileKeys, QStringLiteral("file_io"))) continue;
                if (Categorize(F, ProcKeys, QStringLiteral("process"))) continue;
                if (Categorize(F, RegKeys, QStringLiteral("registry"))) continue;
                Categorize(F, DbgKeys, QStringLiteral("debug"));
            }

            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("total_imports")] = AllFuncs.size();
            for (auto It = Categories.constBegin(); It != Categories.constEnd(); ++It) {
                R[It.key()] = It.value();
            }
            return R;
        });

    RegisterTool(QStringLiteral("find_interesting_strings"),
        QStringLiteral("Scan memory for strings containing security-relevant keywords."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name to scan"))},
                       {QStringLiteral("keywords"), Schema::String(QStringLiteral("Comma-separated keywords (default: password,key,secret,token,admin,login,http,error)"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            if (Size == 0) return Schema::Err(QStringLiteral("Module size is 0"));
            if (Size > 50 * 1024 * 1024) Size = 50 * 1024 * 1024;
            QString KeywordStr = A.value(QStringLiteral("keywords")).toString();
            QStringList Keywords;
            if (KeywordStr.isEmpty()) {
                Keywords = {QStringLiteral("password"), QStringLiteral("key"), QStringLiteral("secret"),
                    QStringLiteral("token"), QStringLiteral("admin"), QStringLiteral("login"),
                    QStringLiteral("http"), QStringLiteral("ftp"), QStringLiteral("error"),
                    QStringLiteral("debug"), QStringLiteral("api"), QStringLiteral("auth")};
            } else {
                Keywords = KeywordStr.split(QStringLiteral(","), Qt::SkipEmptyParts);
                for (auto& K : Keywords) K = K.trimmed().toLower();
            }
            QStringList AllStrings = ScanStrings(CoreRef, Base, Size);
            QMap<QString, QJsonArray> Found;
            for (const auto& Str : AllStrings) {
                QString Lower = Str.toLower();
                for (const auto& Kw : Keywords) {
                    if (Lower.contains(Kw)) {
                        Found[Kw].append(Str);
                        break;
                    }
                }
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("total_strings_scanned")] = AllStrings.size();
            int TotalFound = 0;
            for (auto It = Found.constBegin(); It != Found.constEnd(); ++It) {
                R[It.key()] = It.value();
                TotalFound += It.value().size();
            }
            R[QStringLiteral("matches_found")] = TotalFound;
            return R;
        });

    RegisterTool(QStringLiteral("map_api_usage"),
        QStringLiteral("Categorize all imported functions by type: file I/O, network, crypto, memory, process, registry, GUI."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList AllFuncs = ReadImportFunctionNames(CoreRef, Base, Pe);
            QMap<QString, QJsonArray> Map;
            for (const auto& F : AllFuncs) {
                QString Lower = F.toLower();
                if (Lower.contains(QStringLiteral("file")) || Lower.contains(QStringLiteral("fopen")) ||
                    Lower.contains(QStringLiteral("fread")) || Lower.contains(QStringLiteral("fwrite")) ||
                    Lower.contains(QStringLiteral("directory")))
                    Map[QStringLiteral("file_io")].append(F);
                else if (Lower.contains(QStringLiteral("socket")) || Lower.contains(QStringLiteral("connect")) ||
                         Lower.contains(QStringLiteral("send")) || Lower.contains(QStringLiteral("recv")) ||
                         Lower.contains(QStringLiteral("http")) || Lower.contains(QStringLiteral("internet")) ||
                         Lower.contains(QStringLiteral("url")))
                    Map[QStringLiteral("network")].append(F);
                else if (Lower.contains(QStringLiteral("crypt")) || Lower.contains(QStringLiteral("hash")) ||
                         Lower.contains(QStringLiteral("ssl")) || Lower.contains(QStringLiteral("cert")))
                    Map[QStringLiteral("crypto")].append(F);
                else if (Lower.contains(QStringLiteral("virtual")) || Lower.contains(QStringLiteral("heap")) ||
                         Lower.contains(QStringLiteral("alloc")) || Lower.contains(QStringLiteral("free")) ||
                         Lower.contains(QStringLiteral("memcpy")) || Lower.contains(QStringLiteral("memset")))
                    Map[QStringLiteral("memory")].append(F);
                else if (Lower.contains(QStringLiteral("process")) || Lower.contains(QStringLiteral("thread")) ||
                         Lower.contains(QStringLiteral("module")) || Lower.contains(QStringLiteral("snapshot")))
                    Map[QStringLiteral("process")].append(F);
                else if (Lower.contains(QStringLiteral("reg")) && (Lower.contains(QStringLiteral("open")) ||
                         Lower.contains(QStringLiteral("query")) || Lower.contains(QStringLiteral("set")) ||
                         Lower.contains(QStringLiteral("create")) || Lower.contains(QStringLiteral("enum"))))
                    Map[QStringLiteral("registry")].append(F);
                else if (Lower.contains(QStringLiteral("window")) || Lower.contains(QStringLiteral("dialog")) ||
                         Lower.contains(QStringLiteral("message")) || Lower.contains(QStringLiteral("paint")) ||
                         Lower.contains(QStringLiteral("draw")) || Lower.contains(QStringLiteral("gdi")))
                    Map[QStringLiteral("gui")].append(F);
                else
                    Map[QStringLiteral("other")].append(F);
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("total_imports")] = AllFuncs.size();
            for (auto It = Map.constBegin(); It != Map.constEnd(); ++It) {
                QJsonObject Cat;
                Cat[QStringLiteral("count")] = It.value().size();
                Cat[QStringLiteral("functions")] = It.value();
                R[It.key()] = Cat;
            }
            return R;
        });

    RegisterTool(QStringLiteral("identify_library"),
        QStringLiteral("Identify statically or dynamically linked libraries by checking import patterns."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList Dlls = ReadImportDllNames(CoreRef, Base, Pe);
            QJsonArray Identified;
            for (const auto& D : Dlls) {
                if (D.contains(QStringLiteral("openssl")) || D.contains(QStringLiteral("libssl")) || D.contains(QStringLiteral("libcrypto"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("OpenSSL"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("zlib")) || D == QStringLiteral("zlib1.dll")) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("zlib"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.startsWith(QStringLiteral("qt"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("Qt"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("mfc"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("MFC"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("boost"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("Boost"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("lua"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("Lua"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("python"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("Python"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("d3d")) || D.contains(QStringLiteral("dxgi")) || D.contains(QStringLiteral("direct"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("DirectX"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("vulkan"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("Vulkan"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                } else if (D.contains(QStringLiteral("sdl"))) {
                    QJsonObject Lib; Lib[QStringLiteral("library")] = QStringLiteral("SDL"); Lib[QStringLiteral("dll")] = D; Identified.append(Lib);
                }
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("imported_dlls")] = QJsonArray::fromStringList(Dlls);
            R[QStringLiteral("identified_libraries")] = Identified;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_data_layout"),
        QStringLiteral("Read memory and interpret as a potential struct: find pointers, strings, counters, padding."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Base address in hex"))},
                       {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size in bytes to analyze"), 1, 4096)}},
                      {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(256);
            QByteArray Data(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Data.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            ProcessInfo Proc = CoreRef->CurrentProcess();
            bool Is64 = (Proc.Arch == Architecture::X64);
            int PtrSize = Is64 ? 8 : 4;
            QJsonArray Fields;
            for (int Off = 0; Off + PtrSize <= Size; Off += PtrSize) {
                uint64_t Val = 0;
                std::memcpy(&Val, Data.constData() + Off, static_cast<size_t>(PtrSize));
                QJsonObject Field;
                Field[QStringLiteral("offset")] = Off;
                Field[QStringLiteral("hex")] = QStringLiteral("0x") + QString::number(Val, 16).toUpper();
                if (Val == 0) {
                    Field[QStringLiteral("type")] = QStringLiteral("null/zero");
                } else if (Is64 && Val > 0x10000 && Val < 0x00007FFFFFFFFFFF) {
                    Field[QStringLiteral("type")] = QStringLiteral("possible_pointer");
                    char StrBuf[64] = {};
                    if (CoreRef->ReadMemory(Val, StrBuf, 63)) {
                        bool IsStr = true;
                        int StrLen = 0;
                        for (int I = 0; I < 63 && StrBuf[I]; ++I) {
                            if (StrBuf[I] < 0x20 || StrBuf[I] > 0x7E) { IsStr = false; break; }
                            StrLen++;
                        }
                        if (IsStr && StrLen >= 4) {
                            Field[QStringLiteral("type")] = QStringLiteral("string_pointer");
                            Field[QStringLiteral("string_value")] = QString::fromUtf8(StrBuf, StrLen);
                        }
                    }
                } else if (!Is64 && Val > 0x10000 && Val < 0xFFFFFFFF) {
                    Field[QStringLiteral("type")] = QStringLiteral("possible_pointer");
                } else if (Val <= 0xFFFF) {
                    Field[QStringLiteral("type")] = QStringLiteral("small_integer");
                    Field[QStringLiteral("decimal")] = static_cast<qint64>(Val);
                } else {
                    float FVal;
                    std::memcpy(&FVal, Data.constData() + Off, 4);
                    if (std::isfinite(FVal) && std::fabs(FVal) > 0.0001f && std::fabs(FVal) < 1e10f) {
                        Field[QStringLiteral("type")] = QStringLiteral("possible_float");
                        Field[QStringLiteral("float_value")] = static_cast<double>(FVal);
                    } else {
                        Field[QStringLiteral("type")] = QStringLiteral("unknown");
                        Field[QStringLiteral("decimal")] = static_cast<qint64>(Val);
                    }
                }
                Fields.append(Field);
            }
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("size")] = Size;
            R[QStringLiteral("pointer_size")] = PtrSize;
            R[QStringLiteral("fields")] = Fields;
            R[QStringLiteral("hex_dump")] = QString::fromLatin1(Data.toHex(' '));
            return R;
        });

    RegisterTool(QStringLiteral("find_encryption_keys"),
        QStringLiteral("Scan memory for high-entropy blocks that might be encryption keys (16/24/32 byte aligned)."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
                       {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size to scan"), 1, 1048576)}},
                      {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            QByteArray Data(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Data.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            QJsonArray Candidates;
            int KeySizes[] = {16, 24, 32};
            for (int Ks : KeySizes) {
                for (int Off = 0; Off + Ks <= Size; Off += 16) {
                    QByteArray Block = Data.mid(Off, Ks);
                    double Ent = CalcEntropy(Block);
                    if (Ent >= 4.5) {
                        bool AllSame = true;
                        for (int I = 1; I < Block.size(); ++I) {
                            if (Block[I] != Block[0]) { AllSame = false; break; }
                        }
                        if (AllSame) continue;
                        QJsonObject Cand;
                        Cand[QStringLiteral("address")] = Schema::FormatAddress(Addr + Off);
                        Cand[QStringLiteral("size")] = Ks;
                        Cand[QStringLiteral("entropy")] = QString::number(Ent, 'f', 4);
                        Cand[QStringLiteral("hex")] = QString::fromLatin1(Block.toHex(' '));
                        if (Ks == 16) Cand[QStringLiteral("possible_algorithm")] = QStringLiteral("AES-128");
                        else if (Ks == 24) Cand[QStringLiteral("possible_algorithm")] = QStringLiteral("AES-192/3DES");
                        else Cand[QStringLiteral("possible_algorithm")] = QStringLiteral("AES-256");
                        Candidates.append(Cand);
                        if (Candidates.size() >= 100) break;
                    }
                }
                if (Candidates.size() >= 100) break;
            }
            QJsonObject R;
            R[QStringLiteral("scan_address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("scan_size")] = Size;
            R[QStringLiteral("candidates_found")] = Candidates.size();
            R[QStringLiteral("candidates")] = Candidates;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_error_handling"),
        QStringLiteral("Scan function for error-handling patterns: test eax/cmp eax,0 followed by conditional jump and error-path calls."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Buf(4096, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, 300, &Insns);
            QJsonArray Patterns;
            for (size_t I = 0; I + 1 < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                QString Op = QString::fromUtf8(Insns[I].op_str);
                if (Mn == QStringLiteral("ret")) break;
                bool IsErrCheck = false;
                if (Mn == QStringLiteral("test") && Op.contains(QStringLiteral("eax")) && Op.contains(QStringLiteral("eax")))
                    IsErrCheck = true;
                if (Mn == QStringLiteral("cmp") && Op.contains(QStringLiteral("eax")) && Op.contains(QStringLiteral("0")))
                    IsErrCheck = true;
                if (Mn == QStringLiteral("test") && Op.contains(QStringLiteral("rax")) && Op.contains(QStringLiteral("rax")))
                    IsErrCheck = true;
                if (IsErrCheck) {
                    QString NextMn = QString::fromUtf8(Insns[I + 1].mnemonic);
                    if (NextMn.startsWith(QStringLiteral("j"))) {
                        QJsonObject Pat;
                        Pat[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Pat[QStringLiteral("check")] = Mn + QStringLiteral(" ") + Op;
                        Pat[QStringLiteral("branch")] = NextMn + QStringLiteral(" ") + QString::fromUtf8(Insns[I + 1].op_str);
                        Pat[QStringLiteral("type")] = QStringLiteral("return_value_check");
                        Patterns.append(Pat);
                    }
                }
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("function_address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("error_checks_found")] = Patterns.size();
            R[QStringLiteral("patterns")] = Patterns;
            return R;
        });

    RegisterTool(QStringLiteral("detect_design_patterns"),
        QStringLiteral("Check for software design patterns: singleton, factory, observer by analyzing code/data patterns."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Address to analyze"))},
                       {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size to scan"), 1, 65536)}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);
            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Size), Addr, 500, &Insns);
            QJsonArray Patterns;
            bool HasStaticPtr = false;
            bool HasSwitch = false;
            int CmpCount = 0;
            for (size_t I = 0; I < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                QString Op = QString::fromUtf8(Insns[I].op_str);
                if (Mn == QStringLiteral("ret")) break;
                if (Mn == QStringLiteral("cmp")) CmpCount++;
                if ((Mn == QStringLiteral("mov") || Mn == QStringLiteral("lea")) &&
                    Op.contains(QStringLiteral("rip"))) {
                    HasStaticPtr = true;
                }
                if (Mn == QStringLiteral("jmp") && Op.contains(QStringLiteral("["))) {
                    HasSwitch = true;
                }
            }
            if (HasStaticPtr && CmpCount <= 2) {
                QJsonObject P;
                P[QStringLiteral("pattern")] = QStringLiteral("singleton");
                P[QStringLiteral("confidence")] = QStringLiteral("medium");
                P[QStringLiteral("evidence")] = QStringLiteral("Static pointer via RIP-relative addressing with few branches");
                Patterns.append(P);
            }
            if (HasSwitch || CmpCount >= 5) {
                QJsonObject P;
                P[QStringLiteral("pattern")] = QStringLiteral("factory/dispatch");
                P[QStringLiteral("confidence")] = QStringLiteral("medium");
                P[QStringLiteral("evidence")] = QString::number(CmpCount) + QStringLiteral(" comparisons found, possible switch/dispatch table");
                Patterns.append(P);
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("patterns_detected")] = Patterns;
            return R;
        });

    RegisterTool(QStringLiteral("find_game_objects"),
        QStringLiteral("Scan memory for common game patterns: float arrays (positions), health-like values, pointer arrays."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
                       {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size to scan"), 1, 1048576)}},
                      {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            QByteArray Data(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Data.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            QJsonArray Findings;
            for (int Off = 0; Off + 12 <= Size; Off += 4) {
                float X, Y, Z;
                std::memcpy(&X, Data.constData() + Off, 4);
                std::memcpy(&Y, Data.constData() + Off + 4, 4);
                std::memcpy(&Z, Data.constData() + Off + 8, 4);
                if (std::isfinite(X) && std::isfinite(Y) && std::isfinite(Z) &&
                    std::fabs(X) > 0.01f && std::fabs(X) < 100000.0f &&
                    std::fabs(Y) > 0.01f && std::fabs(Y) < 100000.0f &&
                    std::fabs(Z) > 0.01f && std::fabs(Z) < 100000.0f) {
                    QJsonObject F;
                    F[QStringLiteral("address")] = Schema::FormatAddress(Addr + Off);
                    F[QStringLiteral("type")] = QStringLiteral("possible_position_vector");
                    F[QStringLiteral("x")] = static_cast<double>(X);
                    F[QStringLiteral("y")] = static_cast<double>(Y);
                    F[QStringLiteral("z")] = static_cast<double>(Z);
                    Findings.append(F);
                    if (Findings.size() >= 50) break;
                }
            }
            for (int Off = 0; Off + 4 <= Size; Off += 4) {
                if (Findings.size() >= 100) break;
                float Val;
                std::memcpy(&Val, Data.constData() + Off, 4);
                if (std::isfinite(Val) && Val > 0.0f && Val <= 1000.0f) {
                    int IntVal = static_cast<int>(Val);
                    if (IntVal == 100 || IntVal == 200 || IntVal == 500 || IntVal == 1000 ||
                        (Val == std::floor(Val) && IntVal > 0 && IntVal <= 100)) {
                        QJsonObject F;
                        F[QStringLiteral("address")] = Schema::FormatAddress(Addr + Off);
                        F[QStringLiteral("type")] = QStringLiteral("possible_health_or_stat");
                        F[QStringLiteral("value")] = static_cast<double>(Val);
                        Findings.append(F);
                    }
                }
            }
            QJsonObject R;
            R[QStringLiteral("scan_address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("scan_size")] = Size;
            R[QStringLiteral("findings")] = Findings;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_vtable"),
        QStringLiteral("Read vtable at address, resolve entries, disassemble first instructions of each virtual function."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Vtable address in hex"))},
                       {QStringLiteral("max_entries"), Schema::Integer(QStringLiteral("Max vtable entries"), 1, 256)}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address VtAddr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxEntries = A.value(QStringLiteral("max_entries")).toInt(32);
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            QJsonArray Entries;
            for (int I = 0; I < MaxEntries; ++I) {
                uint64_t FuncPtr = 0;
                if (!CoreRef->ReadMemory(VtAddr + static_cast<uint64_t>(I) * 8, &FuncPtr, 8))
                    break;
                if (FuncPtr == 0 || FuncPtr < 0x10000) break;
                QJsonObject Entry;
                Entry[QStringLiteral("index")] = I;
                Entry[QStringLiteral("address")] = Schema::FormatAddress(FuncPtr);
                uint8_t CodeBuf[64];
                if (CoreRef->ReadMemory(FuncPtr, CodeBuf, sizeof(CodeBuf))) {
                    cs_insn* Insns = nullptr;
                    size_t Cnt = cs_disasm(Handle, CodeBuf, sizeof(CodeBuf), FuncPtr, 5, &Insns);
                    QJsonArray DisArr;
                    for (size_t J = 0; J < Cnt; ++J) {
                        DisArr.append(QString::fromUtf8(Insns[J].mnemonic) + QStringLiteral(" ") +
                                      QString::fromUtf8(Insns[J].op_str));
                    }
                    if (Cnt > 0) cs_free(Insns, Cnt);
                    Entry[QStringLiteral("disassembly")] = DisArr;
                }
                Entries.append(Entry);
            }
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("vtable_address")] = Schema::FormatAddress(VtAddr);
            R[QStringLiteral("entry_count")] = Entries.size();
            R[QStringLiteral("entries")] = Entries;
            return R;
        });

    RegisterTool(QStringLiteral("map_class_hierarchy"),
        QStringLiteral("Follow vtable pointers and RTTI type descriptors to build class hierarchy."),
        Schema::Build({{QStringLiteral("vtable_address"), Schema::String(QStringLiteral("Vtable address"))}},
                      {QStringLiteral("vtable_address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address VtAddr = Schema::ParseHexAddress(A.value(QStringLiteral("vtable_address")).toString());
            uint64_t RttiPtr = 0;
            CoreRef->ReadMemory(VtAddr - 8, &RttiPtr, 8);
            QJsonObject R;
            R[QStringLiteral("vtable_address")] = Schema::FormatAddress(VtAddr);
            if (RttiPtr == 0 || RttiPtr < 0x10000) {
                R[QStringLiteral("rtti_found")] = false;
                R[QStringLiteral("note")] = QStringLiteral("No RTTI pointer found at vtable-8. Binary may be compiled with -fno-rtti or RTTI stripped.");
                return R;
            }
            R[QStringLiteral("rtti_complete_object_locator")] = Schema::FormatAddress(RttiPtr);
            uint8_t Col[24];
            if (!CoreRef->ReadMemory(RttiPtr, Col, sizeof(Col))) {
                R[QStringLiteral("rtti_found")] = false;
                return R;
            }
            uint32_t Sig = *reinterpret_cast<uint32_t*>(Col);
            uint32_t TypeDescRva = *reinterpret_cast<uint32_t*>(Col + 12);
            uint32_t HierarchyRva = *reinterpret_cast<uint32_t*>(Col + 16);
            R[QStringLiteral("rtti_found")] = true;
            R[QStringLiteral("signature")] = static_cast<int>(Sig);
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            Address ImageBase = 0;
            for (const auto& Reg : Regions) {
                uint16_t Mz = 0;
                if (CoreRef->ReadMemory(Reg.Base, &Mz, 2) && Mz == 0x5A4D) {
                    if (VtAddr >= Reg.Base && VtAddr < Reg.Base + Reg.Size) {
                        ImageBase = Reg.Base;
                        break;
                    }
                }
            }
            if (ImageBase && Sig == 1) {
                char TypeName[256] = {};
                CoreRef->ReadMemory(ImageBase + TypeDescRva + 16, TypeName, 255);
                R[QStringLiteral("class_name")] = QString::fromUtf8(TypeName);
                uint8_t Hier[16];
                if (CoreRef->ReadMemory(ImageBase + HierarchyRva, Hier, sizeof(Hier))) {
                    uint32_t NumBases = *reinterpret_cast<uint32_t*>(Hier + 8);
                    uint32_t BaseArrayRva = *reinterpret_cast<uint32_t*>(Hier + 12);
                    R[QStringLiteral("num_base_classes")] = static_cast<int>(NumBases);
                    QJsonArray Bases;
                    for (uint32_t I = 0; I < NumBases && I < 20; ++I) {
                        uint32_t BaseDescRva = 0;
                        CoreRef->ReadMemory(ImageBase + BaseArrayRva + I * 4, &BaseDescRva, 4);
                        if (BaseDescRva) {
                            uint32_t BaseTypeDescRva = 0;
                            CoreRef->ReadMemory(ImageBase + BaseDescRva, &BaseTypeDescRva, 4);
                            if (BaseTypeDescRva) {
                                char BaseName[256] = {};
                                CoreRef->ReadMemory(ImageBase + BaseTypeDescRva + 16, BaseName, 255);
                                Bases.append(QString::fromUtf8(BaseName));
                            }
                        }
                    }
                    R[QStringLiteral("base_classes")] = Bases;
                }
            }
            return R;
        });

    RegisterTool(QStringLiteral("estimate_function_complexity"),
        QStringLiteral("Calculate cyclomatic complexity and other metrics for a function."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Buf(8192, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, 500, &Insns);
            int Edges = 0, Nodes = 1, Calls = 0, Loops = 0, InsnCount = 0;
            for (size_t I = 0; I < Count; ++I) {
                InsnCount++;
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) break;
                if (Mn == QStringLiteral("call")) Calls++;
                if (Mn.startsWith(QStringLiteral("j")) && Mn != QStringLiteral("jmp")) {
                    Edges += 2;
                    Nodes++;
                    if (Insns[I].detail->x86.op_count > 0 && Insns[I].detail->x86.operands[0].type == X86_OP_IMM) {
                        uint64_t Target = static_cast<uint64_t>(Insns[I].detail->x86.operands[0].imm);
                        if (Target < Insns[I].address) Loops++;
                    }
                } else if (Mn == QStringLiteral("jmp")) {
                    Edges++;
                } else {
                    Edges++;
                }
            }
            int Complexity = Edges - Nodes + 2;
            if (Complexity < 1) Complexity = 1;
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QString Rating;
            if (Complexity <= 5) Rating = QStringLiteral("simple");
            else if (Complexity <= 10) Rating = QStringLiteral("moderate");
            else if (Complexity <= 20) Rating = QStringLiteral("complex");
            else Rating = QStringLiteral("very_complex");
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("instruction_count")] = InsnCount;
            R[QStringLiteral("cyclomatic_complexity")] = Complexity;
            R[QStringLiteral("rating")] = Rating;
            R[QStringLiteral("call_count")] = Calls;
            R[QStringLiteral("loop_count")] = Loops;
            R[QStringLiteral("edges")] = Edges;
            R[QStringLiteral("nodes")] = Nodes;
            return R;
        });

    RegisterTool(QStringLiteral("find_similar_functions"),
        QStringLiteral("Find functions with similar opcode sequences to the given function."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Reference function address"))},
                       {QStringLiteral("search_address"), Schema::String(QStringLiteral("Start of search region"))},
                       {QStringLiteral("search_size"), Schema::Integer(QStringLiteral("Search region size"), 1, 1048576)}},
                      {QStringLiteral("address"), QStringLiteral("search_address"), QStringLiteral("search_size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address RefAddr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            Address SearchAddr = Schema::ParseHexAddress(A.value(QStringLiteral("search_address")).toString());
            int SearchSize = A.value(QStringLiteral("search_size")).toInt(65536);
            QByteArray RefBuf(2048, '\0');
            if (!CoreRef->ReadMemory(RefAddr, RefBuf.data(), static_cast<size_t>(RefBuf.size())))
                return Schema::Err(QStringLiteral("Failed to read reference function"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_insn* RefInsns = nullptr;
            size_t RefCount = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(RefBuf.constData()),
                                        static_cast<size_t>(RefBuf.size()), RefAddr, 50, &RefInsns);
            QVector<uint16_t> RefOpcodes;
            for (size_t I = 0; I < RefCount; ++I) {
                if (QString::fromUtf8(RefInsns[I].mnemonic) == QStringLiteral("ret")) {
                    RefOpcodes.append(RefInsns[I].id);
                    break;
                }
                RefOpcodes.append(RefInsns[I].id);
            }
            if (RefCount > 0) cs_free(RefInsns, RefCount);
            if (RefOpcodes.isEmpty()) { cs_close(&Handle); return Schema::Err(QStringLiteral("Could not disassemble reference")); }
            QByteArray SearchBuf(SearchSize, '\0');
            if (!CoreRef->ReadMemory(SearchAddr, SearchBuf.data(), static_cast<size_t>(SearchSize))) {
                cs_close(&Handle);
                return Schema::Err(QStringLiteral("Failed to read search region"));
            }
            static const uint8_t Prologues[][3] = {{0x55, 0x48, 0x89}, {0x48, 0x89, 0x5C}, {0x48, 0x83, 0xEC},
                                                    {0x40, 0x55, 0x48}, {0x41, 0x56, 0x41}};
            QJsonArray Matches;
            for (int Off = 0; Off + 3 < SearchSize && Matches.size() < 50; Off++) {
                bool IsPrologue = false;
                for (const auto& P : Prologues) {
                    if (std::memcmp(SearchBuf.constData() + Off, P, 3) == 0) { IsPrologue = true; break; }
                }
                if (!IsPrologue) continue;
                Address CandAddr = SearchAddr + Off;
                if (CandAddr == RefAddr) continue;
                cs_insn* CandInsns = nullptr;
                size_t CandCount = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(SearchBuf.constData() + Off),
                                             static_cast<size_t>(SearchSize - Off), CandAddr, 50, &CandInsns);
                if (CandCount >= static_cast<size_t>(RefOpcodes.size())) {
                    int MatchCount = 0;
                    int CompareLen = std::min(static_cast<int>(RefOpcodes.size()), static_cast<int>(CandCount));
                    for (int J = 0; J < CompareLen; ++J) {
                        if (CandInsns[J].id == RefOpcodes[J]) MatchCount++;
                    }
                    double Similarity = static_cast<double>(MatchCount) / static_cast<double>(CompareLen);
                    if (Similarity >= 0.7) {
                        QJsonObject M;
                        M[QStringLiteral("address")] = Schema::FormatAddress(CandAddr);
                        M[QStringLiteral("similarity")] = QString::number(Similarity * 100.0, 'f', 1) + QStringLiteral("%");
                        M[QStringLiteral("matching_opcodes")] = MatchCount;
                        M[QStringLiteral("total_opcodes")] = CompareLen;
                        Matches.append(M);
                    }
                }
                if (CandCount > 0) cs_free(CandInsns, CandCount);
            }
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("reference")] = Schema::FormatAddress(RefAddr);
            R[QStringLiteral("reference_opcodes")] = RefOpcodes.size();
            R[QStringLiteral("matches_found")] = Matches.size();
            R[QStringLiteral("matches")] = Matches;
            return R;
        });

    RegisterTool(QStringLiteral("trace_data_flow"),
        QStringLiteral("Trace data flow: find where values at an address are read from and written to."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Data address to trace"))},
                       {QStringLiteral("code_address"), Schema::String(QStringLiteral("Code region to search"))},
                       {QStringLiteral("code_size"), Schema::Integer(QStringLiteral("Code region size"), 1, 1048576)}},
                      {QStringLiteral("address"), QStringLiteral("code_address"), QStringLiteral("code_size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address DataAddr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            Address CodeAddr = Schema::ParseHexAddress(A.value(QStringLiteral("code_address")).toString());
            int CodeSize = A.value(QStringLiteral("code_size")).toInt(65536);
            QByteArray CodeBuf(CodeSize, '\0');
            if (!CoreRef->ReadMemory(CodeAddr, CodeBuf.data(), static_cast<size_t>(CodeSize)))
                return Schema::Err(QStringLiteral("Failed to read code"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(CodeBuf.constData()),
                                     static_cast<size_t>(CodeSize), CodeAddr, 0, &Insns);
            QJsonArray Reads;
            QJsonArray Writes;
            for (size_t I = 0; I < Count; ++I) {
                if (Insns[I].detail->x86.op_count < 1) continue;
                for (uint8_t J = 0; J < Insns[I].detail->x86.op_count; ++J) {
                    cs_x86_op* Op = &Insns[I].detail->x86.operands[J];
                    if (Op->type == X86_OP_MEM) {
                        int64_t EffAddr = 0;
                        if (Op->mem.base == X86_REG_RIP) {
                            EffAddr = static_cast<int64_t>(Insns[I].address + Insns[I].size) + Op->mem.disp;
                        } else if (Op->mem.base == X86_REG_INVALID && Op->mem.index == X86_REG_INVALID) {
                            EffAddr = Op->mem.disp;
                        }
                        if (static_cast<uint64_t>(EffAddr) == DataAddr) {
                            QJsonObject Ref;
                            Ref[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                            Ref[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") +
                                                                 QString::fromUtf8(Insns[I].op_str);
                            if (J == 0) {
                                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                                if (Mn == QStringLiteral("mov") || Mn == QStringLiteral("add") || Mn == QStringLiteral("sub") ||
                                    Mn == QStringLiteral("and") || Mn == QStringLiteral("or") || Mn == QStringLiteral("xor"))
                                    Writes.append(Ref);
                                else
                                    Reads.append(Ref);
                            } else {
                                Reads.append(Ref);
                            }
                        }
                    }
                }
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("data_address")] = Schema::FormatAddress(DataAddr);
            R[QStringLiteral("reads")] = Reads;
            R[QStringLiteral("writes")] = Writes;
            R[QStringLiteral("total_references")] = Reads.size() + Writes.size();
            return R;
        });

    RegisterTool(QStringLiteral("find_magic_numbers"),
        QStringLiteral("Scan memory for well-known constants: PI, file signatures, hash init values, etc."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
                       {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size to scan"), 1, 1048576)}},
                      {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            QByteArray Data(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Data.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            struct MagicConst { uint32_t Value; QString Name; };
            QVector<MagicConst> Consts = {
                {0x5A4D, QStringLiteral("MZ_HEADER")},
                {0x00004550, QStringLiteral("PE_SIGNATURE")},
                {0x464C457F, QStringLiteral("ELF_MAGIC")},
                {0x04034B50, QStringLiteral("ZIP_LOCAL_HEADER")},
                {0x40490FDB, QStringLiteral("FLOAT_PI")},
                {0x67452301, QStringLiteral("MD5_INIT_A")},
                {0xEFCDAB89, QStringLiteral("MD5_INIT_B")},
                {0x98BADCFE, QStringLiteral("MD5_INIT_C")},
                {0x10325476, QStringLiteral("MD5_INIT_D")},
                {0x6A09E667, QStringLiteral("SHA256_INIT_H0")},
                {0xBB67AE85, QStringLiteral("SHA256_INIT_H1")},
                {0x3C6EF372, QStringLiteral("SHA256_INIT_H2")},
                {0xA54FF53A, QStringLiteral("SHA256_INIT_H3")},
                {0xEDB88320, QStringLiteral("CRC32_POLY")},
                {0x9E3779B9, QStringLiteral("TEA_GOLDEN_RATIO")},
                {0xDEADBEEF, QStringLiteral("DEADBEEF_MARKER")},
                {0xCAFEBABE, QStringLiteral("JAVA_CLASS_MAGIC")},
                {0xFEEDFACE, QStringLiteral("MACH_O_32")},
                {0xFEEDFACF, QStringLiteral("MACH_O_64")},
                {0x00000100, QStringLiteral("ICO_HEADER")},
                {0x46464952, QStringLiteral("RIFF_HEADER")},
                {0x89504E47, QStringLiteral("PNG_HEADER")},
            };
            QJsonArray Found;
            for (int Off = 0; Off + 4 <= Size; Off += 4) {
                uint32_t Val = *reinterpret_cast<const uint32_t*>(Data.constData() + Off);
                for (const auto& C : Consts) {
                    if (Val == C.Value) {
                        QJsonObject F;
                        F[QStringLiteral("address")] = Schema::FormatAddress(Addr + Off);
                        F[QStringLiteral("value")] = QStringLiteral("0x") + QString::number(Val, 16).toUpper();
                        F[QStringLiteral("name")] = C.Name;
                        Found.append(F);
                        if (Found.size() >= 200) break;
                    }
                }
                if (Found.size() >= 200) break;
            }
            QJsonObject R;
            R[QStringLiteral("scan_address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("scan_size")] = Size;
            R[QStringLiteral("found")] = Found;
            return R;
        });

    RegisterTool(QStringLiteral("detect_backdoors"),
        QStringLiteral("Check for suspicious patterns: hardcoded IPs, base64 commands, hidden socket creation."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name to scan"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            if (Size > 20 * 1024 * 1024) Size = 20 * 1024 * 1024;
            QStringList AllStrings = ScanStrings(CoreRef, Base, Size);
            QJsonArray Suspicious;
            QRegularExpression IpRegex(QStringLiteral("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"));
            QRegularExpression B64Regex(QStringLiteral("^[A-Za-z0-9+/]{20,}={0,2}$"));
            for (const auto& S : AllStrings) {
                auto IpMatch = IpRegex.match(S);
                if (IpMatch.hasMatch()) {
                    QString Ip = IpMatch.captured();
                    if (!Ip.startsWith(QStringLiteral("0.")) && !Ip.startsWith(QStringLiteral("255.")) && Ip != QStringLiteral("127.0.0.1")) {
                        QJsonObject F;
                        F[QStringLiteral("type")] = QStringLiteral("hardcoded_ip");
                        F[QStringLiteral("value")] = Ip;
                        F[QStringLiteral("context")] = S.left(100);
                        Suspicious.append(F);
                    }
                }
                if (B64Regex.match(S).hasMatch() && S.size() >= 24) {
                    QByteArray Decoded = QByteArray::fromBase64(S.toLatin1());
                    bool HasPrintable = true;
                    for (qsizetype I = 0; I < std::min(Decoded.size(), qsizetype(20)); ++I) {
                        if (Decoded[I] < 0x20 || Decoded[I] > 0x7E) { HasPrintable = false; break; }
                    }
                    if (HasPrintable && Decoded.size() >= 8) {
                        QJsonObject F;
                        F[QStringLiteral("type")] = QStringLiteral("encoded_string");
                        F[QStringLiteral("encoded")] = S.left(60);
                        F[QStringLiteral("decoded")] = QString::fromUtf8(Decoded.left(100));
                        Suspicious.append(F);
                    }
                }
                QString Lower = S.toLower();
                if (Lower.contains(QStringLiteral("cmd.exe")) || Lower.contains(QStringLiteral("/bin/sh")) ||
                    Lower.contains(QStringLiteral("powershell")) || Lower.contains(QStringLiteral("exec(")) ||
                    Lower.contains(QStringLiteral("system("))) {
                    QJsonObject F;
                    F[QStringLiteral("type")] = QStringLiteral("command_execution");
                    F[QStringLiteral("value")] = S.left(200);
                    Suspicious.append(F);
                }
                if (Suspicious.size() >= 100) break;
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("suspicious_count")] = Suspicious.size();
            R[QStringLiteral("findings")] = Suspicious;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_authentication"),
        QStringLiteral("Find functions that reference password/login/auth strings and analyze their structure."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            if (Size > 20 * 1024 * 1024) Size = 20 * 1024 * 1024;
            QStringList AllStrings = ScanStrings(CoreRef, Base, Size);
            QStringList AuthKeywords = {QStringLiteral("password"), QStringLiteral("passwd"), QStringLiteral("login"),
                QStringLiteral("auth"), QStringLiteral("credential"), QStringLiteral("username"),
                QStringLiteral("user_name"), QStringLiteral("logon"), QStringLiteral("sign_in"),
                QStringLiteral("access_token"), QStringLiteral("api_key"), QStringLiteral("secret_key")};
            QJsonArray AuthStrings;
            for (const auto& S : AllStrings) {
                QString Lower = S.toLower();
                for (const auto& Kw : AuthKeywords) {
                    if (Lower.contains(Kw)) {
                        QJsonObject Entry;
                        Entry[QStringLiteral("string")] = S.left(200);
                        Entry[QStringLiteral("keyword")] = Kw;
                        AuthStrings.append(Entry);
                        break;
                    }
                }
                if (AuthStrings.size() >= 100) break;
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("auth_related_strings")] = AuthStrings;
            R[QStringLiteral("count")] = AuthStrings.size();
            return R;
        });

    RegisterTool(QStringLiteral("analyze_network_usage"),
        QStringLiteral("Find imported network/socket functions and identify protocols used."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList AllFuncs = ReadImportFunctionNames(CoreRef, Base, Pe);
            QStringList Dlls = ReadImportDllNames(CoreRef, Base, Pe);
            QJsonArray NetFuncs;
            QStringList Protocols;
            for (const auto& F : AllFuncs) {
                QString Lower = F.toLower();
                if (Lower.contains(QStringLiteral("socket")) || Lower.contains(QStringLiteral("connect")) ||
                    Lower.contains(QStringLiteral("send")) || Lower.contains(QStringLiteral("recv")) ||
                    Lower.contains(QStringLiteral("bind")) || Lower.contains(QStringLiteral("listen")) ||
                    Lower.contains(QStringLiteral("accept")) || Lower.contains(QStringLiteral("select")) ||
                    Lower.contains(QStringLiteral("getaddrinfo")) || Lower.contains(QStringLiteral("gethostby")))
                    NetFuncs.append(F);
                if (Lower.contains(QStringLiteral("http"))) Protocols.append(QStringLiteral("HTTP"));
                if (Lower.contains(QStringLiteral("ssl")) || Lower.contains(QStringLiteral("tls"))) Protocols.append(QStringLiteral("TLS/SSL"));
                if (Lower.contains(QStringLiteral("ftp"))) Protocols.append(QStringLiteral("FTP"));
                if (Lower.contains(QStringLiteral("dns"))) Protocols.append(QStringLiteral("DNS"));
            }
            for (const auto& D : Dlls) {
                if (D.contains(QStringLiteral("ws2_32")) || D.contains(QStringLiteral("wsock32")))
                    Protocols.append(QStringLiteral("Winsock"));
                if (D.contains(QStringLiteral("winhttp"))) Protocols.append(QStringLiteral("WinHTTP"));
                if (D.contains(QStringLiteral("wininet"))) Protocols.append(QStringLiteral("WinINet"));
            }
            Protocols.removeDuplicates();
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("network_functions")] = NetFuncs;
            R[QStringLiteral("protocols_detected")] = QJsonArray::fromStringList(Protocols);
            R[QStringLiteral("has_networking")] = !NetFuncs.isEmpty();
            return R;
        });

    RegisterTool(QStringLiteral("get_binary_metadata"),
        QStringLiteral("Comprehensive binary metadata: architecture, compiler, linker, timestamps, subsystem, checksums."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("base_address")] = Schema::FormatAddress(Base);
            R[QStringLiteral("mapped_size")] = static_cast<qint64>(Size);
            if (!Pe.Valid) {
                R[QStringLiteral("pe_valid")] = false;
                return R;
            }
            R[QStringLiteral("pe_valid")] = true;
            R[QStringLiteral("architecture")] = Pe.Is64 ? QStringLiteral("x64") : QStringLiteral("x86");
            QString Machine;
            switch (Pe.Machine) {
                case 0x14C: Machine = QStringLiteral("i386"); break;
                case 0x8664: Machine = QStringLiteral("AMD64"); break;
                case 0xAA64: Machine = QStringLiteral("ARM64"); break;
                default: Machine = QStringLiteral("0x") + QString::number(Pe.Machine, 16); break;
            }
            R[QStringLiteral("machine")] = Machine;
            R[QStringLiteral("linker_version")] = QString::number(Pe.MajorLinkerVersion) + QStringLiteral(".") + QString::number(Pe.MinorLinkerVersion);
            QString Compiler;
            if (Pe.MajorLinkerVersion == 14) Compiler = QStringLiteral("MSVC 2015-2022");
            else if (Pe.MajorLinkerVersion == 12) Compiler = QStringLiteral("MSVC 2013");
            else if (Pe.MajorLinkerVersion == 11) Compiler = QStringLiteral("MSVC 2012");
            else if (Pe.MajorLinkerVersion == 10) Compiler = QStringLiteral("MSVC 2010");
            else if (Pe.MajorLinkerVersion == 2) Compiler = QStringLiteral("GCC/MinGW");
            R[QStringLiteral("probable_compiler")] = Compiler;
            R[QStringLiteral("timestamp")] = QDateTime::fromSecsSinceEpoch(Pe.TimeDateStamp, Qt::UTC).toString(Qt::ISODate);
            R[QStringLiteral("timestamp_raw")] = static_cast<qint64>(Pe.TimeDateStamp);
            QString SubSys;
            switch (Pe.Subsystem) {
                case 1: SubSys = QStringLiteral("Native"); break;
                case 2: SubSys = QStringLiteral("WindowsGUI"); break;
                case 3: SubSys = QStringLiteral("WindowsCUI"); break;
                case 5: SubSys = QStringLiteral("OS2_CUI"); break;
                case 7: SubSys = QStringLiteral("POSIX_CUI"); break;
                case 10: SubSys = QStringLiteral("EFI_Application"); break;
                default: SubSys = QString::number(Pe.Subsystem); break;
            }
            R[QStringLiteral("subsystem")] = SubSys;
            R[QStringLiteral("checksum")] = QStringLiteral("0x") + QString::number(Pe.CheckSum, 16).toUpper();
            R[QStringLiteral("entry_point")] = Schema::FormatAddress(Base + Pe.EntryPointRva);
            R[QStringLiteral("section_count")] = static_cast<int>(Pe.NumberOfSections);
            R[QStringLiteral("has_imports")] = Pe.ImportDirRva != 0;
            R[QStringLiteral("has_exports")] = Pe.ExportDirRva != 0;
            R[QStringLiteral("has_resources")] = Pe.ResourceDirRva != 0;
            R[QStringLiteral("has_debug_info")] = Pe.DebugDirRva != 0;
            R[QStringLiteral("has_tls")] = Pe.TlsDirRva != 0;
            return R;
        });

    RegisterTool(QStringLiteral("get_import_hash"),
        QStringLiteral("Calculate imphash (MD5 of sorted DLL.function import names). Standard malware fingerprint."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList AllFuncs = ReadImportFunctionNames(CoreRef, Base, Pe);
            std::sort(AllFuncs.begin(), AllFuncs.end());
            QString Combined = AllFuncs.join(QStringLiteral(",")).toLower();
            QByteArray Hash = QCryptographicHash::hash(Combined.toUtf8(), QCryptographicHash::Md5);
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("imphash")] = QString::fromLatin1(Hash.toHex());
            R[QStringLiteral("import_count")] = AllFuncs.size();
            return R;
        });

    RegisterTool(QStringLiteral("get_section_hashes"),
        QStringLiteral("Calculate MD5 and SHA256 hashes for each PE section."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QJsonArray Sections;
            for (const auto& S : Pe.Sections) {
                uint32_t ReadSize = std::min(S.VirtualSize, 16u * 1024 * 1024);
                if (ReadSize == 0) continue;
                QByteArray Data(static_cast<int>(ReadSize), '\0');
                if (!CoreRef->ReadMemory(Base + S.VirtualAddress, Data.data(), ReadSize)) continue;
                QJsonObject SecObj;
                SecObj[QStringLiteral("name")] = QString::fromLatin1(S.Name, static_cast<int>(strnlen(S.Name, 8)));
                SecObj[QStringLiteral("md5")] = QString::fromLatin1(QCryptographicHash::hash(Data, QCryptographicHash::Md5).toHex());
                SecObj[QStringLiteral("sha256")] = QString::fromLatin1(QCryptographicHash::hash(Data, QCryptographicHash::Sha256).toHex());
                SecObj[QStringLiteral("size")] = static_cast<int>(ReadSize);
                SecObj[QStringLiteral("entropy")] = QString::number(CalcEntropy(Data), 'f', 4);
                Sections.append(SecObj);
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("sections")] = Sections;
            return R;
        });

    RegisterTool(QStringLiteral("find_packed_sections"),
        QStringLiteral("Identify sections with high entropy (>7.0), unusual names, or zero raw size indicating packing."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QStringList NormalNames = {QStringLiteral(".text"), QStringLiteral(".rdata"), QStringLiteral(".data"),
                QStringLiteral(".rsrc"), QStringLiteral(".reloc"), QStringLiteral(".pdata"), QStringLiteral(".idata"),
                QStringLiteral(".edata"), QStringLiteral(".bss"), QStringLiteral(".tls"), QStringLiteral(".CRT")};
            QJsonArray Suspicious;
            bool IsPacked = false;
            for (const auto& S : Pe.Sections) {
                QString Name = QString::fromLatin1(S.Name, static_cast<int>(strnlen(S.Name, 8)));
                QJsonObject SecObj;
                SecObj[QStringLiteral("name")] = Name;
                SecObj[QStringLiteral("virtual_size")] = static_cast<int>(S.VirtualSize);
                SecObj[QStringLiteral("raw_size")] = static_cast<int>(S.RawSize);
                QJsonArray Reasons;
                uint32_t ReadSize = std::min(S.VirtualSize, 65536u);
                double Entropy = 0.0;
                if (ReadSize > 0) {
                    QByteArray Data(static_cast<int>(ReadSize), '\0');
                    if (CoreRef->ReadMemory(Base + S.VirtualAddress, Data.data(), ReadSize))
                        Entropy = CalcEntropy(Data);
                }
                SecObj[QStringLiteral("entropy")] = QString::number(Entropy, 'f', 4);
                if (Entropy > 7.0) { Reasons.append(QStringLiteral("High entropy (>7.0) indicates compression/encryption")); IsPacked = true; }
                if (S.RawSize == 0 && S.VirtualSize > 0) { Reasons.append(QStringLiteral("Zero raw size with non-zero virtual size")); IsPacked = true; }
                if (!NormalNames.contains(Name) && !Name.startsWith(QStringLiteral("."))) {
                    Reasons.append(QStringLiteral("Unusual section name"));
                    if (Name.contains(QStringLiteral("UPX")) || Name.contains(QStringLiteral("vmp")) ||
                        Name.contains(QStringLiteral("themida")) || Name.contains(QStringLiteral(".nsp"))) {
                        Reasons.append(QStringLiteral("Known packer section name"));
                        IsPacked = true;
                    }
                }
                bool AllPerms = (S.Characteristics & 0xE0000000) == 0xE0000000;
                if (AllPerms) { Reasons.append(QStringLiteral("RWX permissions")); IsPacked = true; }
                if (!Reasons.isEmpty()) {
                    SecObj[QStringLiteral("reasons")] = Reasons;
                    Suspicious.append(SecObj);
                }
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("is_likely_packed")] = IsPacked;
            R[QStringLiteral("suspicious_sections")] = Suspicious;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_resources"),
        QStringLiteral("Parse PE resources and categorize by type."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            if (!Pe.ResourceDirRva) {
                QJsonObject R;
                R[QStringLiteral("module")] = Mod;
                R[QStringLiteral("has_resources")] = false;
                return R;
            }
            uint8_t ResDir[16];
            if (!CoreRef->ReadMemory(Base + Pe.ResourceDirRva, ResDir, sizeof(ResDir)))
                return Schema::Err(QStringLiteral("Failed to read resource directory"));
            uint16_t NamedEntries = *reinterpret_cast<uint16_t*>(ResDir + 12);
            uint16_t IdEntries = *reinterpret_cast<uint16_t*>(ResDir + 14);
            int TotalEntries = NamedEntries + IdEntries;
            QMap<int, QString> TypeNames = {
                {1, QStringLiteral("RT_CURSOR")}, {2, QStringLiteral("RT_BITMAP")},
                {3, QStringLiteral("RT_ICON")}, {4, QStringLiteral("RT_MENU")},
                {5, QStringLiteral("RT_DIALOG")}, {6, QStringLiteral("RT_STRING")},
                {9, QStringLiteral("RT_ACCELERATOR")}, {10, QStringLiteral("RT_RCDATA")},
                {11, QStringLiteral("RT_MESSAGETABLE")}, {12, QStringLiteral("RT_GROUP_CURSOR")},
                {14, QStringLiteral("RT_GROUP_ICON")}, {16, QStringLiteral("RT_VERSION")},
                {24, QStringLiteral("RT_MANIFEST")}
            };
            QJsonArray Resources;
            for (int I = 0; I < TotalEntries && I < 50; ++I) {
                uint8_t Entry[8];
                if (!CoreRef->ReadMemory(Base + Pe.ResourceDirRva + 16 + static_cast<uint64_t>(I) * 8, Entry, sizeof(Entry)))
                    break;
                uint32_t NameOrId = *reinterpret_cast<uint32_t*>(Entry);
                QJsonObject ResObj;
                if (NameOrId & 0x80000000) {
                    ResObj[QStringLiteral("type")] = QStringLiteral("named");
                } else {
                    int TypeId = static_cast<int>(NameOrId);
                    ResObj[QStringLiteral("type_id")] = TypeId;
                    ResObj[QStringLiteral("type_name")] = TypeNames.value(TypeId, QStringLiteral("UNKNOWN_") + QString::number(TypeId));
                }
                Resources.append(ResObj);
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("has_resources")] = true;
            R[QStringLiteral("named_entries")] = NamedEntries;
            R[QStringLiteral("id_entries")] = IdEntries;
            R[QStringLiteral("resource_types")] = Resources;
            return R;
        });

    RegisterTool(QStringLiteral("get_compilation_timestamp"),
        QStringLiteral("Read PE TimeDateStamp and convert to human-readable datetime."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Not a valid PE"));
            QDateTime Dt = QDateTime::fromSecsSinceEpoch(Pe.TimeDateStamp, Qt::UTC);
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("timestamp_raw")] = static_cast<qint64>(Pe.TimeDateStamp);
            R[QStringLiteral("timestamp_hex")] = QStringLiteral("0x") + QString::number(Pe.TimeDateStamp, 16).toUpper();
            R[QStringLiteral("datetime_utc")] = Dt.toString(Qt::ISODate);
            R[QStringLiteral("date")] = Dt.toString(QStringLiteral("yyyy-MM-dd"));
            R[QStringLiteral("time")] = Dt.toString(QStringLiteral("HH:mm:ss"));
            bool IsFuture = Dt > QDateTime::currentDateTimeUtc();
            bool IsTooOld = Dt.date().year() < 1995;
            if (IsFuture || IsTooOld) R[QStringLiteral("warning")] = QStringLiteral("Timestamp appears tampered or invalid");
            return R;
        });

    RegisterTool(QStringLiteral("detect_debug_artifacts"),
        QStringLiteral("Look for debug strings, PDB paths, assert macros, and debug-build indicators."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            if (Size > 20 * 1024 * 1024) Size = 20 * 1024 * 1024;
            QStringList AllStrings = ScanStrings(CoreRef, Base, Size);
            QJsonArray PdbPaths;
            QJsonArray AssertMsgs;
            QJsonArray DebugMsgs;
            for (const auto& S : AllStrings) {
                if (S.endsWith(QStringLiteral(".pdb"), Qt::CaseInsensitive))
                    PdbPaths.append(S);
                if (S.contains(QStringLiteral("assert"), Qt::CaseInsensitive) || S.contains(QStringLiteral("ASSERT")))
                    AssertMsgs.append(S.left(200));
                QString Lower = S.toLower();
                if (Lower.contains(QStringLiteral("debug")) || Lower.contains(QStringLiteral("[dbg]")) ||
                    Lower.contains(QStringLiteral("trace:")) || Lower.contains(QStringLiteral("debug_")))
                    DebugMsgs.append(S.left(200));
                if (PdbPaths.size() + AssertMsgs.size() + DebugMsgs.size() > 200) break;
            }
            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            bool HasDebugDir = Pe.Valid && Pe.DebugDirRva != 0;
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("has_debug_directory")] = HasDebugDir;
            R[QStringLiteral("pdb_paths")] = PdbPaths;
            R[QStringLiteral("assert_strings")] = AssertMsgs;
            R[QStringLiteral("debug_strings")] = DebugMsgs;
            R[QStringLiteral("is_debug_build")] = !PdbPaths.isEmpty() || !AssertMsgs.isEmpty();
            return R;
        });

    RegisterTool(QStringLiteral("find_config_data"),
        QStringLiteral("Scan for configuration-like data: IP addresses, URLs, file paths, registry keys."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Mod = A.value(QStringLiteral("module")).toString();
            Address Base = FindModuleBase(CoreRef, Mod);
            if (!Base) return Schema::Err(QStringLiteral("Module not found"));
            size_t Size = FindModuleSize(CoreRef, Mod);
            if (Size > 20 * 1024 * 1024) Size = 20 * 1024 * 1024;
            QStringList AllStrings = ScanStrings(CoreRef, Base, Size);
            QJsonArray Urls;
            QJsonArray IpAddresses;
            QJsonArray FilePaths;
            QJsonArray RegistryKeys;
            QRegularExpression IpRx(QStringLiteral("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"));
            for (const auto& S : AllStrings) {
                if (S.startsWith(QStringLiteral("http://")) || S.startsWith(QStringLiteral("https://")) ||
                    S.startsWith(QStringLiteral("ftp://")) || S.startsWith(QStringLiteral("ws://")))
                    Urls.append(S.left(500));
                auto IpM = IpRx.match(S);
                if (IpM.hasMatch()) IpAddresses.append(IpM.captured());
                if (S.contains(QStringLiteral(":\\")) || S.startsWith(QStringLiteral("/usr/")) ||
                    S.startsWith(QStringLiteral("/etc/")) || S.startsWith(QStringLiteral("/tmp/")))
                    FilePaths.append(S.left(300));
                if (S.startsWith(QStringLiteral("HKEY_")) || S.startsWith(QStringLiteral("HKLM\\")) ||
                    S.startsWith(QStringLiteral("HKCU\\")) || S.contains(QStringLiteral("SOFTWARE\\")))
                    RegistryKeys.append(S.left(300));
                if (Urls.size() + IpAddresses.size() + FilePaths.size() + RegistryKeys.size() > 300) break;
            }
            QJsonObject R;
            R[QStringLiteral("module")] = Mod;
            R[QStringLiteral("urls")] = Urls;
            R[QStringLiteral("ip_addresses")] = IpAddresses;
            R[QStringLiteral("file_paths")] = FilePaths;
            R[QStringLiteral("registry_keys")] = RegistryKeys;
            return R;
        });

    RegisterTool(QStringLiteral("analyze_stack_usage"),
        QStringLiteral("Analyze function stack frame: size from sub rsp,N, local variable count estimate."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Buf(2048, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, 200, &Insns);
            int StackSize = 0;
            int PushCount = 0;
            bool HasFramePointer = false;
            QJsonArray StackAccesses;
            for (size_t I = 0; I < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                QString Op = QString::fromUtf8(Insns[I].op_str);
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) break;
                if (Mn == QStringLiteral("push")) PushCount++;
                if (Mn == QStringLiteral("sub") && Op.contains(QStringLiteral("rsp"))) {
                    if (Insns[I].detail->x86.op_count >= 2 && Insns[I].detail->x86.operands[1].type == X86_OP_IMM)
                        StackSize = static_cast<int>(Insns[I].detail->x86.operands[1].imm);
                }
                if (Mn == QStringLiteral("mov") && Op.startsWith(QStringLiteral("rbp, rsp")))
                    HasFramePointer = true;
                if (Op.contains(QStringLiteral("[rsp")) || Op.contains(QStringLiteral("[rbp"))) {
                    if (StackAccesses.size() < 50) {
                        QJsonObject Access;
                        Access[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Access[QStringLiteral("instruction")] = Mn + QStringLiteral(" ") + Op;
                        StackAccesses.append(Access);
                    }
                }
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            int EstimatedLocals = StackSize > 0 ? (StackSize - 32) / 8 : 0;
            if (EstimatedLocals < 0) EstimatedLocals = 0;
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("stack_frame_size")] = StackSize;
            R[QStringLiteral("saved_registers")] = PushCount;
            R[QStringLiteral("has_frame_pointer")] = HasFramePointer;
            R[QStringLiteral("estimated_local_variables")] = EstimatedLocals;
            R[QStringLiteral("total_stack_usage")] = StackSize + PushCount * 8;
            R[QStringLiteral("stack_accesses")] = StackAccesses;
            return R;
        });

    RegisterTool(QStringLiteral("get_function_args"),
        QStringLiteral("Analyze function to determine number of arguments by checking register usage (rcx/rdx/r8/r9 for x64)."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Buf(1024, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, 50, &Insns);
            bool UsesRcx = false, UsesRdx = false, UsesR8 = false, UsesR9 = false;
            bool UsesXmm0 = false, UsesXmm1 = false, UsesXmm2 = false, UsesXmm3 = false;
            for (size_t I = 0; I < Count && I < 30; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("call")) break;
                for (uint8_t J = 0; J < Insns[I].detail->x86.op_count; ++J) {
                    cs_x86_op* Op = &Insns[I].detail->x86.operands[J];
                    if (Op->type == X86_OP_REG) {
                        if (Op->reg == X86_REG_RCX || Op->reg == X86_REG_ECX) UsesRcx = true;
                        if (Op->reg == X86_REG_RDX || Op->reg == X86_REG_EDX) UsesRdx = true;
                        if (Op->reg == X86_REG_R8 || Op->reg == X86_REG_R8D) UsesR8 = true;
                        if (Op->reg == X86_REG_R9 || Op->reg == X86_REG_R9D) UsesR9 = true;
                        if (Op->reg == X86_REG_XMM0) UsesXmm0 = true;
                        if (Op->reg == X86_REG_XMM1) UsesXmm1 = true;
                        if (Op->reg == X86_REG_XMM2) UsesXmm2 = true;
                        if (Op->reg == X86_REG_XMM3) UsesXmm3 = true;
                    }
                    if (Op->type == X86_OP_MEM) {
                        if (Op->mem.base == X86_REG_RCX || Op->mem.base == X86_REG_ECX) UsesRcx = true;
                        if (Op->mem.base == X86_REG_RDX || Op->mem.base == X86_REG_EDX) UsesRdx = true;
                        if (Op->mem.base == X86_REG_R8 || Op->mem.base == X86_REG_R8D) UsesR8 = true;
                        if (Op->mem.base == X86_REG_R9 || Op->mem.base == X86_REG_R9D) UsesR9 = true;
                    }
                }
            }
            int ArgCount = 0;
            if (UsesRcx) ArgCount = 1;
            if (UsesRdx) ArgCount = 2;
            if (UsesR8) ArgCount = 3;
            if (UsesR9) ArgCount = 4;
            int FloatArgs = 0;
            if (UsesXmm0) FloatArgs++;
            if (UsesXmm1) FloatArgs++;
            if (UsesXmm2) FloatArgs++;
            if (UsesXmm3) FloatArgs++;
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("estimated_arg_count")] = std::max(ArgCount, FloatArgs);
            R[QStringLiteral("integer_args")] = ArgCount;
            R[QStringLiteral("float_args")] = FloatArgs;
            R[QStringLiteral("uses_rcx")] = UsesRcx;
            R[QStringLiteral("uses_rdx")] = UsesRdx;
            R[QStringLiteral("uses_r8")] = UsesR8;
            R[QStringLiteral("uses_r9")] = UsesR9;
            R[QStringLiteral("calling_convention")] = QStringLiteral("Microsoft x64 (assumed)");
            return R;
        });

    RegisterTool(QStringLiteral("get_calling_convention"),
        QStringLiteral("Analyze function to determine calling convention by checking register usage and stack cleanup."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Function address"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Buf(2048, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                     static_cast<size_t>(Buf.size()), Addr, 200, &Insns);
            bool HasSubRsp = false;
            bool HasMovRbpRsp = false;
            bool RetCleanup = false;
            int RetImm = 0;
            bool UsesRcx = false, UsesRdi = false;
            for (size_t I = 0; I < Count; ++I) {
                QString Mn = QString::fromUtf8(Insns[I].mnemonic);
                QString Op = QString::fromUtf8(Insns[I].op_str);
                if (Mn == QStringLiteral("sub") && Op.contains(QStringLiteral("rsp"))) HasSubRsp = true;
                if (Mn == QStringLiteral("mov") && Op == QStringLiteral("rbp, rsp")) HasMovRbpRsp = true;
                if ((Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) && !Op.isEmpty()) {
                    RetCleanup = true;
                    RetImm = Op.toInt();
                    break;
                }
                if (Mn == QStringLiteral("ret") || Mn == QStringLiteral("retn")) break;
                for (uint8_t J = 0; J < Insns[I].detail->x86.op_count; ++J) {
                    if (Insns[I].detail->x86.operands[J].type == X86_OP_REG) {
                        if (Insns[I].detail->x86.operands[J].reg == X86_REG_RCX) UsesRcx = true;
                        if (Insns[I].detail->x86.operands[J].reg == X86_REG_RDI) UsesRdi = true;
                    }
                }
            }
            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);
            ProcessInfo Proc = CoreRef->CurrentProcess();
            QString Convention;
            QString Confidence;
            if (Proc.Arch == Architecture::X64) {
                if (UsesRdi) {
                    Convention = QStringLiteral("System V AMD64 ABI (Linux/macOS)");
                    Confidence = QStringLiteral("high");
                } else if (UsesRcx) {
                    Convention = QStringLiteral("Microsoft x64");
                    Confidence = QStringLiteral("high");
                } else {
                    Convention = QStringLiteral("Microsoft x64 (assumed)");
                    Confidence = QStringLiteral("low");
                }
            } else {
                if (RetCleanup) {
                    Convention = QStringLiteral("stdcall (callee cleanup, ret ") + QString::number(RetImm) + QStringLiteral(")");
                    Confidence = QStringLiteral("high");
                } else {
                    Convention = QStringLiteral("cdecl (caller cleanup)");
                    Confidence = QStringLiteral("medium");
                }
            }
            QJsonObject R;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("calling_convention")] = Convention;
            R[QStringLiteral("confidence")] = Confidence;
            R[QStringLiteral("has_frame_pointer")] = HasMovRbpRsp;
            R[QStringLiteral("has_stack_allocation")] = HasSubRsp;
            R[QStringLiteral("callee_stack_cleanup")] = RetCleanup;
            if (RetCleanup) R[QStringLiteral("cleanup_bytes")] = RetImm;
            return R;
        });
}

}
