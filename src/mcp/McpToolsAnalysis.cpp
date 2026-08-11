#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <capstone/capstone.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <QCryptographicHash>
#include <QRegularExpression>

namespace Fidra {

static QMap<Address, QString> FunctionNames;
static QMap<Address, QString> VariableNames;

static bool InitCapstone(csh& Handle) {
    cs_err E = cs_open(CS_ARCH_X86, CS_MODE_64, &Handle);
    if (E != CS_ERR_OK) return false;
    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}

static QJsonArray DisassembleRegion(ICore* Core, Address Addr, int Count) {
    QJsonArray Instructions;
    size_t ReadSize = static_cast<size_t>(Count) * 15;
    QByteArray Buf(static_cast<int>(ReadSize), '\0');
    if (!Core->ReadMemory(Addr, Buf.data(), ReadSize)) return Instructions;

    csh Handle;
    if (!InitCapstone(Handle)) return Instructions;

    cs_insn* Insns = nullptr;
    size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                           ReadSize, Addr, static_cast<size_t>(Count), &Insns);

    for (size_t I = 0; I < Cnt; ++I) {
        QJsonObject Obj;
        Obj[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
        QByteArray Bytes(reinterpret_cast<const char*>(Insns[I].bytes),
                         static_cast<int>(Insns[I].size));
        Obj[QStringLiteral("bytes")] = QString::fromLatin1(Bytes.toHex(' '));
        Obj[QStringLiteral("mnemonic")] = QString::fromUtf8(Insns[I].mnemonic);
        Obj[QStringLiteral("operands")] = QString::fromUtf8(Insns[I].op_str);
        Obj[QStringLiteral("size")] = static_cast<int>(Insns[I].size);
        Instructions.append(Obj);
    }

    if (Cnt > 0) cs_free(Insns, Cnt);
    cs_close(&Handle);
    return Instructions;
}

static double CalculateEntropy(const uint8_t* Data, size_t Size) {
    if (Size == 0) return 0.0;
    uint64_t Freq[256] = {};
    for (size_t I = 0; I < Size; ++I) Freq[Data[I]]++;
    double Ent = 0.0;
    for (int I = 0; I < 256; ++I) {
        if (Freq[I] == 0) continue;
        double P = static_cast<double>(Freq[I]) / static_cast<double>(Size);
        Ent -= P * std::log2(P);
    }
    return Ent;
}

struct PeInfo {
    bool Valid;
    Address ModBase;
    uint32_t PeOffset;
    bool Is64;
    uint16_t NumberOfSections;
    uint32_t SectionHeaderOffset;
    uint32_t OptionalHeaderOffset;
    uint16_t OptionalHeaderSize;
};

static PeInfo ReadPeInfo(ICore* Core, Address Base) {
    PeInfo Info = {};
    Info.Valid = false;
    Info.ModBase = Base;

    uint8_t Dos[64];
    if (!Core->ReadMemory(Base, Dos, sizeof(Dos))) return Info;
    if (*reinterpret_cast<uint16_t*>(Dos) != 0x5A4D) return Info;

    Info.PeOffset = *reinterpret_cast<uint32_t*>(Dos + 0x3C);

    uint8_t Pe[4096];
    if (!Core->ReadMemory(Base + Info.PeOffset, Pe, sizeof(Pe))) return Info;
    if (*reinterpret_cast<uint32_t*>(Pe) != 0x00004550) return Info;

    uint16_t Machine = *reinterpret_cast<uint16_t*>(Pe + 4);
    Info.Is64 = (Machine == 0x8664);
    Info.NumberOfSections = *reinterpret_cast<uint16_t*>(Pe + 6);
    Info.OptionalHeaderSize = *reinterpret_cast<uint16_t*>(Pe + 20);
    Info.OptionalHeaderOffset = Info.PeOffset + 24;
    Info.SectionHeaderOffset = Info.PeOffset + 24 + Info.OptionalHeaderSize;
    Info.Valid = true;
    return Info;
}

static Address FindModuleBase(ICore* Core, const QString& ModName = QString()) {
    QList<MemoryRegion> Regions = Core->GetMemoryRegions();
    Address Base = 0;
    if (ModName.isEmpty()) {
        ProcessInfo Proc = Core->CurrentProcess();
        for (const MemoryRegion& R : Regions) {
            if (!R.ModuleName.isEmpty()) {
                if (Base == 0 || R.Base < Base) Base = R.Base;
                break;
            }
        }
        if (Base == 0) Base = Proc.BaseAddress;
    } else {
        for (const MemoryRegion& R : Regions) {
            if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
                if (Base == 0 || R.Base < Base) Base = R.Base;
            }
        }
    }
    return Base;
}

void McpToolRegistry::RegisterAnalysisTools() {

    RegisterTool(QStringLiteral("analyze_function"),
        QStringLiteral("Disassemble and analyze a function at the given address. Returns call targets, branches, stack usage, and overall description."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
            {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions to analyze"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsns = A.value(QStringLiteral("max_instructions")).toInt(500);

            size_t ReadSize = static_cast<size_t>(MaxInsns) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory at ") + Schema::FormatAddress(Addr));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(MaxInsns), &Insns);

            QJsonArray Calls, Branches, StringRefs;
            int StackSize = 0;
            int InsnCount = 0;
            Address FuncEnd = Addr;
            bool HitRet = false;

            for (size_t I = 0; I < Cnt && !HitRet; ++I) {
                InsnCount++;
                FuncEnd = Insns[I].address + Insns[I].size;
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                QString Ops = QString::fromUtf8(Insns[I].op_str);

                if (Mnem == QStringLiteral("call")) {
                    QJsonObject C;
                    C[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    C[QStringLiteral("target")] = Ops;
                    Calls.append(C);
                } else if (Mnem.startsWith(QStringLiteral("j")) && Mnem != QStringLiteral("jmp")) {
                    QJsonObject B;
                    B[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    B[QStringLiteral("type")] = Mnem;
                    B[QStringLiteral("target")] = Ops;
                    Branches.append(B);
                } else if (Mnem == QStringLiteral("sub") && Ops.startsWith(QStringLiteral("rsp"))) {
                    bool Ok = false;
                    QString ValStr = Ops.mid(Ops.lastIndexOf(',') + 1).trimmed();
                    if (ValStr.startsWith(QStringLiteral("0x")))
                        StackSize = ValStr.mid(2).toInt(&Ok, 16);
                    else
                        StackSize = ValStr.toInt(&Ok);
                } else if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) {
                    HitRet = true;
                } else if (Mnem == QStringLiteral("lea") && Insns[I].detail) {
                    cs_x86* X86 = &Insns[I].detail->x86;
                    for (uint8_t O = 0; O < X86->op_count; ++O) {
                        if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP) {
                            Address Target = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;
                            char StrBuf[128] = {};
                            if (CoreRef->ReadMemory(Target, StrBuf, sizeof(StrBuf) - 1)) {
                                bool IsPrintable = true;
                                int Len = 0;
                                for (int S = 0; S < 127 && StrBuf[S]; ++S) {
                                    if (StrBuf[S] < 0x20 || StrBuf[S] > 0x7E) { IsPrintable = false; break; }
                                    Len++;
                                }
                                if (IsPrintable && Len >= 4) {
                                    QJsonObject Sr;
                                    Sr[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                                    Sr[QStringLiteral("string_address")] = Schema::FormatAddress(Target);
                                    Sr[QStringLiteral("string")] = QString::fromUtf8(StrBuf, Len);
                                    StringRefs.append(Sr);
                                }
                            }
                        }
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("end_address")] = Schema::FormatAddress(FuncEnd);
            Result[QStringLiteral("size")] = static_cast<qint64>(FuncEnd - Addr);
            Result[QStringLiteral("instruction_count")] = InsnCount;
            Result[QStringLiteral("stack_size")] = StackSize;
            Result[QStringLiteral("calls")] = Calls;
            Result[QStringLiteral("call_count")] = Calls.size();
            Result[QStringLiteral("branches")] = Branches;
            Result[QStringLiteral("branch_count")] = Branches.size();
            Result[QStringLiteral("string_references")] = StringRefs;
            if (FunctionNames.contains(Addr))
                Result[QStringLiteral("name")] = FunctionNames[Addr];
            return Result;
        });

    RegisterTool(QStringLiteral("rename_function"),
        QStringLiteral("Assign a name to a function address for future reference."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
            {QStringLiteral("name"), Schema::String(QStringLiteral("New function name"))}
        }, {QStringLiteral("address"), QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Name = A.value(QStringLiteral("name")).toString();
            FunctionNames[Addr] = Name;
            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("name")] = Name;
            return R;
        });

    RegisterTool(QStringLiteral("rename_variable"),
        QStringLiteral("Assign a name to a variable address for future reference."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Variable address in hex"))},
            {QStringLiteral("name"), Schema::String(QStringLiteral("New variable name"))}
        }, {QStringLiteral("address"), QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Name = A.value(QStringLiteral("name")).toString();
            VariableNames[Addr] = Name;
            QJsonObject R;
            R[QStringLiteral("success")] = true;
            R[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            R[QStringLiteral("name")] = Name;
            return R;
        });

    RegisterTool(QStringLiteral("detect_crypto"),
        QStringLiteral("Scan a memory region for known cryptographic constants (AES S-box, SHA256, MD5, CRC32, RC4)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size to scan"), 1, 16777216)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            const uint8_t* Data = reinterpret_cast<const uint8_t*>(Buf.constData());
            QJsonArray Found;

            const uint8_t AesSbox[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76};
            for (int I = 0; I + 16 <= Size; ++I) {
                if (std::memcmp(Data + I, AesSbox, 16) == 0) {
                    QJsonObject E;
                    E[QStringLiteral("algorithm")] = QStringLiteral("AES");
                    E[QStringLiteral("type")] = QStringLiteral("S-Box");
                    E[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Found.append(E);
                    break;
                }
            }

            const uint8_t Sha256Init[] = {0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb};
            for (int I = 0; I + 8 <= Size; ++I) {
                if (std::memcmp(Data + I, Sha256Init, 8) == 0) {
                    QJsonObject E;
                    E[QStringLiteral("algorithm")] = QStringLiteral("SHA-256");
                    E[QStringLiteral("type")] = QStringLiteral("Init Vector");
                    E[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Found.append(E);
                    break;
                }
            }

            const uint32_t Md5A = 0x67452301;
            const uint32_t Md5B = 0xEFCDAB89;
            for (int I = 0; I + 8 <= Size; I += 4) {
                uint32_t V1 = *reinterpret_cast<const uint32_t*>(Data + I);
                uint32_t V2 = (I + 4 < Size) ? *reinterpret_cast<const uint32_t*>(Data + I + 4) : 0;
                if (V1 == Md5A && V2 == Md5B) {
                    QJsonObject E;
                    E[QStringLiteral("algorithm")] = QStringLiteral("MD5");
                    E[QStringLiteral("type")] = QStringLiteral("Init Constants");
                    E[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Found.append(E);
                    break;
                }
            }

            const uint32_t Crc32Poly = 0xEDB88320;
            for (int I = 0; I + 4 <= Size; I += 4) {
                if (*reinterpret_cast<const uint32_t*>(Data + I) == Crc32Poly) {
                    QJsonObject E;
                    E[QStringLiteral("algorithm")] = QStringLiteral("CRC32");
                    E[QStringLiteral("type")] = QStringLiteral("Polynomial");
                    E[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Found.append(E);
                    break;
                }
            }

            for (int I = 0; I + 256 <= Size; ++I) {
                bool IsKsa = true;
                for (int J = 0; J < 256; ++J) {
                    if (Data[I + J] != static_cast<uint8_t>(J)) { IsKsa = false; break; }
                }
                if (IsKsa) {
                    QJsonObject E;
                    E[QStringLiteral("algorithm")] = QStringLiteral("RC4");
                    E[QStringLiteral("type")] = QStringLiteral("KSA Identity Permutation");
                    E[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Found.append(E);
                    break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("scan_address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("scan_size")] = Size;
            Result[QStringLiteral("found")] = Found;
            Result[QStringLiteral("count")] = Found.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_compiler"),
        QStringLiteral("Detect the compiler and linker used to build the binary by examining PE headers and Rich header."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional, uses main module if empty)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE header"));

            if (*reinterpret_cast<uint16_t*>(Header) != 0x5A4D)
                return Schema::Err(QStringLiteral("Not a valid PE"));

            uint32_t PeOff = *reinterpret_cast<uint32_t*>(Header + 0x3C);
            if (PeOff + 200 > sizeof(Header)) return Schema::Err(QStringLiteral("PE offset out of range"));

            uint8_t* Pe = Header + PeOff;
            uint16_t Machine = *reinterpret_cast<uint16_t*>(Pe + 4);
            uint16_t LinkerMajor = Pe[24 + 2];
            uint16_t LinkerMinor = Pe[24 + 3];

            QString Compiler = QStringLiteral("Unknown");
            QString CompilerVersion;

            if (LinkerMajor >= 14) {
                Compiler = QStringLiteral("MSVC");
                CompilerVersion = QString::number(LinkerMajor) + QStringLiteral(".") + QString::number(LinkerMinor);
            } else if (LinkerMajor >= 2 && LinkerMajor <= 6) {
                Compiler = QStringLiteral("MSVC (Legacy)");
                CompilerVersion = QString::number(LinkerMajor) + QStringLiteral(".") + QString::number(LinkerMinor);
            }

            uint16_t NumSections = *reinterpret_cast<uint16_t*>(Pe + 6);
            uint16_t OptSize = *reinterpret_cast<uint16_t*>(Pe + 20);
            uint32_t SecOff = PeOff + 24 + OptSize;
            QJsonArray SectionNames;
            for (int I = 0; I < NumSections && SecOff + I * 40 + 40 <= sizeof(Header); ++I) {
                char Name[9] = {};
                std::memcpy(Name, Header + SecOff + I * 40, 8);
                SectionNames.append(QString::fromUtf8(Name));
            }

            for (int I = 0; I < SectionNames.size(); ++I) {
                QString Sn = SectionNames[I].toString();
                if (Sn == QStringLiteral(".gcc_exc") || Sn == QStringLiteral(".eh_frame")) {
                    Compiler = QStringLiteral("GCC/MinGW");
                } else if (Sn == QStringLiteral("__TEXT") || Sn == QStringLiteral("__DATA")) {
                    Compiler = QStringLiteral("Clang/LLVM");
                } else if (Sn.startsWith(QStringLiteral("UPX"))) {
                    Compiler = QStringLiteral("UPX Packed");
                }
            }

            bool HasRich = false;
            for (uint32_t I = 0x40; I + 4 < PeOff && I + 4 < sizeof(Header); I += 4) {
                if (*reinterpret_cast<uint32_t*>(Header + I) == 0x68636952) {
                    HasRich = true;
                    break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("compiler")] = Compiler;
            if (!CompilerVersion.isEmpty())
                Result[QStringLiteral("linker_version")] = CompilerVersion;
            Result[QStringLiteral("machine")] = (Machine == 0x8664) ? QStringLiteral("x64") :
                                                (Machine == 0x014C) ? QStringLiteral("x86") : QString::number(Machine, 16);
            Result[QStringLiteral("has_rich_header")] = HasRich;
            Result[QStringLiteral("sections")] = SectionNames;
            return Result;
        });

    RegisterTool(QStringLiteral("find_vulnerabilities"),
        QStringLiteral("Scan disassembled code for potentially dangerous patterns like unsafe function calls, stack overflows, and format strings."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size to scan"), 1, 1048576)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            QJsonArray Vulns;

            for (size_t I = 0; I < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                QString Ops = QString::fromUtf8(Insns[I].op_str);

                if (Mnem == QStringLiteral("call")) {
                    if (Insns[I].detail) {
                        cs_x86* X86 = &Insns[I].detail->x86;
                        if (X86->op_count == 1 && X86->operands[0].type == X86_OP_IMM) {
                            Address Target = static_cast<Address>(X86->operands[0].imm);
                            char StrBuf[64] = {};
                            CoreRef->ReadMemory(Target, StrBuf, sizeof(StrBuf) - 1);
                        }
                    }
                }

                if (Mnem == QStringLiteral("sub") && Ops.contains(QStringLiteral("rsp"))) {
                    QString ValPart = Ops.mid(Ops.lastIndexOf(',') + 1).trimmed();
                    bool Ok = false;
                    int StackAlloc = 0;
                    if (ValPart.startsWith(QStringLiteral("0x")))
                        StackAlloc = ValPart.mid(2).toInt(&Ok, 16);
                    else
                        StackAlloc = ValPart.toInt(&Ok);

                    if (Ok && StackAlloc > 0x1000) {
                        QJsonObject V;
                        V[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        V[QStringLiteral("type")] = QStringLiteral("large_stack_allocation");
                        V[QStringLiteral("description")] = QStringLiteral("Large stack allocation of 0x") + QString::number(StackAlloc, 16);
                        V[QStringLiteral("severity")] = QStringLiteral("medium");
                        Vulns.append(V);
                    }
                }

                if (Mnem == QStringLiteral("rep") || (I > 0 && QString::fromUtf8(Insns[I-1].mnemonic) == QStringLiteral("rep"))) {
                    if (Mnem == QStringLiteral("movsb") || Mnem == QStringLiteral("movsd") || Mnem == QStringLiteral("movsq") ||
                        Mnem == QStringLiteral("stosb") || Mnem == QStringLiteral("stosd")) {
                        QJsonObject V;
                        V[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        V[QStringLiteral("type")] = QStringLiteral("unbounded_copy");
                        V[QStringLiteral("description")] = QStringLiteral("REP MOVS/STOS without visible bounds check");
                        V[QStringLiteral("severity")] = QStringLiteral("high");
                        Vulns.append(V);
                    }
                }

                if (Mnem == QStringLiteral("int") && Ops == QStringLiteral("3")) {
                    QJsonObject V;
                    V[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    V[QStringLiteral("type")] = QStringLiteral("debug_break");
                    V[QStringLiteral("description")] = QStringLiteral("INT3 breakpoint instruction");
                    V[QStringLiteral("severity")] = QStringLiteral("info");
                    Vulns.append(V);
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("vulnerabilities")] = Vulns;
            Result[QStringLiteral("count")] = Vulns.size();
            return Result;
        });

    RegisterTool(QStringLiteral("decompile_function"),
        QStringLiteral("Generate pseudocode from disassembled instructions at the given address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
            {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions"), 1, 2000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsns = A.value(QStringLiteral("max_instructions")).toInt(500);

            size_t ReadSize = static_cast<size_t>(MaxInsns) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(MaxInsns), &Insns);

            QStringList Pseudo;
            QString FuncName = FunctionNames.contains(Addr) ? FunctionNames[Addr] : (QStringLiteral("sub_") + QString::number(Addr, 16));
            Pseudo.append(QStringLiteral("void ") + FuncName + QStringLiteral("() {"));

            int IndentLevel = 1;
            auto Indent = [&]() -> QString { return QString(IndentLevel * 4, ' '); };

            for (size_t I = 0; I < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                QString Ops = QString::fromUtf8(Insns[I].op_str);

                if (Mnem == QStringLiteral("push") && Mnem == QStringLiteral("push")) {
                    continue;
                } else if (Mnem == QStringLiteral("mov")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" = ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("lea")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" = &") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("add")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" += ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("sub")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2) {
                        if (Parts[0].trimmed() == QStringLiteral("rsp"))
                            Pseudo.append(Indent() + QStringLiteral("// stack alloc ") + Parts[1].trimmed());
                        else
                            Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" -= ") + Parts[1].trimmed() + QStringLiteral(";"));
                    }
                } else if (Mnem == QStringLiteral("xor")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2) {
                        if (Parts[0].trimmed() == Parts[1].trimmed())
                            Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" = 0;"));
                        else
                            Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" ^= ") + Parts[1].trimmed() + QStringLiteral(";"));
                    }
                } else if (Mnem == QStringLiteral("and")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" &= ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("or")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" |= ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("shl") || Mnem == QStringLiteral("sal")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" <<= ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("shr") || Mnem == QStringLiteral("sar")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2)
                        Pseudo.append(Indent() + Parts[0].trimmed() + QStringLiteral(" >>= ") + Parts[1].trimmed() + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("test")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2 && Parts[0].trimmed() == Parts[1].trimmed())
                        Pseudo.append(Indent() + QStringLiteral("if (") + Parts[0].trimmed() + QStringLiteral(" == 0) {"));
                    else
                        Pseudo.append(Indent() + QStringLiteral("if (") + Ops + QStringLiteral(") {"));
                } else if (Mnem == QStringLiteral("cmp")) {
                    QStringList Parts = Ops.split(',');
                    if (Parts.size() == 2 && I + 1 < Cnt) {
                        QString NextMnem = QString::fromUtf8(Insns[I + 1].mnemonic);
                        QString CmpOp = QStringLiteral("==");
                        if (NextMnem == QStringLiteral("je") || NextMnem == QStringLiteral("jz")) CmpOp = QStringLiteral("==");
                        else if (NextMnem == QStringLiteral("jne") || NextMnem == QStringLiteral("jnz")) CmpOp = QStringLiteral("!=");
                        else if (NextMnem == QStringLiteral("jg") || NextMnem == QStringLiteral("jnle")) CmpOp = QStringLiteral(">");
                        else if (NextMnem == QStringLiteral("jge") || NextMnem == QStringLiteral("jnl")) CmpOp = QStringLiteral(">=");
                        else if (NextMnem == QStringLiteral("jl") || NextMnem == QStringLiteral("jnge")) CmpOp = QStringLiteral("<");
                        else if (NextMnem == QStringLiteral("jle") || NextMnem == QStringLiteral("jng")) CmpOp = QStringLiteral("<=");
                        else if (NextMnem == QStringLiteral("ja")) CmpOp = QStringLiteral(">(u)");
                        else if (NextMnem == QStringLiteral("jb")) CmpOp = QStringLiteral("<(u)");
                        Pseudo.append(Indent() + QStringLiteral("if (") + Parts[0].trimmed() + QStringLiteral(" ") + CmpOp + QStringLiteral(" ") + Parts[1].trimmed() + QStringLiteral(") {"));
                        ++I;
                        IndentLevel++;
                    }
                } else if (Mnem == QStringLiteral("call")) {
                    Pseudo.append(Indent() + Ops + QStringLiteral("();"));
                } else if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) {
                    Pseudo.append(Indent() + QStringLiteral("return;"));
                    break;
                } else if (Mnem == QStringLiteral("nop") || Mnem == QStringLiteral("endbr64")) {
                    continue;
                } else if (Mnem == QStringLiteral("jmp")) {
                    Pseudo.append(Indent() + QStringLiteral("goto ") + Ops + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("push")) {
                    continue;
                } else if (Mnem == QStringLiteral("pop")) {
                    continue;
                } else if (Mnem == QStringLiteral("inc")) {
                    Pseudo.append(Indent() + Ops + QStringLiteral("++;"));
                } else if (Mnem == QStringLiteral("dec")) {
                    Pseudo.append(Indent() + Ops + QStringLiteral("--;"));
                } else if (Mnem == QStringLiteral("neg")) {
                    Pseudo.append(Indent() + Ops + QStringLiteral(" = -") + Ops + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("not")) {
                    Pseudo.append(Indent() + Ops + QStringLiteral(" = ~") + Ops + QStringLiteral(";"));
                } else if (Mnem == QStringLiteral("imul") || Mnem == QStringLiteral("mul")) {
                    Pseudo.append(Indent() + QStringLiteral("// multiply ") + Ops);
                } else if (Mnem == QStringLiteral("idiv") || Mnem == QStringLiteral("div")) {
                    Pseudo.append(Indent() + QStringLiteral("// divide ") + Ops);
                }
            }

            while (IndentLevel > 0) {
                IndentLevel--;
                Pseudo.append(QString(IndentLevel * 4, ' ') + QStringLiteral("}"));
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("pseudocode")] = Pseudo.join(QStringLiteral("\n"));
            return Result;
        });

    RegisterTool(QStringLiteral("explain_assembly"),
        QStringLiteral("Disassemble instructions and return a natural language explanation of each."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of instructions"), 1, 200)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(20);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray Explained;
            for (size_t I = 0; I < Cnt; ++I) {
                QJsonObject E;
                E[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                QString Ops = QString::fromUtf8(Insns[I].op_str);
                E[QStringLiteral("instruction")] = Mnem + QStringLiteral(" ") + Ops;

                QString Explanation;
                if (Mnem == QStringLiteral("mov")) Explanation = QStringLiteral("Move value: copy ") + Ops.section(',', 1).trimmed() + QStringLiteral(" into ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("lea")) Explanation = QStringLiteral("Load effective address of ") + Ops.section(',', 1).trimmed() + QStringLiteral(" into ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("push")) Explanation = QStringLiteral("Push ") + Ops + QStringLiteral(" onto the stack");
                else if (Mnem == QStringLiteral("pop")) Explanation = QStringLiteral("Pop top of stack into ") + Ops;
                else if (Mnem == QStringLiteral("call")) Explanation = QStringLiteral("Call function at ") + Ops;
                else if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) Explanation = QStringLiteral("Return from function");
                else if (Mnem == QStringLiteral("add")) Explanation = QStringLiteral("Add ") + Ops.section(',', 1).trimmed() + QStringLiteral(" to ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("sub")) Explanation = QStringLiteral("Subtract ") + Ops.section(',', 1).trimmed() + QStringLiteral(" from ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("xor")) {
                    if (Ops.section(',', 0, 0).trimmed() == Ops.section(',', 1).trimmed())
                        Explanation = QStringLiteral("Zero out ") + Ops.section(',', 0, 0).trimmed();
                    else
                        Explanation = QStringLiteral("XOR ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" with ") + Ops.section(',', 1).trimmed();
                }
                else if (Mnem == QStringLiteral("cmp")) Explanation = QStringLiteral("Compare ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" with ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("test")) Explanation = QStringLiteral("Bitwise test ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" AND ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("jmp")) Explanation = QStringLiteral("Unconditional jump to ") + Ops;
                else if (Mnem == QStringLiteral("je") || Mnem == QStringLiteral("jz")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if equal/zero");
                else if (Mnem == QStringLiteral("jne") || Mnem == QStringLiteral("jnz")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if not equal/not zero");
                else if (Mnem == QStringLiteral("jg")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if greater (signed)");
                else if (Mnem == QStringLiteral("jl")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if less (signed)");
                else if (Mnem == QStringLiteral("ja")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if above (unsigned)");
                else if (Mnem == QStringLiteral("jb")) Explanation = QStringLiteral("Jump to ") + Ops + QStringLiteral(" if below (unsigned)");
                else if (Mnem == QStringLiteral("nop")) Explanation = QStringLiteral("No operation");
                else if (Mnem == QStringLiteral("int")) Explanation = QStringLiteral("Software interrupt ") + Ops;
                else if (Mnem == QStringLiteral("syscall")) Explanation = QStringLiteral("Invoke system call");
                else if (Mnem == QStringLiteral("inc")) Explanation = QStringLiteral("Increment ") + Ops + QStringLiteral(" by 1");
                else if (Mnem == QStringLiteral("dec")) Explanation = QStringLiteral("Decrement ") + Ops + QStringLiteral(" by 1");
                else if (Mnem == QStringLiteral("shl") || Mnem == QStringLiteral("sal")) Explanation = QStringLiteral("Shift ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" left by ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("shr") || Mnem == QStringLiteral("sar")) Explanation = QStringLiteral("Shift ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" right by ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("and")) Explanation = QStringLiteral("Bitwise AND ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" with ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("or")) Explanation = QStringLiteral("Bitwise OR ") + Ops.section(',', 0, 0).trimmed() + QStringLiteral(" with ") + Ops.section(',', 1).trimmed();
                else if (Mnem == QStringLiteral("not")) Explanation = QStringLiteral("Bitwise NOT ") + Ops;
                else if (Mnem == QStringLiteral("neg")) Explanation = QStringLiteral("Negate ") + Ops;
                else if (Mnem == QStringLiteral("imul")) Explanation = QStringLiteral("Signed multiply ") + Ops;
                else if (Mnem == QStringLiteral("mul")) Explanation = QStringLiteral("Unsigned multiply ") + Ops;
                else if (Mnem == QStringLiteral("idiv")) Explanation = QStringLiteral("Signed divide by ") + Ops;
                else if (Mnem == QStringLiteral("div")) Explanation = QStringLiteral("Unsigned divide by ") + Ops;
                else if (Mnem == QStringLiteral("movzx")) Explanation = QStringLiteral("Move with zero extension from ") + Ops.section(',', 1).trimmed() + QStringLiteral(" to ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("movsx") || Mnem == QStringLiteral("movsxd")) Explanation = QStringLiteral("Move with sign extension from ") + Ops.section(',', 1).trimmed() + QStringLiteral(" to ") + Ops.section(',', 0, 0).trimmed();
                else if (Mnem == QStringLiteral("cdqe")) Explanation = QStringLiteral("Sign-extend EAX to RAX");
                else if (Mnem == QStringLiteral("cmovne") || Mnem == QStringLiteral("cmovnz")) Explanation = QStringLiteral("Conditional move if not equal: ") + Ops;
                else if (Mnem == QStringLiteral("cmove") || Mnem == QStringLiteral("cmovz")) Explanation = QStringLiteral("Conditional move if equal: ") + Ops;
                else if (Mnem.startsWith(QStringLiteral("cmov"))) Explanation = QStringLiteral("Conditional move: ") + Mnem + QStringLiteral(" ") + Ops;
                else if (Mnem.startsWith(QStringLiteral("set"))) Explanation = QStringLiteral("Set byte on condition: ") + Mnem + QStringLiteral(" ") + Ops;
                else Explanation = Mnem + QStringLiteral(" ") + Ops;

                E[QStringLiteral("explanation")] = Explanation;
                Explained.append(E);
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("instructions")] = Explained;
            Result[QStringLiteral("count")] = Explained.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_strings"),
        QStringLiteral("Scan a memory region for printable ASCII strings with a minimum length."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)},
            {QStringLiteral("min_length"), Schema::Integer(QStringLiteral("Minimum string length"), 1, 256)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            int MinLen = A.value(QStringLiteral("min_length")).toInt(4);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QJsonArray Strings;
            int Start = -1;
            for (int I = 0; I <= Size; ++I) {
                bool Printable = (I < Size) && (Buf[I] >= 0x20 && Buf[I] <= 0x7E);
                if (Printable && Start < 0) {
                    Start = I;
                } else if (!Printable && Start >= 0) {
                    int Len = I - Start;
                    if (Len >= MinLen) {
                        QJsonObject S;
                        S[QStringLiteral("address")] = Schema::FormatAddress(Addr + Start);
                        S[QStringLiteral("string")] = QString::fromUtf8(Buf.constData() + Start, Len);
                        S[QStringLiteral("length")] = Len;
                        Strings.append(S);
                        if (Strings.size() >= 10000) break;
                    }
                    Start = -1;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("strings")] = Strings;
            Result[QStringLiteral("count")] = Strings.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_strings_regex"),
        QStringLiteral("Search found strings in a memory region matching a regex pattern."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)},
            {QStringLiteral("pattern"), Schema::String(QStringLiteral("Regex pattern to match"))},
            {QStringLiteral("min_length"), Schema::Integer(QStringLiteral("Minimum string length"), 1, 256)}
        }, {QStringLiteral("address"), QStringLiteral("size"), QStringLiteral("pattern")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            int MinLen = A.value(QStringLiteral("min_length")).toInt(4);
            QRegularExpression Regex(A.value(QStringLiteral("pattern")).toString());
            if (!Regex.isValid()) return Schema::Err(QStringLiteral("Invalid regex: ") + Regex.errorString());

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QJsonArray Matches;
            int Start = -1;
            for (int I = 0; I <= Size; ++I) {
                bool Printable = (I < Size) && (Buf[I] >= 0x20 && Buf[I] <= 0x7E);
                if (Printable && Start < 0) { Start = I; }
                else if (!Printable && Start >= 0) {
                    int Len = I - Start;
                    if (Len >= MinLen) {
                        QString Str = QString::fromUtf8(Buf.constData() + Start, Len);
                        if (Regex.match(Str).hasMatch()) {
                            QJsonObject S;
                            S[QStringLiteral("address")] = Schema::FormatAddress(Addr + Start);
                            S[QStringLiteral("string")] = Str;
                            Matches.append(S);
                            if (Matches.size() >= 5000) break;
                        }
                    }
                    Start = -1;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("matches")] = Matches;
            Result[QStringLiteral("count")] = Matches.size();
            return Result;
        });

    RegisterTool(QStringLiteral("classify_binary"),
        QStringLiteral("Classify a binary by checking for packer signatures, entropy, and suspicious characteristics."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint8_t Header[4096];
            CoreRef->ReadMemory(Base, Header, sizeof(Header));

            QJsonArray Tags;
            QJsonArray Sections;
            double MaxEntropy = 0;

            for (int I = 0; I < Pe.NumberOfSections && Pe.SectionHeaderOffset + I * 40 + 40 <= sizeof(Header); ++I) {
                uint8_t* Sec = Header + Pe.SectionHeaderOffset + I * 40;
                char Name[9] = {};
                std::memcpy(Name, Sec, 8);
                uint32_t VSize = *reinterpret_cast<uint32_t*>(Sec + 8);
                uint32_t VAddr = *reinterpret_cast<uint32_t*>(Sec + 12);
                uint32_t Chars = *reinterpret_cast<uint32_t*>(Sec + 36);

                int SampleSize = std::min(static_cast<int>(VSize), 4096);
                QByteArray Sample(SampleSize, '\0');
                CoreRef->ReadMemory(Base + VAddr, Sample.data(), static_cast<size_t>(SampleSize));
                double Ent = CalculateEntropy(reinterpret_cast<const uint8_t*>(Sample.constData()), static_cast<size_t>(SampleSize));
                if (Ent > MaxEntropy) MaxEntropy = Ent;

                QJsonObject SecObj;
                SecObj[QStringLiteral("name")] = QString::fromUtf8(Name);
                SecObj[QStringLiteral("entropy")] = Ent;
                SecObj[QStringLiteral("executable")] = (Chars & 0x20000000) != 0;
                SecObj[QStringLiteral("writable")] = (Chars & 0x80000000) != 0;
                Sections.append(SecObj);

                QString SName = QString::fromUtf8(Name);
                if (SName.startsWith(QStringLiteral("UPX"))) Tags.append(QStringLiteral("UPX"));
                if (SName == QStringLiteral(".vmp0") || SName == QStringLiteral(".vmp1")) Tags.append(QStringLiteral("VMProtect"));
                if (SName == QStringLiteral(".themida")) Tags.append(QStringLiteral("Themida"));
                if (SName == QStringLiteral(".aspack")) Tags.append(QStringLiteral("ASPack"));
                if (SName == QStringLiteral(".nsp0") || SName == QStringLiteral(".nsp1")) Tags.append(QStringLiteral("NSPack"));
                if ((Chars & 0xE0000000) == 0xE0000000) Tags.append(QStringLiteral("RWX section: ") + SName);
            }

            if (MaxEntropy > 7.5) Tags.append(QStringLiteral("High entropy (likely packed/encrypted)"));

            QString Classification = QStringLiteral("Native executable");
            if (Tags.size() > 0) Classification = QStringLiteral("Possibly packed/protected");

            QJsonObject Result;
            Result[QStringLiteral("classification")] = Classification;
            Result[QStringLiteral("tags")] = Tags;
            Result[QStringLiteral("max_entropy")] = MaxEntropy;
            Result[QStringLiteral("sections")] = Sections;
            return Result;
        });

    RegisterTool(QStringLiteral("diff_regions"),
        QStringLiteral("Compare two memory regions byte by byte and return differences."),
        Schema::Build({
            {QStringLiteral("address1"), Schema::String(QStringLiteral("First region address in hex"))},
            {QStringLiteral("address2"), Schema::String(QStringLiteral("Second region address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Size to compare"), 1, 1048576)}
        }, {QStringLiteral("address1"), QStringLiteral("address2"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr1 = Schema::ParseHexAddress(A.value(QStringLiteral("address1")).toString());
            Address Addr2 = Schema::ParseHexAddress(A.value(QStringLiteral("address2")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(256);

            QByteArray Buf1(Size, '\0'), Buf2(Size, '\0');
            if (!CoreRef->ReadMemory(Addr1, Buf1.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read region 1"));
            if (!CoreRef->ReadMemory(Addr2, Buf2.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read region 2"));

            QJsonArray Diffs;
            for (int I = 0; I < Size; ++I) {
                if (Buf1[I] != Buf2[I]) {
                    QJsonObject D;
                    D[QStringLiteral("offset")] = I;
                    D[QStringLiteral("address1")] = Schema::FormatAddress(Addr1 + I);
                    D[QStringLiteral("address2")] = Schema::FormatAddress(Addr2 + I);
                    D[QStringLiteral("byte1")] = QString::number(static_cast<uint8_t>(Buf1[I]), 16).rightJustified(2, '0');
                    D[QStringLiteral("byte2")] = QString::number(static_cast<uint8_t>(Buf2[I]), 16).rightJustified(2, '0');
                    Diffs.append(D);
                    if (Diffs.size() >= 10000) break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("total_size")] = Size;
            Result[QStringLiteral("differences")] = Diffs;
            Result[QStringLiteral("diff_count")] = Diffs.size();
            Result[QStringLiteral("match_percentage")] = 100.0 * (1.0 - static_cast<double>(Diffs.size()) / static_cast<double>(Size));
            return Result;
        });

    RegisterTool(QStringLiteral("find_vtables"),
        QStringLiteral("Scan memory region for C++ vtable patterns (consecutive valid function pointers)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)},
            {QStringLiteral("min_entries"), Schema::Integer(QStringLiteral("Minimum vtable entries"), 2, 100)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            int MinEntries = A.value(QStringLiteral("min_entries")).toInt(3);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            auto IsExecutable = [&](Address A) -> bool {
                for (const MemoryRegion& R : Regions) {
                    if (A >= R.Base && A < R.Base + R.Size) {
                        return (R.Protection & 0x10) || (R.Protection & 0x20) || (R.Protection & 0x40);
                    }
                }
                return false;
            };

            QJsonArray VTables;
            for (int I = 0; I + 8 <= Size; I += 8) {
                int Consecutive = 0;
                QJsonArray Entries;
                for (int J = I; J + 8 <= Size; J += 8) {
                    Address Ptr = *reinterpret_cast<const uint64_t*>(Buf.constData() + J);
                    if (Ptr == 0 || !IsExecutable(Ptr)) break;
                    Consecutive++;
                    QJsonObject Entry;
                    Entry[QStringLiteral("index")] = Consecutive - 1;
                    Entry[QStringLiteral("address")] = Schema::FormatAddress(Ptr);
                    Entries.append(Entry);
                    if (Consecutive >= 200) break;
                }
                if (Consecutive >= MinEntries) {
                    QJsonObject Vt;
                    Vt[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    Vt[QStringLiteral("entry_count")] = Consecutive;
                    Vt[QStringLiteral("entries")] = Entries;
                    VTables.append(Vt);
                    I += Consecutive * 8 - 8;
                    if (VTables.size() >= 500) break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("vtables")] = VTables;
            Result[QStringLiteral("count")] = VTables.size();
            return Result;
        });

    RegisterTool(QStringLiteral("recover_struct"),
        QStringLiteral("Read memory and suggest struct field layout based on pointer-sized alignment and value heuristics."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Struct base address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Struct size to analyze"), 1, 65536)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(64);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QJsonArray Fields;
            int Offset = 0;
            while (Offset + 8 <= Size) {
                uint64_t QwordVal = *reinterpret_cast<const uint64_t*>(Buf.constData() + Offset);
                uint32_t DwordVal = *reinterpret_cast<const uint32_t*>(Buf.constData() + Offset);
                float FloatVal = *reinterpret_cast<const float*>(Buf.constData() + Offset);

                QJsonObject Field;
                Field[QStringLiteral("offset")] = Offset;
                Field[QStringLiteral("hex")] = QString::fromLatin1(QByteArray(Buf.constData() + Offset, 8).toHex(' '));

                if (QwordVal >= 0x10000 && QwordVal < 0x7FFFFFFFFFFF) {
                    Field[QStringLiteral("type")] = QStringLiteral("pointer");
                    Field[QStringLiteral("value")] = Schema::FormatAddress(QwordVal);
                    Field[QStringLiteral("size")] = 8;
                    Fields.append(Field);
                    Offset += 8;
                } else if (DwordVal == 0 && Offset + 4 <= Size) {
                    Field[QStringLiteral("type")] = QStringLiteral("int32");
                    Field[QStringLiteral("value")] = 0;
                    Field[QStringLiteral("size")] = 4;
                    Fields.append(Field);
                    Offset += 4;
                } else if (std::abs(FloatVal) > 0.001f && std::abs(FloatVal) < 1e10f && FloatVal == FloatVal) {
                    Field[QStringLiteral("type")] = QStringLiteral("float");
                    Field[QStringLiteral("value")] = static_cast<double>(FloatVal);
                    Field[QStringLiteral("size")] = 4;
                    Fields.append(Field);
                    Offset += 4;
                } else if (DwordVal <= 0xFFFF) {
                    Field[QStringLiteral("type")] = QStringLiteral("int32");
                    Field[QStringLiteral("value")] = static_cast<int>(DwordVal);
                    Field[QStringLiteral("size")] = 4;
                    Fields.append(Field);
                    Offset += 4;
                } else {
                    Field[QStringLiteral("type")] = QStringLiteral("uint64");
                    Field[QStringLiteral("value")] = Schema::FormatAddress(QwordVal);
                    Field[QStringLiteral("size")] = 8;
                    Fields.append(Field);
                    Offset += 8;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("total_size")] = Size;
            Result[QStringLiteral("fields")] = Fields;
            Result[QStringLiteral("field_count")] = Fields.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_obfuscation"),
        QStringLiteral("Analyze code for obfuscation indicators: junk instructions, opaque predicates, control flow flattening."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 1048576)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            int JunkCount = 0, OpaqueCount = 0, DispatcherJmps = 0, NopSleds = 0;
            QJsonArray Indicators;

            for (size_t I = 0; I < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                QString Ops = QString::fromUtf8(Insns[I].op_str);

                if ((Mnem == QStringLiteral("mov") || Mnem == QStringLiteral("lea") || Mnem == QStringLiteral("xchg")) && I + 1 < Cnt) {
                    QString NextMnem = QString::fromUtf8(Insns[I + 1].mnemonic);
                    QString NextOps = QString::fromUtf8(Insns[I + 1].op_str);
                    if (NextMnem == Mnem) {
                        QStringList P1 = Ops.split(',');
                        QStringList P2 = NextOps.split(',');
                        if (P1.size() == 2 && P2.size() == 2 && P1[0].trimmed() == P2[1].trimmed() && P1[1].trimmed() == P2[0].trimmed()) {
                            JunkCount++;
                        }
                    }
                }

                if (Mnem == QStringLiteral("xor") && Ops.section(',', 0, 0).trimmed() == Ops.section(',', 1).trimmed()) {
                    if (I + 1 < Cnt) {
                        QString NextMnem = QString::fromUtf8(Insns[I + 1].mnemonic);
                        if (NextMnem == QStringLiteral("je") || NextMnem == QStringLiteral("jz")) {
                            OpaqueCount++;
                            QJsonObject Ind;
                            Ind[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                            Ind[QStringLiteral("type")] = QStringLiteral("opaque_predicate");
                            Ind[QStringLiteral("detail")] = QStringLiteral("XOR reg,reg always sets zero flag - conditional jump is always taken");
                            Indicators.append(Ind);
                        }
                    }
                }

                if (Mnem == QStringLiteral("jmp") && Ops.contains(QStringLiteral("["))) {
                    DispatcherJmps++;
                }

                if (Mnem == QStringLiteral("nop")) {
                    int NopRun = 1;
                    while (I + NopRun < Cnt && QString::fromUtf8(Insns[I + NopRun].mnemonic) == QStringLiteral("nop")) NopRun++;
                    if (NopRun >= 5) {
                        NopSleds++;
                        QJsonObject Ind;
                        Ind[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Ind[QStringLiteral("type")] = QStringLiteral("nop_sled");
                        Ind[QStringLiteral("length")] = NopRun;
                        Indicators.append(Ind);
                        I += NopRun - 1;
                    }
                }

                if (Mnem == QStringLiteral("push") && I + 1 < Cnt && QString::fromUtf8(Insns[I+1].mnemonic) == QStringLiteral("pop")) {
                    JunkCount++;
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            int Score = JunkCount * 2 + OpaqueCount * 5 + DispatcherJmps * 3 + NopSleds;
            QString Level = QStringLiteral("none");
            if (Score > 20) Level = QStringLiteral("heavy");
            else if (Score > 10) Level = QStringLiteral("moderate");
            else if (Score > 3) Level = QStringLiteral("light");

            QJsonObject Result;
            Result[QStringLiteral("obfuscation_level")] = Level;
            Result[QStringLiteral("score")] = Score;
            Result[QStringLiteral("junk_instructions")] = JunkCount;
            Result[QStringLiteral("opaque_predicates")] = OpaqueCount;
            Result[QStringLiteral("dispatcher_jumps")] = DispatcherJmps;
            Result[QStringLiteral("nop_sleds")] = NopSleds;
            Result[QStringLiteral("indicators")] = Indicators;
            return Result;
        });

    RegisterTool(QStringLiteral("find_antidbg"),
        QStringLiteral("Scan code for anti-debugging techniques (API calls, timing checks, int 2d, etc)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            const uint8_t* Data = reinterpret_cast<const uint8_t*>(Buf.constData());
            QJsonArray Tricks;

            const uint8_t Int2d[] = {0xCD, 0x2D};
            for (int I = 0; I + 2 <= Size; ++I) {
                if (Data[I] == Int2d[0] && Data[I+1] == Int2d[1]) {
                    QJsonObject T;
                    T[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    T[QStringLiteral("technique")] = QStringLiteral("INT 2D");
                    T[QStringLiteral("description")] = QStringLiteral("Kernel anti-debug interrupt - causes exception in non-debugged process");
                    Tricks.append(T);
                }
            }

            const uint8_t Rdtsc[] = {0x0F, 0x31};
            int RdtscCount = 0;
            for (int I = 0; I + 2 <= Size; ++I) {
                if (Data[I] == Rdtsc[0] && Data[I+1] == Rdtsc[1]) {
                    RdtscCount++;
                    if (RdtscCount <= 5) {
                        QJsonObject T;
                        T[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                        T[QStringLiteral("technique")] = QStringLiteral("RDTSC");
                        T[QStringLiteral("description")] = QStringLiteral("Timing check using RDTSC instruction");
                        Tricks.append(T);
                    }
                }
            }

            QStringList AntiDbgApis = {
                QStringLiteral("IsDebuggerPresent"),
                QStringLiteral("CheckRemoteDebuggerPresent"),
                QStringLiteral("NtQueryInformationProcess"),
                QStringLiteral("OutputDebugString"),
                QStringLiteral("NtSetInformationThread"),
                QStringLiteral("NtClose"),
                QStringLiteral("CloseHandle")
            };

            for (const QString& Api : AntiDbgApis) {
                QByteArray ApiBytes = Api.toUtf8();
                int Pos = Buf.indexOf(ApiBytes);
                if (Pos >= 0) {
                    QJsonObject T;
                    T[QStringLiteral("address")] = Schema::FormatAddress(Addr + Pos);
                    T[QStringLiteral("technique")] = QStringLiteral("API String: ") + Api;
                    T[QStringLiteral("description")] = QStringLiteral("Reference to anti-debug API function name");
                    Tricks.append(T);
                }
            }

            const uint8_t Cpuid[] = {0x0F, 0xA2};
            for (int I = 0; I + 2 <= Size; ++I) {
                if (Data[I] == Cpuid[0] && Data[I+1] == Cpuid[1]) {
                    QJsonObject T;
                    T[QStringLiteral("address")] = Schema::FormatAddress(Addr + I);
                    T[QStringLiteral("technique")] = QStringLiteral("CPUID");
                    T[QStringLiteral("description")] = QStringLiteral("CPUID instruction - may be used for VM/hypervisor detection");
                    Tricks.append(T);
                    break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("techniques")] = Tricks;
            Result[QStringLiteral("count")] = Tricks.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_call_graph"),
        QStringLiteral("Disassemble a function and extract all CALL targets to build a call graph."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
            {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsns = A.value(QStringLiteral("max_instructions")).toInt(1000);

            size_t ReadSize = static_cast<size_t>(MaxInsns) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(MaxInsns), &Insns);

            QJsonArray Nodes;
            QMap<Address, int> SeenTargets;

            for (size_t I = 0; I < Cnt; ++I) {
                if (QString::fromUtf8(Insns[I].mnemonic) != QStringLiteral("call")) continue;
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                if (X86->op_count < 1) continue;
                if (X86->operands[0].type == X86_OP_IMM) {
                    Address Target = static_cast<Address>(X86->operands[0].imm);
                    SeenTargets[Target]++;
                    QJsonObject Node;
                    Node[QStringLiteral("caller")] = Schema::FormatAddress(Insns[I].address);
                    Node[QStringLiteral("target")] = Schema::FormatAddress(Target);
                    Node[QStringLiteral("type")] = QStringLiteral("direct");
                    if (FunctionNames.contains(Target))
                        Node[QStringLiteral("name")] = FunctionNames[Target];
                    Nodes.append(Node);
                } else {
                    QJsonObject Node;
                    Node[QStringLiteral("caller")] = Schema::FormatAddress(Insns[I].address);
                    Node[QStringLiteral("target")] = QString::fromUtf8(Insns[I].op_str);
                    Node[QStringLiteral("type")] = QStringLiteral("indirect");
                    Nodes.append(Node);
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("function")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("calls")] = Nodes;
            Result[QStringLiteral("unique_targets")] = SeenTargets.size();
            Result[QStringLiteral("total_calls")] = Nodes.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_xrefs_to"),
        QStringLiteral("Scan code for cross-references to a target address (calls, lea, mov)."),
        Schema::Build({
            {QStringLiteral("target"), Schema::String(QStringLiteral("Target address to find references to"))},
            {QStringLiteral("search_address"), Schema::String(QStringLiteral("Start of search region"))},
            {QStringLiteral("search_size"), Schema::Integer(QStringLiteral("Search region size"), 1, 16777216)}
        }, {QStringLiteral("target"), QStringLiteral("search_address"), QStringLiteral("search_size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Target = Schema::ParseHexAddress(A.value(QStringLiteral("target")).toString());
            Address SearchAddr = Schema::ParseHexAddress(A.value(QStringLiteral("search_address")).toString());
            int SearchSize = A.value(QStringLiteral("search_size")).toInt(65536);

            QByteArray Buf(SearchSize, '\0');
            if (!CoreRef->ReadMemory(SearchAddr, Buf.data(), static_cast<size_t>(SearchSize)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(SearchSize), SearchAddr, 0, &Insns);

            QJsonArray Xrefs;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                for (uint8_t O = 0; O < X86->op_count; ++O) {
                    Address RefAddr = 0;
                    if (X86->operands[O].type == X86_OP_IMM)
                        RefAddr = static_cast<Address>(X86->operands[O].imm);
                    else if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP)
                        RefAddr = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;

                    if (RefAddr == Target) {
                        QJsonObject Xref;
                        Xref[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Xref[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                        if (Mnem == QStringLiteral("call")) Xref[QStringLiteral("type")] = QStringLiteral("call");
                        else if (Mnem.startsWith(QStringLiteral("j"))) Xref[QStringLiteral("type")] = QStringLiteral("jump");
                        else if (Mnem == QStringLiteral("lea")) Xref[QStringLiteral("type")] = QStringLiteral("lea");
                        else Xref[QStringLiteral("type")] = QStringLiteral("data");
                        Xrefs.append(Xref);
                    }
                }
                if (Xrefs.size() >= 1000) break;
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("target")] = Schema::FormatAddress(Target);
            Result[QStringLiteral("xrefs")] = Xrefs;
            Result[QStringLiteral("count")] = Xrefs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_xrefs_from"),
        QStringLiteral("Disassemble at an address and list all addresses referenced by those instructions."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of instructions"), 1, 500)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(50);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray Refs;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                for (uint8_t O = 0; O < X86->op_count; ++O) {
                    Address RefAddr = 0;
                    QString RefType;
                    if (X86->operands[O].type == X86_OP_IMM) {
                        RefAddr = static_cast<Address>(X86->operands[O].imm);
                        RefType = QStringLiteral("immediate");
                    } else if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP) {
                        RefAddr = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;
                        RefType = QStringLiteral("rip_relative");
                    }
                    if (RefAddr != 0 && RefAddr != Insns[I].address) {
                        QJsonObject Ref;
                        Ref[QStringLiteral("from")] = Schema::FormatAddress(Insns[I].address);
                        Ref[QStringLiteral("to")] = Schema::FormatAddress(RefAddr);
                        Ref[QStringLiteral("type")] = RefType;
                        Ref[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        Refs.append(Ref);
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("references")] = Refs;
            Result[QStringLiteral("count")] = Refs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_functions"),
        QStringLiteral("Scan a memory region for function prologues (push rbp; mov rbp,rsp and similar patterns)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            const uint8_t* Data = reinterpret_cast<const uint8_t*>(Buf.constData());
            QJsonArray Functions;

            const uint8_t Prol1[] = {0x55, 0x48, 0x89, 0xE5};
            const uint8_t Prol2[] = {0x55, 0x48, 0x8B, 0xEC};
            const uint8_t Prol3[] = {0x48, 0x83, 0xEC};
            const uint8_t Prol4[] = {0x48, 0x89, 0x5C, 0x24};

            for (int I = 0; I + 4 <= Size; ++I) {
                bool Found = false;
                QString PrologueType;

                if (I + 4 <= Size && std::memcmp(Data + I, Prol1, 4) == 0) {
                    Found = true; PrologueType = QStringLiteral("push rbp; mov rbp, rsp");
                } else if (I + 4 <= Size && std::memcmp(Data + I, Prol2, 4) == 0) {
                    Found = true; PrologueType = QStringLiteral("push rbp; mov rbp, rsp (alt)");
                } else if (I + 3 <= Size && std::memcmp(Data + I, Prol3, 3) == 0) {
                    Found = true; PrologueType = QStringLiteral("sub rsp, imm");
                } else if (I + 4 <= Size && std::memcmp(Data + I, Prol4, 4) == 0) {
                    Found = true; PrologueType = QStringLiteral("mov [rsp+N], rbx");
                }

                if (Found) {
                    QJsonObject Func;
                    Address FuncAddr = Addr + I;
                    Func[QStringLiteral("address")] = Schema::FormatAddress(FuncAddr);
                    Func[QStringLiteral("prologue")] = PrologueType;
                    if (FunctionNames.contains(FuncAddr))
                        Func[QStringLiteral("name")] = FunctionNames[FuncAddr];
                    Functions.append(Func);
                    if (Functions.size() >= 10000) break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("functions")] = Functions;
            Result[QStringLiteral("count")] = Functions.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_function_bounds"),
        QStringLiteral("Find the start and end of a function by scanning for prologue and return instructions."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address within the function"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());

            Address ScanStart = (Addr > 4096) ? Addr - 4096 : 0;
            size_t ScanSize = 4096;
            QByteArray Buf(static_cast<int>(ScanSize), '\0');
            if (!CoreRef->ReadMemory(ScanStart, Buf.data(), ScanSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ScanSize, ScanStart, 0, &Insns);

            Address FuncStart = Addr;
            for (size_t I = 0; I < Cnt; ++I) {
                if (Insns[I].address > Addr) break;
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                if (Mnem == QStringLiteral("push") && QString::fromUtf8(Insns[I].op_str) == QStringLiteral("rbp")) {
                    FuncStart = Insns[I].address;
                } else if (Insns[I].size >= 3 && Insns[I].bytes[0] == 0x48 && Insns[I].bytes[1] == 0x83 && Insns[I].bytes[2] == 0xEC) {
                    if (I == 0 || QString::fromUtf8(Insns[I-1].mnemonic) == QStringLiteral("ret") || QString::fromUtf8(Insns[I-1].mnemonic) == QStringLiteral("int3") || QString::fromUtf8(Insns[I-1].mnemonic) == QStringLiteral("nop")) {
                        FuncStart = Insns[I].address;
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);

            QByteArray FwdBuf(32768, '\0');
            if (!CoreRef->ReadMemory(FuncStart, FwdBuf.data(), 32768)) {
                cs_close(&Handle);
                return Schema::Err(QStringLiteral("Failed to read forward"));
            }

            cs_insn* FwdInsns = nullptr;
            size_t FwdCnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(FwdBuf.constData()),
                                      32768, FuncStart, 0, &FwdInsns);

            Address FuncEnd = FuncStart;
            for (size_t I = 0; I < FwdCnt; ++I) {
                QString Mnem = QString::fromUtf8(FwdInsns[I].mnemonic);
                if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) {
                    FuncEnd = FwdInsns[I].address + FwdInsns[I].size;
                    break;
                }
                if (Mnem == QStringLiteral("int3") && I > 10) {
                    FuncEnd = FwdInsns[I].address;
                    break;
                }
            }

            if (FwdCnt > 0) cs_free(FwdInsns, FwdCnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("start")] = Schema::FormatAddress(FuncStart);
            Result[QStringLiteral("end")] = Schema::FormatAddress(FuncEnd);
            Result[QStringLiteral("size")] = static_cast<qint64>(FuncEnd - FuncStart);
            return Result;
        });

    RegisterTool(QStringLiteral("get_basic_blocks"),
        QStringLiteral("Split a function into basic blocks at branch and call boundaries."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Function address in hex"))},
            {QStringLiteral("max_instructions"), Schema::Integer(QStringLiteral("Max instructions"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxInsns = A.value(QStringLiteral("max_instructions")).toInt(1000);

            size_t ReadSize = static_cast<size_t>(MaxInsns) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(MaxInsns), &Insns);

            QJsonArray Blocks;
            Address BlockStart = Addr;
            int BlockInsns = 0;

            for (size_t I = 0; I < Cnt; ++I) {
                BlockInsns++;
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                bool IsTerminator = Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn") ||
                                    Mnem == QStringLiteral("jmp") || Mnem.startsWith(QStringLiteral("j"));

                if (IsTerminator || I + 1 == Cnt) {
                    Address BlockEnd = Insns[I].address + Insns[I].size;
                    QJsonObject Block;
                    Block[QStringLiteral("start")] = Schema::FormatAddress(BlockStart);
                    Block[QStringLiteral("end")] = Schema::FormatAddress(BlockEnd);
                    Block[QStringLiteral("size")] = static_cast<qint64>(BlockEnd - BlockStart);
                    Block[QStringLiteral("instruction_count")] = BlockInsns;
                    Block[QStringLiteral("terminator")] = Mnem + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                    Blocks.append(Block);

                    if (I + 1 < Cnt) BlockStart = Insns[I + 1].address;
                    BlockInsns = 0;

                    if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) break;
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("function")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("basic_blocks")] = Blocks;
            Result[QStringLiteral("count")] = Blocks.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_switch_tables"),
        QStringLiteral("Look for indirect jump patterns indicating switch/case jump tables."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 1048576)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            QJsonArray Tables;
            for (size_t I = 0; I < Cnt; ++I) {
                if (QString::fromUtf8(Insns[I].mnemonic) != QStringLiteral("jmp")) continue;
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                if (X86->op_count < 1 || X86->operands[0].type != X86_OP_MEM) continue;
                if (X86->operands[0].mem.scale >= 4) {
                    QJsonObject Tbl;
                    Tbl[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    Tbl[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                    Tbl[QStringLiteral("scale")] = X86->operands[0].mem.scale;
                    Tables.append(Tbl);
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("switch_tables")] = Tables;
            Result[QStringLiteral("count")] = Tables.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_loop_structures"),
        QStringLiteral("Detect backward jumps in code indicating loop constructs."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 1048576)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            QJsonArray Loops;
            for (size_t I = 0; I < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                if (!Mnem.startsWith(QStringLiteral("j")) && Mnem != QStringLiteral("loop")) continue;
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                if (X86->op_count < 1 || X86->operands[0].type != X86_OP_IMM) continue;

                Address Target = static_cast<Address>(X86->operands[0].imm);
                if (Target < Insns[I].address) {
                    QJsonObject Loop;
                    Loop[QStringLiteral("back_edge")] = Schema::FormatAddress(Insns[I].address);
                    Loop[QStringLiteral("target")] = Schema::FormatAddress(Target);
                    Loop[QStringLiteral("type")] = Mnem;
                    Loop[QStringLiteral("body_size")] = static_cast<qint64>(Insns[I].address - Target);
                    Loops.append(Loop);
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("loops")] = Loops;
            Result[QStringLiteral("count")] = Loops.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_data_refs"),
        QStringLiteral("Find RIP-relative data references in code (LEA, MOV with RIP-relative addressing)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Instructions to scan"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(200);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray Refs;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                for (uint8_t O = 0; O < X86->op_count; ++O) {
                    if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP) {
                        Address DataAddr = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;
                        QJsonObject Ref;
                        Ref[QStringLiteral("instruction_address")] = Schema::FormatAddress(Insns[I].address);
                        Ref[QStringLiteral("data_address")] = Schema::FormatAddress(DataAddr);
                        Ref[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        Refs.append(Ref);
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("data_references")] = Refs;
            Result[QStringLiteral("count")] = Refs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_string_refs"),
        QStringLiteral("Given a string, find code locations that reference it in a memory region."),
        Schema::Build({
            {QStringLiteral("string"), Schema::String(QStringLiteral("String to search for"))},
            {QStringLiteral("search_address"), Schema::String(QStringLiteral("Code region start"))},
            {QStringLiteral("search_size"), Schema::Integer(QStringLiteral("Code region size"), 1, 16777216)},
            {QStringLiteral("data_address"), Schema::String(QStringLiteral("Data region start"))},
            {QStringLiteral("data_size"), Schema::Integer(QStringLiteral("Data region size"), 1, 16777216)}
        }, {QStringLiteral("string"), QStringLiteral("search_address"), QStringLiteral("search_size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString SearchString = A.value(QStringLiteral("string")).toString();
            Address CodeAddr = Schema::ParseHexAddress(A.value(QStringLiteral("search_address")).toString());
            int CodeSize = A.value(QStringLiteral("search_size")).toInt(65536);
            Address DataAddr = Schema::ParseHexAddress(A.value(QStringLiteral("data_address")).toString());
            int DataSize = A.value(QStringLiteral("data_size")).toInt(0);

            Address StringAddr = 0;
            if (DataSize > 0 && DataAddr > 0) {
                QByteArray DataBuf(DataSize, '\0');
                if (CoreRef->ReadMemory(DataAddr, DataBuf.data(), static_cast<size_t>(DataSize))) {
                    int Pos = DataBuf.indexOf(SearchString.toUtf8());
                    if (Pos >= 0) StringAddr = DataAddr + Pos;
                }
            }

            if (StringAddr == 0) {
                QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
                for (const MemoryRegion& R : Regions) {
                    int ChunkSize = std::min(static_cast<int>(R.Size), 1048576);
                    QByteArray Chunk(ChunkSize, '\0');
                    if (CoreRef->ReadMemory(R.Base, Chunk.data(), static_cast<size_t>(ChunkSize))) {
                        int Pos = Chunk.indexOf(SearchString.toUtf8());
                        if (Pos >= 0) { StringAddr = R.Base + Pos; break; }
                    }
                }
            }

            if (StringAddr == 0) return Schema::Err(QStringLiteral("String not found in memory"));

            QByteArray CodeBuf(CodeSize, '\0');
            if (!CoreRef->ReadMemory(CodeAddr, CodeBuf.data(), static_cast<size_t>(CodeSize)))
                return Schema::Err(QStringLiteral("Failed to read code region"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(CodeBuf.constData()),
                                   static_cast<size_t>(CodeSize), CodeAddr, 0, &Insns);

            QJsonArray Refs;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                for (uint8_t O = 0; O < X86->op_count; ++O) {
                    Address RefTarget = 0;
                    if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP)
                        RefTarget = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;
                    else if (X86->operands[O].type == X86_OP_IMM)
                        RefTarget = static_cast<Address>(X86->operands[O].imm);

                    if (RefTarget == StringAddr) {
                        QJsonObject Ref;
                        Ref[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                        Ref[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                        Refs.append(Ref);
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("string")] = SearchString;
            Result[QStringLiteral("string_address")] = Schema::FormatAddress(StringAddr);
            Result[QStringLiteral("references")] = Refs;
            Result[QStringLiteral("count")] = Refs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_section_info"),
        QStringLiteral("Parse PE section headers and return detailed section information."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE header"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            QJsonArray Sections;
            for (int I = 0; I < Pe.NumberOfSections && Pe.SectionHeaderOffset + I * 40 + 40 <= sizeof(Header); ++I) {
                uint8_t* Sec = Header + Pe.SectionHeaderOffset + I * 40;
                char Name[9] = {};
                std::memcpy(Name, Sec, 8);

                QJsonObject SecObj;
                SecObj[QStringLiteral("name")] = QString::fromUtf8(Name);
                SecObj[QStringLiteral("virtual_size")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Sec + 8));
                SecObj[QStringLiteral("virtual_address")] = Schema::FormatAddress(Base + *reinterpret_cast<uint32_t*>(Sec + 12));
                SecObj[QStringLiteral("raw_size")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Sec + 16));
                SecObj[QStringLiteral("raw_offset")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Sec + 20));
                uint32_t Chars = *reinterpret_cast<uint32_t*>(Sec + 36);
                SecObj[QStringLiteral("characteristics")] = Schema::FormatAddress(Chars);
                SecObj[QStringLiteral("executable")] = (Chars & 0x20000000) != 0;
                SecObj[QStringLiteral("readable")] = (Chars & 0x40000000) != 0;
                SecObj[QStringLiteral("writable")] = (Chars & 0x80000000) != 0;
                Sections.append(SecObj);
            }

            QJsonObject Result;
            Result[QStringLiteral("base")] = Schema::FormatAddress(Base);
            Result[QStringLiteral("sections")] = Sections;
            Result[QStringLiteral("count")] = Sections.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_entry_point"),
        QStringLiteral("Get the entry point address from the PE optional header."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint32_t Ep = *reinterpret_cast<uint32_t*>(Header + Pe.OptionalHeaderOffset + 16);

            QJsonObject Result;
            Result[QStringLiteral("entry_point_rva")] = Schema::FormatAddress(Ep);
            Result[QStringLiteral("entry_point")] = Schema::FormatAddress(Base + Ep);
            Result[QStringLiteral("base")] = Schema::FormatAddress(Base);
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_info"),
        QStringLiteral("Full PE header parsing: DOS header, COFF header, Optional header fields."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint16_t Magic = *reinterpret_cast<uint16_t*>(Opt);

            QJsonObject Result;
            Result[QStringLiteral("base")] = Schema::FormatAddress(Base);
            Result[QStringLiteral("is_64bit")] = Pe.Is64;
            Result[QStringLiteral("magic")] = Schema::FormatAddress(Magic);
            Result[QStringLiteral("linker_version")] = QString::number(Opt[2]) + QStringLiteral(".") + QString::number(Opt[3]);
            Result[QStringLiteral("size_of_code")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 4));
            Result[QStringLiteral("entry_point")] = Schema::FormatAddress(Base + *reinterpret_cast<uint32_t*>(Opt + 16));
            Result[QStringLiteral("image_base")] = Pe.Is64 ? Schema::FormatAddress(*reinterpret_cast<uint64_t*>(Opt + 24)) : Schema::FormatAddress(*reinterpret_cast<uint32_t*>(Opt + 28));
            Result[QStringLiteral("section_alignment")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 32));
            Result[QStringLiteral("file_alignment")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 36));
            Result[QStringLiteral("size_of_image")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 56));
            Result[QStringLiteral("size_of_headers")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 60));
            Result[QStringLiteral("checksum")] = static_cast<int>(*reinterpret_cast<uint32_t*>(Opt + 64));
            Result[QStringLiteral("number_of_sections")] = Pe.NumberOfSections;
            int DdOffset = Pe.Is64 ? 108 : 92;
            int NumDirs = *reinterpret_cast<uint32_t*>(Opt + DdOffset);
            Result[QStringLiteral("number_of_data_directories")] = NumDirs;
            return Result;
        });

    RegisterTool(QStringLiteral("find_constants"),
        QStringLiteral("Scan disassembly for interesting immediate values and constants."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Instructions to scan"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(500);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray Constants;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                for (uint8_t O = 0; O < X86->op_count; ++O) {
                    if (X86->operands[O].type != X86_OP_IMM) continue;
                    int64_t Val = X86->operands[O].imm;
                    if (Val == 0 || Val == 1 || Val == -1 || (Val > 0 && Val <= 0xFF)) continue;

                    QJsonObject C;
                    C[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    C[QStringLiteral("value_hex")] = QStringLiteral("0x") + QString::number(static_cast<uint64_t>(Val), 16).toUpper();
                    C[QStringLiteral("value_dec")] = static_cast<qint64>(Val);
                    C[QStringLiteral("instruction")] = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                    Constants.append(C);
                }
                if (Constants.size() >= 1000) break;
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("constants")] = Constants;
            Result[QStringLiteral("count")] = Constants.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_packing"),
        QStringLiteral("Check for packing indicators: section entropy, unusual names, small imports."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint8_t Header[4096];
            CoreRef->ReadMemory(Base, Header, sizeof(Header));

            QJsonArray Indicators;
            bool Packed = false;
            double MaxEnt = 0;

            for (int I = 0; I < Pe.NumberOfSections && Pe.SectionHeaderOffset + I * 40 + 40 <= sizeof(Header); ++I) {
                uint8_t* Sec = Header + Pe.SectionHeaderOffset + I * 40;
                char Name[9] = {};
                std::memcpy(Name, Sec, 8);
                uint32_t VSize = *reinterpret_cast<uint32_t*>(Sec + 8);
                uint32_t VAddr = *reinterpret_cast<uint32_t*>(Sec + 12);

                int SampleSize = std::min(static_cast<int>(VSize), 8192);
                QByteArray Sample(SampleSize, '\0');
                CoreRef->ReadMemory(Base + VAddr, Sample.data(), static_cast<size_t>(SampleSize));
                double Ent = CalculateEntropy(reinterpret_cast<const uint8_t*>(Sample.constData()), static_cast<size_t>(SampleSize));
                if (Ent > MaxEnt) MaxEnt = Ent;

                if (Ent > 7.0) {
                    Indicators.append(QStringLiteral("High entropy section: ") + QString::fromUtf8(Name) + QStringLiteral(" (") + QString::number(Ent, 'f', 2) + QStringLiteral(")"));
                    Packed = true;
                }

                QString SName = QString::fromUtf8(Name);
                if (SName.startsWith(QStringLiteral("UPX")) || SName == QStringLiteral(".vmp0") || SName == QStringLiteral(".themida") || SName == QStringLiteral(".aspack") || SName == QStringLiteral(".packed")) {
                    Indicators.append(QStringLiteral("Packer section name: ") + SName);
                    Packed = true;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("packed")] = Packed;
            Result[QStringLiteral("max_entropy")] = MaxEnt;
            Result[QStringLiteral("indicators")] = Indicators;
            return Result;
        });

    RegisterTool(QStringLiteral("get_entropy"),
        QStringLiteral("Calculate Shannon entropy of a memory region (0-8 scale)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            double Ent = CalculateEntropy(reinterpret_cast<const uint8_t*>(Buf.constData()), static_cast<size_t>(Size));

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("entropy")] = Ent;
            Result[QStringLiteral("assessment")] = Ent > 7.5 ? QStringLiteral("encrypted/compressed") : Ent > 6.0 ? QStringLiteral("likely compressed") : Ent > 4.0 ? QStringLiteral("normal code/data") : Ent > 1.0 ? QStringLiteral("low entropy data") : QStringLiteral("near-zero entropy");
            return Result;
        });

    RegisterTool(QStringLiteral("find_code_caves"),
        QStringLiteral("Find regions of consecutive zero or INT3 (0xCC) bytes in code sections."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)},
            {QStringLiteral("min_size"), Schema::Integer(QStringLiteral("Minimum cave size"), 1, 65536)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            int MinCave = A.value(QStringLiteral("min_size")).toInt(16);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QJsonArray Caves;
            int RunStart = -1;
            uint8_t RunByte = 0;

            for (int I = 0; I <= Size; ++I) {
                uint8_t B = (I < Size) ? static_cast<uint8_t>(Buf[I]) : 0xFF;
                if (B == 0x00 || B == 0xCC) {
                    if (RunStart < 0) { RunStart = I; RunByte = B; }
                    else if (B != RunByte) {
                        int RunLen = I - RunStart;
                        if (RunLen >= MinCave) {
                            QJsonObject Cave;
                            Cave[QStringLiteral("address")] = Schema::FormatAddress(Addr + RunStart);
                            Cave[QStringLiteral("size")] = RunLen;
                            Cave[QStringLiteral("fill_byte")] = RunByte == 0xCC ? QStringLiteral("CC (INT3)") : QStringLiteral("00 (NUL)");
                            Caves.append(Cave);
                        }
                        RunStart = I; RunByte = B;
                    }
                } else {
                    if (RunStart >= 0) {
                        int RunLen = I - RunStart;
                        if (RunLen >= MinCave) {
                            QJsonObject Cave;
                            Cave[QStringLiteral("address")] = Schema::FormatAddress(Addr + RunStart);
                            Cave[QStringLiteral("size")] = RunLen;
                            Cave[QStringLiteral("fill_byte")] = RunByte == 0xCC ? QStringLiteral("CC (INT3)") : QStringLiteral("00 (NUL)");
                            Caves.append(Cave);
                        }
                        RunStart = -1;
                    }
                }
                if (Caves.size() >= 500) break;
            }

            QJsonObject Result;
            Result[QStringLiteral("caves")] = Caves;
            Result[QStringLiteral("count")] = Caves.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_relocations"),
        QStringLiteral("Parse the PE relocation directory."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int RelocDdIdx = 5;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t RelocRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + RelocDdIdx * 8);
            uint32_t RelocSize = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + RelocDdIdx * 8 + 4);

            if (RelocRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("relocations")] = QJsonArray();
                Result[QStringLiteral("count")] = 0;
                return Result;
            }

            QByteArray RelocBuf(static_cast<int>(RelocSize), '\0');
            if (!CoreRef->ReadMemory(Base + RelocRva, RelocBuf.data(), RelocSize))
                return Schema::Err(QStringLiteral("Failed to read relocation data"));

            QJsonArray Relocs;
            int Off = 0;
            while (Off + 8 <= static_cast<int>(RelocSize)) {
                uint32_t PageRva = *reinterpret_cast<const uint32_t*>(RelocBuf.constData() + Off);
                uint32_t BlockSize = *reinterpret_cast<const uint32_t*>(RelocBuf.constData() + Off + 4);
                if (BlockSize < 8 || BlockSize > RelocSize) break;

                int NumEntries = (static_cast<int>(BlockSize) - 8) / 2;
                for (int I = 0; I < NumEntries; ++I) {
                    uint16_t Entry = *reinterpret_cast<const uint16_t*>(RelocBuf.constData() + Off + 8 + I * 2);
                    int Type = Entry >> 12;
                    int EntryOffset = Entry & 0xFFF;
                    if (Type == 0) continue;

                    QJsonObject R;
                    R[QStringLiteral("address")] = Schema::FormatAddress(Base + PageRva + EntryOffset);
                    R[QStringLiteral("type")] = Type;
                    Relocs.append(R);
                    if (Relocs.size() >= 5000) break;
                }
                Off += static_cast<int>(BlockSize);
                if (Relocs.size() >= 5000) break;
            }

            QJsonObject Result;
            Result[QStringLiteral("relocations")] = Relocs;
            Result[QStringLiteral("count")] = Relocs.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_tls_callbacks"),
        QStringLiteral("Parse the TLS directory for callback function addresses."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int TlsDdIdx = 9;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t TlsRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + TlsDdIdx * 8);

            if (TlsRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("callbacks")] = QJsonArray();
                Result[QStringLiteral("count")] = 0;
                return Result;
            }

            uint8_t TlsDir[48];
            if (!CoreRef->ReadMemory(Base + TlsRva, TlsDir, sizeof(TlsDir)))
                return Schema::Err(QStringLiteral("Failed to read TLS directory"));

            Address CallbacksAddr = Pe.Is64 ? *reinterpret_cast<uint64_t*>(TlsDir + 24) : *reinterpret_cast<uint32_t*>(TlsDir + 12);

            QJsonArray Callbacks;
            if (CallbacksAddr != 0) {
                int PtrSize = Pe.Is64 ? 8 : 4;
                for (int I = 0; I < 64; ++I) {
                    uint64_t Cb = 0;
                    if (!CoreRef->ReadMemory(CallbacksAddr + I * PtrSize, &Cb, PtrSize)) break;
                    if (Cb == 0) break;
                    Callbacks.append(Schema::FormatAddress(Cb));
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("tls_directory")] = Schema::FormatAddress(Base + TlsRva);
            Result[QStringLiteral("callbacks")] = Callbacks;
            Result[QStringLiteral("count")] = Callbacks.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_debug_directory"),
        QStringLiteral("Parse the PE debug directory."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int DbgDdIdx = 6;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t DbgRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + DbgDdIdx * 8);
            uint32_t DbgSize = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + DbgDdIdx * 8 + 4);

            if (DbgRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("entries")] = QJsonArray();
                return Result;
            }

            int NumEntries = static_cast<int>(DbgSize) / 28;
            QJsonArray Entries;

            for (int I = 0; I < NumEntries && I < 16; ++I) {
                uint8_t DbgEntry[28];
                if (!CoreRef->ReadMemory(Base + DbgRva + I * 28, DbgEntry, 28)) break;

                uint32_t Type = *reinterpret_cast<uint32_t*>(DbgEntry + 12);
                uint32_t DataSize = *reinterpret_cast<uint32_t*>(DbgEntry + 16);
                uint32_t DataRva = *reinterpret_cast<uint32_t*>(DbgEntry + 24);

                QJsonObject Entry;
                QString TypeStr;
                switch (Type) {
                case 1: TypeStr = QStringLiteral("COFF"); break;
                case 2: TypeStr = QStringLiteral("CodeView"); break;
                case 4: TypeStr = QStringLiteral("Misc"); break;
                case 9: TypeStr = QStringLiteral("Borland"); break;
                case 13: TypeStr = QStringLiteral("POGO"); break;
                case 14: TypeStr = QStringLiteral("ILTCG"); break;
                case 16: TypeStr = QStringLiteral("Repro"); break;
                default: TypeStr = QStringLiteral("Unknown(") + QString::number(Type) + QStringLiteral(")"); break;
                }
                Entry[QStringLiteral("type")] = TypeStr;
                Entry[QStringLiteral("size")] = static_cast<int>(DataSize);
                Entry[QStringLiteral("rva")] = Schema::FormatAddress(DataRva);

                if (Type == 2 && DataRva != 0 && DataSize > 24) {
                    uint8_t CvData[512];
                    int ReadLen = std::min(static_cast<int>(DataSize), 512);
                    if (CoreRef->ReadMemory(Base + DataRva, CvData, static_cast<size_t>(ReadLen))) {
                        uint32_t CvSig = *reinterpret_cast<uint32_t*>(CvData);
                        if (CvSig == 0x53445352) {
                            Entry[QStringLiteral("pdb_path")] = QString::fromUtf8(reinterpret_cast<char*>(CvData + 24), ReadLen - 24).section('\0', 0, 0);
                        }
                    }
                }

                Entries.append(Entry);
            }

            QJsonObject Result;
            Result[QStringLiteral("entries")] = Entries;
            Result[QStringLiteral("count")] = Entries.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_exception_handlers"),
        QStringLiteral("Parse .pdata section for exception handler entries (x64)."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int ExcDdIdx = 3;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t ExcRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + ExcDdIdx * 8);
            uint32_t ExcSize = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + ExcDdIdx * 8 + 4);

            if (ExcRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("handlers")] = QJsonArray();
                Result[QStringLiteral("count")] = 0;
                return Result;
            }

            int NumEntries = static_cast<int>(ExcSize) / 12;
            int MaxShow = std::min(NumEntries, 1000);

            QByteArray ExcBuf(MaxShow * 12, '\0');
            if (!CoreRef->ReadMemory(Base + ExcRva, ExcBuf.data(), static_cast<size_t>(MaxShow * 12)))
                return Schema::Err(QStringLiteral("Failed to read exception data"));

            QJsonArray Handlers;
            for (int I = 0; I < MaxShow; ++I) {
                const uint8_t* E = reinterpret_cast<const uint8_t*>(ExcBuf.constData()) + I * 12;
                uint32_t BeginRva = *reinterpret_cast<const uint32_t*>(E);
                uint32_t EndRva = *reinterpret_cast<const uint32_t*>(E + 4);
                uint32_t UnwindRva = *reinterpret_cast<const uint32_t*>(E + 8);

                QJsonObject H;
                H[QStringLiteral("begin")] = Schema::FormatAddress(Base + BeginRva);
                H[QStringLiteral("end")] = Schema::FormatAddress(Base + EndRva);
                H[QStringLiteral("unwind_info")] = Schema::FormatAddress(Base + UnwindRva);
                H[QStringLiteral("size")] = static_cast<int>(EndRva - BeginRva);
                Handlers.append(H);
            }

            QJsonObject Result;
            Result[QStringLiteral("total_entries")] = NumEntries;
            Result[QStringLiteral("handlers")] = Handlers;
            Result[QStringLiteral("count")] = Handlers.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_rich_header"),
        QStringLiteral("Parse and decode the Rich header from a PE file."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            uint32_t PeOff = *reinterpret_cast<uint32_t*>(Header + 0x3C);
            int RichEnd = -1;
            for (uint32_t I = 0x40; I + 4 <= PeOff && I + 4 < sizeof(Header); I += 4) {
                if (*reinterpret_cast<uint32_t*>(Header + I) == 0x68636952) {
                    RichEnd = static_cast<int>(I);
                    break;
                }
            }

            if (RichEnd < 0) return Schema::Err(QStringLiteral("No Rich header found"));

            uint32_t Key = *reinterpret_cast<uint32_t*>(Header + RichEnd + 4);

            int RichStart = -1;
            for (int I = RichEnd - 4; I >= 0x40; I -= 4) {
                uint32_t Decoded = *reinterpret_cast<uint32_t*>(Header + I) ^ Key;
                if (Decoded == 0x536E6144) {
                    RichStart = I + 16;
                    break;
                }
            }

            if (RichStart < 0) return Schema::Err(QStringLiteral("Malformed Rich header"));

            QJsonArray Entries;
            for (int I = RichStart; I + 8 <= RichEnd; I += 8) {
                uint32_t CompId = *reinterpret_cast<uint32_t*>(Header + I) ^ Key;
                uint32_t Count = *reinterpret_cast<uint32_t*>(Header + I + 4) ^ Key;

                uint16_t ProdId = static_cast<uint16_t>(CompId >> 16);
                uint16_t BuildId = static_cast<uint16_t>(CompId & 0xFFFF);

                QJsonObject Entry;
                Entry[QStringLiteral("product_id")] = ProdId;
                Entry[QStringLiteral("build_id")] = BuildId;
                Entry[QStringLiteral("count")] = static_cast<int>(Count);
                Entries.append(Entry);
            }

            QJsonObject Result;
            Result[QStringLiteral("key")] = Schema::FormatAddress(Key);
            Result[QStringLiteral("entries")] = Entries;
            Result[QStringLiteral("count")] = Entries.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_overlay"),
        QStringLiteral("Check if PE has overlay data beyond the last section."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint8_t Header[4096];
            CoreRef->ReadMemory(Base, Header, sizeof(Header));

            uint32_t MaxFileOffset = 0;
            for (int I = 0; I < Pe.NumberOfSections && Pe.SectionHeaderOffset + I * 40 + 40 <= sizeof(Header); ++I) {
                uint8_t* Sec = Header + Pe.SectionHeaderOffset + I * 40;
                uint32_t RawOff = *reinterpret_cast<uint32_t*>(Sec + 20);
                uint32_t RawSize = *reinterpret_cast<uint32_t*>(Sec + 16);
                uint32_t EndOff = RawOff + RawSize;
                if (EndOff > MaxFileOffset) MaxFileOffset = EndOff;
            }

            QJsonObject Result;
            Result[QStringLiteral("last_section_end")] = static_cast<int>(MaxFileOffset);
            Result[QStringLiteral("note")] = QStringLiteral("Overlay detection is file-based; in memory, overlay data is not mapped. Check file on disk for actual overlay.");
            return Result;
        });

    RegisterTool(QStringLiteral("find_resources"),
        QStringLiteral("List PE resource entries from the resource directory."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int RsrcDdIdx = 2;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t RsrcRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + RsrcDdIdx * 8);

            if (RsrcRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("resources")] = QJsonArray();
                Result[QStringLiteral("count")] = 0;
                return Result;
            }

            uint8_t RsrcDir[4096];
            if (!CoreRef->ReadMemory(Base + RsrcRva, RsrcDir, sizeof(RsrcDir)))
                return Schema::Err(QStringLiteral("Failed to read resource directory"));

            uint16_t NamedEntries = *reinterpret_cast<uint16_t*>(RsrcDir + 12);
            uint16_t IdEntries = *reinterpret_cast<uint16_t*>(RsrcDir + 14);
            int TotalEntries = NamedEntries + IdEntries;

            QMap<int, QString> TypeNames = {
                {1, QStringLiteral("Cursor")}, {2, QStringLiteral("Bitmap")}, {3, QStringLiteral("Icon")},
                {4, QStringLiteral("Menu")}, {5, QStringLiteral("Dialog")}, {6, QStringLiteral("String")},
                {7, QStringLiteral("FontDir")}, {8, QStringLiteral("Font")}, {9, QStringLiteral("Accelerator")},
                {10, QStringLiteral("RCData")}, {11, QStringLiteral("MessageTable")}, {12, QStringLiteral("GroupCursor")},
                {14, QStringLiteral("GroupIcon")}, {16, QStringLiteral("Version")}, {24, QStringLiteral("Manifest")}
            };

            QJsonArray Resources;
            for (int I = 0; I < TotalEntries && I < 50; ++I) {
                uint8_t* Entry = RsrcDir + 16 + I * 8;
                uint32_t NameOrId = *reinterpret_cast<uint32_t*>(Entry);
                uint32_t OffsetOrDir = *reinterpret_cast<uint32_t*>(Entry + 4);

                QJsonObject Res;
                int TypeId = static_cast<int>(NameOrId);
                Res[QStringLiteral("type_id")] = TypeId;
                Res[QStringLiteral("type_name")] = TypeNames.value(TypeId, QStringLiteral("Unknown"));
                Res[QStringLiteral("is_directory")] = (OffsetOrDir & 0x80000000) != 0;
                Resources.append(Res);
            }

            QJsonObject Result;
            Result[QStringLiteral("resources")] = Resources;
            Result[QStringLiteral("count")] = Resources.size();
            return Result;
        });

    RegisterTool(QStringLiteral("extract_resource"),
        QStringLiteral("Read raw data from a specific PE resource."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))},
            {QStringLiteral("type_id"), Schema::Integer(QStringLiteral("Resource type ID"), 1, 255)},
            {QStringLiteral("max_size"), Schema::Integer(QStringLiteral("Max bytes to read"), 1, 1048576)}
        }, {QStringLiteral("type_id")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(A);
            return Schema::Err(QStringLiteral("Resource extraction requires walking the 3-level resource tree; use find_resources to list available types"));
        });

    RegisterTool(QStringLiteral("get_certificates"),
        QStringLiteral("Parse the PE certificate/security directory."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int CertDdIdx = 4;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t CertFileOff = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + CertDdIdx * 8);
            uint32_t CertSize = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + CertDdIdx * 8 + 4);

            QJsonObject Result;
            Result[QStringLiteral("has_certificate")] = (CertFileOff != 0 && CertSize != 0);
            Result[QStringLiteral("certificate_offset")] = static_cast<int>(CertFileOff);
            Result[QStringLiteral("certificate_size")] = static_cast<int>(CertSize);
            Result[QStringLiteral("note")] = QStringLiteral("Certificate data is file-offset based and may not be memory-mapped. Check the file on disk for full certificate parsing.");
            return Result;
        });

    RegisterTool(QStringLiteral("find_delay_imports"),
        QStringLiteral("Parse the delay import directory of a PE."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int DelayDdIdx = 13;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t DelayRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + DelayDdIdx * 8);

            if (DelayRva == 0) {
                QJsonObject Result;
                Result[QStringLiteral("delay_imports")] = QJsonArray();
                Result[QStringLiteral("count")] = 0;
                return Result;
            }

            QJsonArray Imports;
            for (int I = 0; I < 64; ++I) {
                uint8_t Desc[32];
                if (!CoreRef->ReadMemory(Base + DelayRva + I * 32, Desc, 32)) break;

                uint32_t NameRva = *reinterpret_cast<uint32_t*>(Desc + 4);
                if (NameRva == 0) break;

                char DllName[256] = {};
                CoreRef->ReadMemory(Base + NameRva, DllName, sizeof(DllName) - 1);

                QJsonObject Entry;
                Entry[QStringLiteral("dll")] = QString::fromUtf8(DllName);
                Imports.append(Entry);
            }

            QJsonObject Result;
            Result[QStringLiteral("delay_imports")] = Imports;
            Result[QStringLiteral("count")] = Imports.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_bound_imports"),
        QStringLiteral("Parse the bound import directory of a PE."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            int DdOffset = Pe.Is64 ? 108 : 92;
            int BoundDdIdx = 11;
            uint8_t* Opt = Header + Pe.OptionalHeaderOffset;
            uint32_t BoundRva = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + BoundDdIdx * 8);
            uint32_t BoundSize = *reinterpret_cast<uint32_t*>(Opt + DdOffset + 4 + BoundDdIdx * 8 + 4);

            QJsonObject Result;
            Result[QStringLiteral("has_bound_imports")] = (BoundRva != 0 && BoundSize != 0);
            Result[QStringLiteral("rva")] = Schema::FormatAddress(BoundRva);
            Result[QStringLiteral("size")] = static_cast<int>(BoundSize);
            return Result;
        });

    RegisterTool(QStringLiteral("analyze_control_flow"),
        QStringLiteral("Analyze control flow patterns in disassembled code."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Instructions"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(200);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            int DirectCalls = 0, IndirectCalls = 0, ConditionalJumps = 0, UnconditionalJumps = 0, Returns = 0;

            for (size_t I = 0; I < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                if (Mnem == QStringLiteral("call")) {
                    if (Insns[I].detail && Insns[I].detail->x86.operands[0].type == X86_OP_IMM) DirectCalls++;
                    else IndirectCalls++;
                } else if (Mnem == QStringLiteral("jmp")) {
                    UnconditionalJumps++;
                } else if (Mnem.startsWith(QStringLiteral("j")) && Mnem != QStringLiteral("jmp")) {
                    ConditionalJumps++;
                } else if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) {
                    Returns++;
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("instruction_count")] = static_cast<int>(Cnt);
            Result[QStringLiteral("direct_calls")] = DirectCalls;
            Result[QStringLiteral("indirect_calls")] = IndirectCalls;
            Result[QStringLiteral("conditional_jumps")] = ConditionalJumps;
            Result[QStringLiteral("unconditional_jumps")] = UnconditionalJumps;
            Result[QStringLiteral("returns")] = Returns;
            double Complexity = static_cast<double>(ConditionalJumps + IndirectCalls) / std::max(1.0, static_cast<double>(Cnt)) * 100.0;
            Result[QStringLiteral("complexity_ratio")] = Complexity;
            return Result;
        });

    RegisterTool(QStringLiteral("find_dead_code"),
        QStringLiteral("Find unreachable code after unconditional jumps or returns."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Instructions"), 1, 5000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(500);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray DeadCode;
            for (size_t I = 0; I + 1 < Cnt; ++I) {
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);
                if (Mnem == QStringLiteral("jmp") || Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) {
                    QString NextMnem = QString::fromUtf8(Insns[I + 1].mnemonic);
                    if (NextMnem != QStringLiteral("nop") && NextMnem != QStringLiteral("int3") && NextMnem != QStringLiteral("cc")) {
                        QJsonObject D;
                        D[QStringLiteral("after")] = Schema::FormatAddress(Insns[I].address);
                        D[QStringLiteral("dead_start")] = Schema::FormatAddress(Insns[I + 1].address);
                        D[QStringLiteral("dead_instruction")] = NextMnem + QStringLiteral(" ") + QString::fromUtf8(Insns[I + 1].op_str);
                        DeadCode.append(D);
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("dead_code")] = DeadCode;
            Result[QStringLiteral("count")] = DeadCode.size();
            return Result;
        });

    RegisterTool(QStringLiteral("detect_api_hashing"),
        QStringLiteral("Scan for API hashing patterns: ROR/ROL + ADD/XOR loops typical of shellcode."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 1048576)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            QJsonArray Patterns;
            for (size_t I = 0; I + 2 < Cnt; ++I) {
                QString M1 = QString::fromUtf8(Insns[I].mnemonic);
                QString M2 = QString::fromUtf8(Insns[I + 1].mnemonic);

                bool HasRotate = (M1 == QStringLiteral("ror") || M1 == QStringLiteral("rol"));
                bool HasAdd = (M2 == QStringLiteral("add") || M2 == QStringLiteral("xor"));

                if (HasRotate && HasAdd) {
                    QJsonObject P;
                    P[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                    P[QStringLiteral("pattern")] = M1 + QStringLiteral(" + ") + M2;
                    P[QStringLiteral("detail")] = M1 + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str) + QStringLiteral("; ") + M2 + QStringLiteral(" ") + QString::fromUtf8(Insns[I + 1].op_str);
                    Patterns.append(P);
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("api_hash_patterns")] = Patterns;
            Result[QStringLiteral("count")] = Patterns.size();
            return Result;
        });

    RegisterTool(QStringLiteral("resolve_api_hash"),
        QStringLiteral("Resolve an API hash to a function name using known hash databases."),
        Schema::Build({
            {QStringLiteral("hash"), Schema::String(QStringLiteral("Hash value in hex"))},
            {QStringLiteral("algorithm"), Schema::StringEnum(QStringLiteral("Hashing algorithm"), {QStringLiteral("ror13"), QStringLiteral("djb2"), QStringLiteral("crc32")})}
        }, {QStringLiteral("hash")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Q_UNUSED(this);
            uint32_t Hash = static_cast<uint32_t>(Schema::ParseHexAddress(A.value(QStringLiteral("hash")).toString()));
            QString Algorithm = A.value(QStringLiteral("algorithm")).toString(QStringLiteral("ror13"));

            QMap<uint32_t, QString> Ror13Db = {
                {0x726774C, QStringLiteral("LoadLibraryA")},
                {0xEC0E4E8E, QStringLiteral("LoadLibraryA")},
                {0x7C0DFCAA, QStringLiteral("GetProcAddress")},
                {0x0E8AFE98, QStringLiteral("WinExec")},
                {0x73E2D87E, QStringLiteral("ExitProcess")},
                {0xE553A458, QStringLiteral("VirtualAlloc")},
                {0x614D6E75, QStringLiteral("CreateFileA")},
                {0x56A2B5F0, QStringLiteral("ExitProcess")},
                {0x5FC8D902, QStringLiteral("CreateThread")},
                {0x160D6838, QStringLiteral("WSAStartup")},
                {0x6174A599, QStringLiteral("connect")},
                {0xE0DF0FEA, QStringLiteral("WSASocketA")},
                {0x6737DBC2, QStringLiteral("bind")},
                {0xFF38E9B7, QStringLiteral("listen")},
                {0xE13BEC74, QStringLiteral("accept")},
                {0x5BAE572D, QStringLiteral("recv")},
                {0x5F38EBC2, QStringLiteral("send")},
            };

            QJsonObject Result;
            Result[QStringLiteral("hash")] = Schema::FormatAddress(Hash);
            Result[QStringLiteral("algorithm")] = Algorithm;

            if (Algorithm == QStringLiteral("ror13") && Ror13Db.contains(Hash)) {
                Result[QStringLiteral("resolved")] = true;
                Result[QStringLiteral("function")] = Ror13Db[Hash];
            } else {
                Result[QStringLiteral("resolved")] = false;
                Result[QStringLiteral("note")] = QStringLiteral("Hash not found in built-in database");
            }
            return Result;
        });

    RegisterTool(QStringLiteral("find_syscalls"),
        QStringLiteral("Find direct syscall patterns (mov r10,rcx; mov eax,N; syscall)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            const uint8_t SyscallOp[] = {0x0F, 0x05};
            const uint8_t MovR10Rcx[] = {0x4C, 0x8B, 0xD1};

            QJsonArray Syscalls;
            const uint8_t* Data = reinterpret_cast<const uint8_t*>(Buf.constData());

            for (int I = 0; I + 2 <= Size; ++I) {
                if (Data[I] == SyscallOp[0] && Data[I+1] == SyscallOp[1]) {
                    QJsonObject Sc;
                    Sc[QStringLiteral("syscall_address")] = Schema::FormatAddress(Addr + I);

                    int LookBack = std::min(I, 32);
                    bool FoundSetup = false;
                    for (int J = I - 2; J >= I - LookBack; --J) {
                        if (J + 3 <= I && Data[J] == MovR10Rcx[0] && Data[J+1] == MovR10Rcx[1] && Data[J+2] == MovR10Rcx[2]) {
                            Sc[QStringLiteral("mov_r10_rcx")] = Schema::FormatAddress(Addr + J);
                            FoundSetup = true;
                        }
                        if (Data[J] == 0xB8 && J + 5 <= I) {
                            uint32_t SyscallNum = *reinterpret_cast<const uint32_t*>(Data + J + 1);
                            Sc[QStringLiteral("syscall_number")] = static_cast<int>(SyscallNum);
                            Sc[QStringLiteral("mov_eax_address")] = Schema::FormatAddress(Addr + J);
                            FoundSetup = true;
                            break;
                        }
                    }
                    Sc[QStringLiteral("has_setup")] = FoundSetup;
                    Syscalls.append(Sc);
                    if (Syscalls.size() >= 500) break;
                }
            }

            QJsonObject Result;
            Result[QStringLiteral("syscalls")] = Syscalls;
            Result[QStringLiteral("count")] = Syscalls.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_instruction_detail"),
        QStringLiteral("Get detailed information about a single instruction: operands, reads, writes, flags."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Instruction address in hex"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());

            uint8_t Buf[15];
            if (!CoreRef->ReadMemory(Addr, Buf, sizeof(Buf)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insn = nullptr;
            size_t Cnt = cs_disasm(Handle, Buf, sizeof(Buf), Addr, 1, &Insn);
            if (Cnt == 0) { cs_close(&Handle); return Schema::Err(QStringLiteral("Failed to disassemble")); }

            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Insn[0].address);
            Result[QStringLiteral("mnemonic")] = QString::fromUtf8(Insn[0].mnemonic);
            Result[QStringLiteral("operands_str")] = QString::fromUtf8(Insn[0].op_str);
            Result[QStringLiteral("size")] = static_cast<int>(Insn[0].size);
            QByteArray Bytes(reinterpret_cast<const char*>(Insn[0].bytes), static_cast<int>(Insn[0].size));
            Result[QStringLiteral("bytes")] = QString::fromLatin1(Bytes.toHex(' '));

            if (Insn[0].detail) {
                cs_x86* X86 = &Insn[0].detail->x86;
                QJsonArray Operands;
                for (uint8_t I = 0; I < X86->op_count; ++I) {
                    QJsonObject Op;
                    switch (X86->operands[I].type) {
                    case X86_OP_REG: Op[QStringLiteral("type")] = QStringLiteral("register"); Op[QStringLiteral("reg")] = QString::fromUtf8(cs_reg_name(Handle, X86->operands[I].reg)); break;
                    case X86_OP_IMM: Op[QStringLiteral("type")] = QStringLiteral("immediate"); Op[QStringLiteral("value")] = Schema::FormatAddress(static_cast<Address>(X86->operands[I].imm)); break;
                    case X86_OP_MEM: Op[QStringLiteral("type")] = QStringLiteral("memory"); Op[QStringLiteral("disp")] = static_cast<qint64>(X86->operands[I].mem.disp); break;
                    default: Op[QStringLiteral("type")] = QStringLiteral("unknown"); break;
                    }
                    Op[QStringLiteral("size")] = X86->operands[I].size;
                    Operands.append(Op);
                }
                Result[QStringLiteral("operands")] = Operands;

                QJsonArray RegsRead, RegsWrite;
                for (uint8_t I = 0; I < Insn[0].detail->regs_read_count; ++I)
                    RegsRead.append(QString::fromUtf8(cs_reg_name(Handle, Insn[0].detail->regs_read[I])));
                for (uint8_t I = 0; I < Insn[0].detail->regs_write_count; ++I)
                    RegsWrite.append(QString::fromUtf8(cs_reg_name(Handle, Insn[0].detail->regs_write[I])));
                Result[QStringLiteral("regs_read")] = RegsRead;
                Result[QStringLiteral("regs_write")] = RegsWrite;

                QJsonArray Groups;
                for (uint8_t I = 0; I < Insn[0].detail->groups_count; ++I)
                    Groups.append(QString::fromUtf8(cs_group_name(Handle, Insn[0].detail->groups[I])));
                Result[QStringLiteral("groups")] = Groups;
            }

            cs_free(Insn, Cnt);
            cs_close(&Handle);
            return Result;
        });

    RegisterTool(QStringLiteral("find_gadgets"),
        QStringLiteral("Find ROP gadgets: short instruction sequences ending in RET."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 16777216)},
            {QStringLiteral("max_insns"), Schema::Integer(QStringLiteral("Max instructions per gadget"), 1, 10)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(65536);
            int MaxGadgetInsns = A.value(QStringLiteral("max_insns")).toInt(5);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            const uint8_t* Data = reinterpret_cast<const uint8_t*>(Buf.constData());
            QJsonArray Gadgets;
            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            for (int I = 0; I < Size; ++I) {
                if (Data[I] != 0xC3 && Data[I] != 0xC2) continue;

                for (int Back = 1; Back <= MaxGadgetInsns * 15 && Back <= I; ++Back) {
                    cs_insn* Insns = nullptr;
                    size_t Cnt = cs_disasm(Handle, Data + I - Back, static_cast<size_t>(Back + 1),
                                           Addr + I - Back, 0, &Insns);

                    if (Cnt >= 2 && Cnt <= static_cast<size_t>(MaxGadgetInsns + 1)) {
                        Address LastAddr = Insns[Cnt - 1].address;
                        if (LastAddr == Addr + static_cast<Address>(I)) {
                            QString GadgetStr;
                            for (size_t J = 0; J < Cnt; ++J) {
                                if (J > 0) GadgetStr += QStringLiteral("; ");
                                GadgetStr += QString::fromUtf8(Insns[J].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[J].op_str);
                            }

                            QJsonObject G;
                            G[QStringLiteral("address")] = Schema::FormatAddress(Insns[0].address);
                            G[QStringLiteral("gadget")] = GadgetStr;
                            G[QStringLiteral("length")] = static_cast<int>(Cnt);
                            Gadgets.append(G);
                        }
                    }
                    if (Cnt > 0) cs_free(Insns, Cnt);
                }
                if (Gadgets.size() >= 2000) break;
            }

            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("gadgets")] = Gadgets;
            Result[QStringLiteral("count")] = Gadgets.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_jmp_chains"),
        QStringLiteral("Follow JMP instructions to find the final target address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("max_depth"), Schema::Integer(QStringLiteral("Max jumps to follow"), 1, 32)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxDepth = A.value(QStringLiteral("max_depth")).toInt(10);

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            QJsonArray Chain;
            Address Current = Addr;

            for (int Depth = 0; Depth < MaxDepth; ++Depth) {
                uint8_t Buf[15];
                if (!CoreRef->ReadMemory(Current, Buf, sizeof(Buf))) break;

                cs_insn* Insn = nullptr;
                size_t Cnt = cs_disasm(Handle, Buf, sizeof(Buf), Current, 1, &Insn);
                if (Cnt == 0) break;

                QJsonObject Step;
                Step[QStringLiteral("address")] = Schema::FormatAddress(Insn[0].address);
                Step[QStringLiteral("instruction")] = QString::fromUtf8(Insn[0].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insn[0].op_str);

                QString Mnem = QString::fromUtf8(Insn[0].mnemonic);
                if (Mnem != QStringLiteral("jmp")) {
                    Step[QStringLiteral("final")] = true;
                    Chain.append(Step);
                    cs_free(Insn, Cnt);
                    break;
                }

                if (Insn[0].detail && Insn[0].detail->x86.op_count > 0) {
                    if (Insn[0].detail->x86.operands[0].type == X86_OP_IMM) {
                        Current = static_cast<Address>(Insn[0].detail->x86.operands[0].imm);
                        Step[QStringLiteral("target")] = Schema::FormatAddress(Current);
                    } else if (Insn[0].detail->x86.operands[0].type == X86_OP_MEM && Insn[0].detail->x86.operands[0].mem.base == X86_REG_RIP) {
                        Address PtrAddr = Insn[0].address + Insn[0].size + Insn[0].detail->x86.operands[0].mem.disp;
                        uint64_t Target = 0;
                        if (CoreRef->ReadMemory(PtrAddr, &Target, 8)) {
                            Current = Target;
                            Step[QStringLiteral("target")] = Schema::FormatAddress(Current);
                            Step[QStringLiteral("indirect")] = true;
                        } else {
                            Chain.append(Step);
                            cs_free(Insn, Cnt);
                            break;
                        }
                    } else {
                        Step[QStringLiteral("indirect_unresolvable")] = true;
                        Chain.append(Step);
                        cs_free(Insn, Cnt);
                        break;
                    }
                }

                Chain.append(Step);
                cs_free(Insn, Cnt);
            }

            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("chain")] = Chain;
            Result[QStringLiteral("depth")] = Chain.size();
            if (!Chain.isEmpty()) {
                QJsonObject Last = Chain.last().toObject();
                if (Last.contains(QStringLiteral("target")))
                    Result[QStringLiteral("final_target")] = Last[QStringLiteral("target")];
                else
                    Result[QStringLiteral("final_target")] = Last[QStringLiteral("address")];
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_checksum"),
        QStringLiteral("Calculate the PE checksum for the module in memory."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            PeInfo Pe = ReadPeInfo(CoreRef, Base);
            if (!Pe.Valid) return Schema::Err(QStringLiteral("Invalid PE"));

            uint32_t StoredChecksum = *reinterpret_cast<uint32_t*>(Header + Pe.OptionalHeaderOffset + 64);
            uint32_t SizeOfImage = *reinterpret_cast<uint32_t*>(Header + Pe.OptionalHeaderOffset + 56);

            int CalcSize = std::min(static_cast<int>(SizeOfImage), 1048576);
            QByteArray ImgBuf(CalcSize, '\0');
            CoreRef->ReadMemory(Base, ImgBuf.data(), static_cast<size_t>(CalcSize));

            uint64_t Checksum = 0;
            uint32_t ChecksumOffset = Pe.OptionalHeaderOffset + 64;
            for (int I = 0; I + 2 <= CalcSize; I += 2) {
                if (I == static_cast<int>(ChecksumOffset) || I == static_cast<int>(ChecksumOffset + 2)) continue;
                Checksum += *reinterpret_cast<uint16_t*>(ImgBuf.data() + I);
                Checksum = (Checksum & 0xFFFF) + (Checksum >> 16);
            }
            Checksum = (Checksum & 0xFFFF) + (Checksum >> 16);
            Checksum += static_cast<uint64_t>(CalcSize);
            uint32_t Calculated = static_cast<uint32_t>(Checksum);

            QJsonObject Result;
            Result[QStringLiteral("stored_checksum")] = Schema::FormatAddress(StoredChecksum);
            Result[QStringLiteral("calculated_checksum")] = Schema::FormatAddress(Calculated);
            Result[QStringLiteral("valid")] = (StoredChecksum == 0 || StoredChecksum == Calculated);
            return Result;
        });

    RegisterTool(QStringLiteral("validate_pe"),
        QStringLiteral("Validate PE structure integrity: magic numbers, section alignment, header sizes."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (optional)"))}}, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = FindModuleBase(CoreRef, A.value(QStringLiteral("module")).toString());
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found"));

            uint8_t Header[4096];
            if (!CoreRef->ReadMemory(Base, Header, sizeof(Header)))
                return Schema::Err(QStringLiteral("Failed to read PE"));

            QJsonArray Issues;
            bool Valid = true;

            if (*reinterpret_cast<uint16_t*>(Header) != 0x5A4D) {
                Issues.append(QStringLiteral("Invalid DOS magic (expected MZ)"));
                Valid = false;
            }

            uint32_t PeOff = *reinterpret_cast<uint32_t*>(Header + 0x3C);
            if (PeOff >= sizeof(Header) - 4) {
                Issues.append(QStringLiteral("PE offset out of range"));
                QJsonObject R; R[QStringLiteral("valid")] = false; R[QStringLiteral("issues")] = Issues; return R;
            }

            if (*reinterpret_cast<uint32_t*>(Header + PeOff) != 0x00004550) {
                Issues.append(QStringLiteral("Invalid PE signature"));
                Valid = false;
            }

            uint16_t Machine = *reinterpret_cast<uint16_t*>(Header + PeOff + 4);
            if (Machine != 0x8664 && Machine != 0x014C && Machine != 0xAA64) {
                Issues.append(QStringLiteral("Unusual machine type: 0x") + QString::number(Machine, 16));
            }

            uint16_t NumSections = *reinterpret_cast<uint16_t*>(Header + PeOff + 6);
            if (NumSections == 0 || NumSections > 96) {
                Issues.append(QStringLiteral("Unusual number of sections: ") + QString::number(NumSections));
            }

            uint16_t OptMagic = *reinterpret_cast<uint16_t*>(Header + PeOff + 24);
            if (OptMagic != 0x010B && OptMagic != 0x020B) {
                Issues.append(QStringLiteral("Invalid optional header magic: 0x") + QString::number(OptMagic, 16));
                Valid = false;
            }

            if (Issues.isEmpty()) Issues.append(QStringLiteral("PE structure is valid"));

            QJsonObject Result;
            Result[QStringLiteral("valid")] = Valid;
            Result[QStringLiteral("issues")] = Issues;
            return Result;
        });

    RegisterTool(QStringLiteral("find_mutations"),
        QStringLiteral("Find potential self-modifying code patterns (writes to executable memory)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Region size"), 1, 1048576)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);

            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   static_cast<size_t>(Size), Addr, 0, &Insns);

            QJsonArray Mutations;
            for (size_t I = 0; I < Cnt; ++I) {
                if (!Insns[I].detail) continue;
                cs_x86* X86 = &Insns[I].detail->x86;
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic);

                if ((Mnem == QStringLiteral("mov") || Mnem == QStringLiteral("stosb") || Mnem == QStringLiteral("stosd")) && X86->op_count >= 1) {
                    if (X86->operands[0].type == X86_OP_MEM && X86->operands[0].mem.base == X86_REG_RIP) {
                        Address Target = Insns[I].address + Insns[I].size + X86->operands[0].mem.disp;
                        if (Target >= Addr && Target < Addr + static_cast<Address>(Size)) {
                            QJsonObject M;
                            M[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                            M[QStringLiteral("write_target")] = Schema::FormatAddress(Target);
                            M[QStringLiteral("instruction")] = Mnem + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                            Mutations.append(M);
                        }
                    }
                }
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("mutations")] = Mutations;
            Result[QStringLiteral("count")] = Mutations.size();
            return Result;
        });

    RegisterTool(QStringLiteral("get_disassembly"),
        QStringLiteral("Extended disassembly with annotations: resolved call targets, string references, function names."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of instructions"), 1, 1000)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Count = A.value(QStringLiteral("count")).toInt(50);

            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buf(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), ReadSize))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (!InitCapstone(Handle)) return Schema::Err(QStringLiteral("Capstone init failed"));

            cs_insn* Insns = nullptr;
            size_t Cnt = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buf.constData()),
                                   ReadSize, Addr, static_cast<size_t>(Count), &Insns);

            QJsonArray Lines;
            for (size_t I = 0; I < Cnt; ++I) {
                QJsonObject Line;
                Line[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                QByteArray Bytes(reinterpret_cast<const char*>(Insns[I].bytes), static_cast<int>(Insns[I].size));
                Line[QStringLiteral("bytes")] = QString::fromLatin1(Bytes.toHex(' '));
                Line[QStringLiteral("mnemonic")] = QString::fromUtf8(Insns[I].mnemonic);
                Line[QStringLiteral("operands")] = QString::fromUtf8(Insns[I].op_str);

                if (FunctionNames.contains(Insns[I].address))
                    Line[QStringLiteral("label")] = FunctionNames[Insns[I].address];
                if (VariableNames.contains(Insns[I].address))
                    Line[QStringLiteral("var_name")] = VariableNames[Insns[I].address];

                if (Insns[I].detail) {
                    cs_x86* X86 = &Insns[I].detail->x86;
                    QString Mnem = QString::fromUtf8(Insns[I].mnemonic);

                    if (Mnem == QStringLiteral("call") && X86->op_count > 0 && X86->operands[0].type == X86_OP_IMM) {
                        Address Target = static_cast<Address>(X86->operands[0].imm);
                        if (FunctionNames.contains(Target))
                            Line[QStringLiteral("call_target_name")] = FunctionNames[Target];
                    }

                    for (uint8_t O = 0; O < X86->op_count; ++O) {
                        if (X86->operands[O].type == X86_OP_MEM && X86->operands[O].mem.base == X86_REG_RIP) {
                            Address DataAddr = Insns[I].address + Insns[I].size + X86->operands[O].mem.disp;
                            Line[QStringLiteral("data_ref")] = Schema::FormatAddress(DataAddr);

                            char StrTest[64] = {};
                            if (CoreRef->ReadMemory(DataAddr, StrTest, sizeof(StrTest) - 1)) {
                                int Len = 0;
                                bool IsPrintable = true;
                                for (int S = 0; S < 63 && StrTest[S]; ++S) {
                                    if (StrTest[S] < 0x20 || StrTest[S] > 0x7E) { IsPrintable = false; break; }
                                    Len++;
                                }
                                if (IsPrintable && Len >= 4)
                                    Line[QStringLiteral("string_ref")] = QString::fromUtf8(StrTest, Len);
                            }
                        }
                    }
                }

                Lines.append(Line);
            }

            if (Cnt > 0) cs_free(Insns, Cnt);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("instructions")] = Lines;
            Result[QStringLiteral("count")] = Lines.size();
            return Result;
        });
}

}
