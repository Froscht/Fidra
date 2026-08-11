#include "PatchEngine.h"
#include "../analysis/AnalysisDatabase.h"
#include "../analysis/AnalysisTypes.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace Fidra {

PatchEngine::PatchEngine(QObject* Parent)
    : QObject(Parent)
{
    RegisterMap64 = {
        {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
        {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
        {"r8",  8}, {"r9",  9}, {"r10", 10}, {"r11", 11},
        {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}
    };

    RegisterMap32 = {
        {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3},
        {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
        {"r8d",  8}, {"r9d",  9}, {"r10d", 10}, {"r11d", 11},
        {"r12d", 12}, {"r13d", 13}, {"r14d", 14}, {"r15d", 15}
    };

    RegisterMap8 = {
        {"al", 0}, {"cl", 1}, {"dl", 2}, {"bl", 3},
        {"spl", 4}, {"bpl", 5}, {"sil", 6}, {"dil", 7},
        {"r8b",  8}, {"r9b",  9}, {"r10b", 10}, {"r11b", 11},
        {"r12b", 12}, {"r13b", 13}, {"r14b", 14}, {"r15b", 15}
    };
}

PatchEngine::~PatchEngine() = default;

bool PatchEngine::PatchBytes(AnalysisDatabase* Db, Address Addr, const QByteArray& NewBytes, const QString& Desc) {
    if (!Db || NewBytes.isEmpty()) return false;

    QByteArray OrigBytes = Db->ReadBytes(Addr, static_cast<size_t>(NewBytes.size()));
    if (OrigBytes.isEmpty()) return false;

    PatchEntry Entry;
    Entry.Addr = Addr;
    Entry.OriginalBytes = OrigBytes;
    Entry.PatchedBytes = NewBytes;
    Entry.Description = Desc.isEmpty() ? QString("Patch at 0x%1").arg(Addr, 16, 16, QChar('0')).toUpper() : Desc;
    Entry.IsApplied = false;
    Entry.Timestamp = QDateTime::currentDateTime();

    if (!WriteToSegment(Db, Addr, NewBytes)) return false;

    Entry.IsApplied = true;
    Patches.append(Entry);
    emit PatchApplied(Addr, Entry.Description);
    return true;
}

bool PatchEngine::NopOut(AnalysisDatabase* Db, Address Addr, int Size) {
    if (!Db || Size <= 0) return false;
    QByteArray Nops(Size, static_cast<char>(0x90));
    return PatchBytes(Db, Addr, Nops, QString("NOP %1 bytes at 0x%2").arg(Size).arg(Addr, 16, 16, QChar('0')).toUpper());
}

bool PatchEngine::NopFunction(AnalysisDatabase* Db, Address FuncAddr) {
    if (!Db) return false;

    AnalyzedFunction Func = Db->GetFunction(FuncAddr);
    if (Func.Size == 0) {
        Func = Db->GetFunctionContaining(FuncAddr);
    }
    if (Func.Size == 0) return false;

    int FuncSize = static_cast<int>(Func.Size);
    QByteArray Nops(FuncSize, static_cast<char>(0x90));

    Nops[0] = static_cast<char>(0xC3);

    return PatchBytes(Db, Func.Start, Nops,
        QString("NOP function %1 at 0x%2 (%3 bytes)")
            .arg(Func.Name.isEmpty() ? "unknown" : Func.Name)
            .arg(Func.Start, 16, 16, QChar('0')).toUpper()
            .arg(FuncSize));
}

bool PatchEngine::RevertPatch(int PatchIndex) {
    if (PatchIndex < 0 || PatchIndex >= Patches.size()) return false;

    PatchEntry& Entry = Patches[PatchIndex];
    if (!Entry.IsApplied) return true;

    Entry.IsApplied = false;
    emit PatchReverted(PatchIndex);
    return true;
}

bool PatchEngine::RevertAll() {
    bool AllOk = true;
    for (int I = Patches.size() - 1; I >= 0; --I) {
        if (Patches[I].IsApplied) {
            if (!RevertPatch(I)) {
                AllOk = false;
            }
        }
    }
    return AllOk;
}

bool PatchEngine::WriteToSegment(AnalysisDatabase* Db, Address Addr, const QByteArray& Bytes) {
    BinaryInfo Info = Db->GetBinaryInfo();

    for (int I = 0; I < Info.Segments.size(); ++I) {
        Segment& Seg = Info.Segments[I];
        if (Addr >= Seg.VirtualAddress && Addr + static_cast<Address>(Bytes.size()) <= Seg.VirtualAddress + Seg.VirtualSize) {
            size_t Offset = static_cast<size_t>(Addr - Seg.VirtualAddress);

            if (static_cast<int>(Offset + static_cast<size_t>(Bytes.size())) > Seg.Data.size()) {
                Seg.Data.resize(static_cast<int>(Offset + static_cast<size_t>(Bytes.size())));
            }

            memcpy(Seg.Data.data() + Offset, Bytes.constData(), static_cast<size_t>(Bytes.size()));
            Db->SetBinaryInfo(Info);
            return true;
        }
    }
    return false;
}

bool PatchEngine::Assemble(const QString& Assembly, Address Addr, QByteArray& OutBytes, QString& OutError) {
    OutBytes.clear();
    OutError.clear();

    QStringList Lines = Assembly.split('\n', Qt::SkipEmptyParts);
    Address CurrentAddr = Addr;

    for (const QString& RawLine : Lines) {
        QString Line = RawLine.trimmed();
        if (Line.isEmpty()) continue;

        if (Line.endsWith(':')) continue;

        QByteArray LineBytes;
        QString LineError;

        if (!AssembleLine(Line, CurrentAddr, LineBytes, LineError)) {
            OutError = QString("Line '%1': %2").arg(Line, LineError);
            OutBytes.clear();
            return false;
        }

        OutBytes.append(LineBytes);
        CurrentAddr += static_cast<Address>(LineBytes.size());
    }

    if (OutBytes.isEmpty()) {
        OutError = "No instructions assembled";
        return false;
    }

    return true;
}

bool PatchEngine::AssembleLine(const QString& Line, Address Addr, QByteArray& OutBytes, QString& OutError) {
    QString Normalized = Line.toLower().trimmed();

    if (Normalized.contains(';')) {
        Normalized = Normalized.left(Normalized.indexOf(';')).trimmed();
    }

    if (Normalized == "nop") {
        OutBytes.append(static_cast<char>(0x90));
        return true;
    }

    if (Normalized == "ret") {
        OutBytes.append(static_cast<char>(0xC3));
        return true;
    }

    if (Normalized == "int3") {
        OutBytes.append(static_cast<char>(0xCC));
        return true;
    }

    if (Normalized == "leave") {
        OutBytes.append(static_cast<char>(0xC9));
        return true;
    }

    if (Normalized == "nop; ret" || Normalized == "retn") {
        OutBytes.append(static_cast<char>(0xC3));
        return true;
    }

    if (Normalized == "cld") {
        OutBytes.append(static_cast<char>(0xFC));
        return true;
    }

    if (Normalized == "std") {
        OutBytes.append(static_cast<char>(0xFD));
        return true;
    }

    if (Normalized == "cli") {
        OutBytes.append(static_cast<char>(0xFA));
        return true;
    }

    if (Normalized == "sti") {
        OutBytes.append(static_cast<char>(0xFB));
        return true;
    }

    if (Normalized == "syscall") {
        OutBytes.append(static_cast<char>(0x0F));
        OutBytes.append(static_cast<char>(0x05));
        return true;
    }

    if (Normalized == "cdq") {
        OutBytes.append(static_cast<char>(0x99));
        return true;
    }

    if (Normalized == "cqo") {
        OutBytes.append(RexByte(true, false, false, false));
        OutBytes.append(static_cast<char>(0x99));
        return true;
    }

    QStringList Parts = Normalized.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (Parts.isEmpty()) {
        OutError = "Empty instruction";
        return false;
    }

    QString Mnemonic = Parts[0];
    QString Operands = Parts.mid(1).join(" ");

    QStringList OpList;
    if (!Operands.isEmpty()) {
        OpList = Operands.split(',');
        for (auto& Op : OpList) {
            Op = Op.trimmed();
        }
    }

    if (Mnemonic == "push" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            if (NeedsRex(Reg64)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0x50 + (Reg64 & 7)));
            return true;
        }

        int64_t Imm;
        if (ParseImmediate(OpList[0], Imm)) {
            if (Imm >= -128 && Imm <= 127) {
                OutBytes.append(static_cast<char>(0x6A));
                OutBytes.append(static_cast<char>(Imm & 0xFF));
            } else {
                OutBytes.append(static_cast<char>(0x68));
                uint32_t Val = static_cast<uint32_t>(Imm);
                OutBytes.append(static_cast<char>(Val & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
            }
            return true;
        }

        OutError = "Invalid operand for push: " + OpList[0];
        return false;
    }

    if (Mnemonic == "pop" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            if (NeedsRex(Reg64)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0x58 + (Reg64 & 7)));
            return true;
        }
        OutError = "Invalid operand for pop: " + OpList[0];
        return false;
    }

    if (Mnemonic == "xor" && OpList.size() == 2) {
        int Dst64 = ParseRegister64(OpList[0]);
        int Src64 = ParseRegister64(OpList[1]);
        if (Dst64 >= 0 && Src64 >= 0) {
            bool W = true;
            bool R = NeedsRex(Src64);
            bool B = NeedsRex(Dst64);
            OutBytes.append(RexByte(W, R, false, B));
            OutBytes.append(static_cast<char>(0x31));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src64 & 7), static_cast<uint8_t>(Dst64 & 7)));
            return true;
        }

        int Dst32 = ParseRegister32(OpList[0]);
        int Src32 = ParseRegister32(OpList[1]);
        if (Dst32 >= 0 && Src32 >= 0) {
            if (NeedsRex(Dst32) || NeedsRex(Src32)) {
                OutBytes.append(RexByte(false, NeedsRex(Src32), false, NeedsRex(Dst32)));
            }
            OutBytes.append(static_cast<char>(0x31));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src32 & 7), static_cast<uint8_t>(Dst32 & 7)));
            return true;
        }

        if (Dst64 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                OutBytes.append(RexByte(true, false, false, NeedsRex(Dst64)));
                if (Imm >= -128 && Imm <= 127) {
                    OutBytes.append(static_cast<char>(0x83));
                    OutBytes.append(ModRmByte(3, 6, static_cast<uint8_t>(Dst64 & 7)));
                    OutBytes.append(static_cast<char>(Imm & 0xFF));
                } else {
                    if (Dst64 == 0) {
                        OutBytes.append(static_cast<char>(0x35));
                    } else {
                        OutBytes.append(static_cast<char>(0x81));
                        OutBytes.append(ModRmByte(3, 6, static_cast<uint8_t>(Dst64 & 7)));
                    }
                    uint32_t Val = static_cast<uint32_t>(Imm);
                    OutBytes.append(static_cast<char>(Val & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
                }
                return true;
            }
        }

        Dst32 = ParseRegister32(OpList[0]);
        if (Dst32 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                if (NeedsRex(Dst32)) {
                    OutBytes.append(RexByte(false, false, false, true));
                }
                if (Imm >= -128 && Imm <= 127) {
                    OutBytes.append(static_cast<char>(0x83));
                    OutBytes.append(ModRmByte(3, 6, static_cast<uint8_t>(Dst32 & 7)));
                    OutBytes.append(static_cast<char>(Imm & 0xFF));
                } else {
                    if (Dst32 == 0 && !NeedsRex(Dst32)) {
                        OutBytes.append(static_cast<char>(0x35));
                    } else {
                        OutBytes.append(static_cast<char>(0x81));
                        OutBytes.append(ModRmByte(3, 6, static_cast<uint8_t>(Dst32 & 7)));
                    }
                    uint32_t Val = static_cast<uint32_t>(Imm);
                    OutBytes.append(static_cast<char>(Val & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
                }
                return true;
            }
        }
    }

    auto EmitAluRegImm = [&](uint8_t AluOp, int Reg, bool Is64, int64_t Imm) {
        if (Is64) {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg)));
        } else if (NeedsRex(Reg)) {
            OutBytes.append(RexByte(false, false, false, true));
        }
        if (Imm >= -128 && Imm <= 127) {
            OutBytes.append(static_cast<char>(0x83));
            OutBytes.append(ModRmByte(3, AluOp, static_cast<uint8_t>(Reg & 7)));
            OutBytes.append(static_cast<char>(Imm & 0xFF));
        } else {
            if (Reg == 0 && !NeedsRex(Reg)) {
                OutBytes.append(static_cast<char>(0x05 + (AluOp * 8)));
            } else {
                OutBytes.append(static_cast<char>(0x81));
                OutBytes.append(ModRmByte(3, AluOp, static_cast<uint8_t>(Reg & 7)));
            }
            uint32_t Val = static_cast<uint32_t>(Imm);
            OutBytes.append(static_cast<char>(Val & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
        }
    };

    auto EmitAluRegReg = [&](uint8_t AluOpcode, int Dst, int Src, bool Is64) {
        if (Is64) {
            OutBytes.append(RexByte(true, NeedsRex(Src), false, NeedsRex(Dst)));
        } else if (NeedsRex(Dst) || NeedsRex(Src)) {
            OutBytes.append(RexByte(false, NeedsRex(Src), false, NeedsRex(Dst)));
        }
        OutBytes.append(static_cast<char>(AluOpcode));
        OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src & 7), static_cast<uint8_t>(Dst & 7)));
    };

    struct AluInfo { QString Name; uint8_t Op; uint8_t Opcode; };
    QList<AluInfo> AluOps = {
        {"add", 0, 0x01}, {"or",  1, 0x09}, {"and", 4, 0x21}, {"sub", 5, 0x29}
    };

    for (const auto& Alu : AluOps) {
        if (Mnemonic == Alu.Name && OpList.size() == 2) {
            int Dst64 = ParseRegister64(OpList[0]);
            int Src64 = ParseRegister64(OpList[1]);
            if (Dst64 >= 0 && Src64 >= 0) {
                EmitAluRegReg(Alu.Opcode, Dst64, Src64, true);
                return true;
            }

            int Dst32 = ParseRegister32(OpList[0]);
            int Src32 = ParseRegister32(OpList[1]);
            if (Dst32 >= 0 && Src32 >= 0) {
                EmitAluRegReg(Alu.Opcode, Dst32, Src32, false);
                return true;
            }

            if (Dst64 >= 0) {
                int64_t Imm;
                if (ParseImmediate(OpList[1], Imm)) {
                    EmitAluRegImm(Alu.Op, Dst64, true, Imm);
                    return true;
                }
            }

            Dst32 = ParseRegister32(OpList[0]);
            if (Dst32 >= 0) {
                int64_t Imm;
                if (ParseImmediate(OpList[1], Imm)) {
                    EmitAluRegImm(Alu.Op, Dst32, false, Imm);
                    return true;
                }
            }
        }
    }

    if (Mnemonic == "mov" && OpList.size() == 2) {
        int Dst64 = ParseRegister64(OpList[0]);
        int Src64 = ParseRegister64(OpList[1]);
        if (Dst64 >= 0 && Src64 >= 0) {
            OutBytes.append(RexByte(true, NeedsRex(Src64), false, NeedsRex(Dst64)));
            OutBytes.append(static_cast<char>(0x89));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src64 & 7), static_cast<uint8_t>(Dst64 & 7)));
            return true;
        }

        if (Dst64 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                if (Imm >= INT32_MIN && Imm <= INT32_MAX) {
                    OutBytes.append(RexByte(true, false, false, NeedsRex(Dst64)));
                    OutBytes.append(static_cast<char>(0xC7));
                    OutBytes.append(ModRmByte(3, 0, static_cast<uint8_t>(Dst64 & 7)));
                    uint32_t Val = static_cast<uint32_t>(static_cast<int32_t>(Imm));
                    OutBytes.append(static_cast<char>(Val & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                    OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
                } else {
                    OutBytes.append(RexByte(true, false, false, NeedsRex(Dst64)));
                    OutBytes.append(static_cast<char>(0xB8 + (Dst64 & 7)));
                    uint64_t Val = static_cast<uint64_t>(Imm);
                    for (int I = 0; I < 8; ++I) {
                        OutBytes.append(static_cast<char>((Val >> (I * 8)) & 0xFF));
                    }
                }
                return true;
            }
        }

        int Dst32 = ParseRegister32(OpList[0]);
        int Src32 = ParseRegister32(OpList[1]);
        if (Dst32 >= 0 && Src32 >= 0) {
            if (NeedsRex(Dst32) || NeedsRex(Src32)) {
                OutBytes.append(RexByte(false, NeedsRex(Src32), false, NeedsRex(Dst32)));
            }
            OutBytes.append(static_cast<char>(0x89));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src32 & 7), static_cast<uint8_t>(Dst32 & 7)));
            return true;
        }

        Dst32 = ParseRegister32(OpList[0]);
        if (Dst32 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                if (NeedsRex(Dst32)) {
                    OutBytes.append(RexByte(false, false, false, true));
                }
                OutBytes.append(static_cast<char>(0xB8 + (Dst32 & 7)));
                uint32_t Val = static_cast<uint32_t>(Imm);
                OutBytes.append(static_cast<char>(Val & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
                return true;
            }
        }

        OutError = "Unsupported mov operands";
        return false;
    }

    if (Mnemonic == "call" && OpList.size() == 1) {
        int64_t Target;
        if (ParseImmediate(OpList[0], Target)) {
            int64_t Rel = Target - static_cast<int64_t>(Addr) - 5;
            if (Rel < INT32_MIN || Rel > INT32_MAX) {
                OutError = "Call target out of rel32 range";
                return false;
            }
            OutBytes.append(static_cast<char>(0xE8));
            uint32_t Val = static_cast<uint32_t>(static_cast<int32_t>(Rel));
            OutBytes.append(static_cast<char>(Val & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
            OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
            return true;
        }

        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            if (NeedsRex(Reg64)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 2, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }

        OutError = "Invalid call operand: " + OpList[0];
        return false;
    }

    if (Mnemonic == "jmp" && OpList.size() == 1) {
        int64_t Target;
        if (ParseImmediate(OpList[0], Target)) {
            int64_t Rel = Target - static_cast<int64_t>(Addr) - 5;
            if (Rel < INT32_MIN || Rel > INT32_MAX) {
                OutError = "Jump target out of rel32 range";
                return false;
            }
            int64_t Rel8 = Target - static_cast<int64_t>(Addr) - 2;
            if (Rel8 >= -128 && Rel8 <= 127) {
                OutBytes.append(static_cast<char>(0xEB));
                OutBytes.append(static_cast<char>(Rel8 & 0xFF));
            } else {
                OutBytes.append(static_cast<char>(0xE9));
                uint32_t Val = static_cast<uint32_t>(static_cast<int32_t>(Rel));
                OutBytes.append(static_cast<char>(Val & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
            }
            return true;
        }

        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            if (NeedsRex(Reg64)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 4, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }

        OutError = "Invalid jmp operand: " + OpList[0];
        return false;
    }

    struct JccInfo { QString Name; uint8_t Short; uint8_t Near; };
    QList<JccInfo> JccOps = {
        {"je",   0x74, 0x84}, {"jz",   0x74, 0x84},
        {"jne",  0x75, 0x85}, {"jnz",  0x75, 0x85},
        {"ja",   0x77, 0x87}, {"jae",  0x73, 0x83},
        {"jb",   0x72, 0x82}, {"jbe",  0x76, 0x86},
        {"jg",   0x7F, 0x8F}, {"jge",  0x7D, 0x8D},
        {"jl",   0x7C, 0x8C}, {"jle",  0x7E, 0x8E},
        {"js",   0x78, 0x88}, {"jns",  0x79, 0x89},
        {"jo",   0x70, 0x80}, {"jno",  0x71, 0x81},
        {"jp",   0x7A, 0x8A}, {"jnp",  0x7B, 0x8B},
    };

    for (const auto& Jcc : JccOps) {
        if (Mnemonic == Jcc.Name && OpList.size() == 1) {
            int64_t Target;
            if (!ParseImmediate(OpList[0], Target)) {
                OutError = "Invalid target for " + Mnemonic;
                return false;
            }

            int64_t Rel8 = Target - static_cast<int64_t>(Addr) - 2;
            if (Rel8 >= -128 && Rel8 <= 127) {
                OutBytes.append(static_cast<char>(Jcc.Short));
                OutBytes.append(static_cast<char>(Rel8 & 0xFF));
            } else {
                int64_t Rel32 = Target - static_cast<int64_t>(Addr) - 6;
                if (Rel32 < INT32_MIN || Rel32 > INT32_MAX) {
                    OutError = "Conditional jump target out of range";
                    return false;
                }
                OutBytes.append(static_cast<char>(0x0F));
                OutBytes.append(static_cast<char>(Jcc.Near));
                uint32_t Val = static_cast<uint32_t>(static_cast<int32_t>(Rel32));
                OutBytes.append(static_cast<char>(Val & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 8) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 16) & 0xFF));
                OutBytes.append(static_cast<char>((Val >> 24) & 0xFF));
            }
            return true;
        }
    }

    if (Mnemonic == "test" && OpList.size() == 2) {
        int Dst64 = ParseRegister64(OpList[0]);
        int Src64 = ParseRegister64(OpList[1]);
        if (Dst64 >= 0 && Src64 >= 0) {
            OutBytes.append(RexByte(true, NeedsRex(Src64), false, NeedsRex(Dst64)));
            OutBytes.append(static_cast<char>(0x85));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src64 & 7), static_cast<uint8_t>(Dst64 & 7)));
            return true;
        }

        int Dst32 = ParseRegister32(OpList[0]);
        int Src32 = ParseRegister32(OpList[1]);
        if (Dst32 >= 0 && Src32 >= 0) {
            if (NeedsRex(Dst32) || NeedsRex(Src32)) {
                OutBytes.append(RexByte(false, NeedsRex(Src32), false, NeedsRex(Dst32)));
            }
            OutBytes.append(static_cast<char>(0x85));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src32 & 7), static_cast<uint8_t>(Dst32 & 7)));
            return true;
        }
    }

    if (Mnemonic == "cmp" && OpList.size() == 2) {
        int Dst64 = ParseRegister64(OpList[0]);
        int Src64 = ParseRegister64(OpList[1]);
        if (Dst64 >= 0 && Src64 >= 0) {
            OutBytes.append(RexByte(true, NeedsRex(Src64), false, NeedsRex(Dst64)));
            OutBytes.append(static_cast<char>(0x39));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src64 & 7), static_cast<uint8_t>(Dst64 & 7)));
            return true;
        }

        int Dst32 = ParseRegister32(OpList[0]);
        int Src32 = ParseRegister32(OpList[1]);
        if (Dst32 >= 0 && Src32 >= 0) {
            if (NeedsRex(Dst32) || NeedsRex(Src32)) {
                OutBytes.append(RexByte(false, NeedsRex(Src32), false, NeedsRex(Dst32)));
            }
            OutBytes.append(static_cast<char>(0x39));
            OutBytes.append(ModRmByte(3, static_cast<uint8_t>(Src32 & 7), static_cast<uint8_t>(Dst32 & 7)));
            return true;
        }

        if (Dst64 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                EmitAluRegImm(7, Dst64, true, Imm);
                return true;
            }
        }

        Dst32 = ParseRegister32(OpList[0]);
        if (Dst32 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm)) {
                EmitAluRegImm(7, Dst32, false, Imm);
                return true;
            }
        }
    }

    if (Mnemonic == "lea" && OpList.size() == 2) {
        OutError = "LEA with memory operands not supported in mini assembler";
        return false;
    }

    if (Mnemonic == "inc" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 0, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }

        int Reg32 = ParseRegister32(OpList[0]);
        if (Reg32 >= 0) {
            if (NeedsRex(Reg32)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 0, static_cast<uint8_t>(Reg32 & 7)));
            return true;
        }
    }

    if (Mnemonic == "dec" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 1, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }

        int Reg32 = ParseRegister32(OpList[0]);
        if (Reg32 >= 0) {
            if (NeedsRex(Reg32)) {
                OutBytes.append(RexByte(false, false, false, true));
            }
            OutBytes.append(static_cast<char>(0xFF));
            OutBytes.append(ModRmByte(3, 1, static_cast<uint8_t>(Reg32 & 7)));
            return true;
        }
    }

    if (Mnemonic == "not" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xF7));
            OutBytes.append(ModRmByte(3, 2, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }
    }

    if (Mnemonic == "neg" && OpList.size() == 1) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0) {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xF7));
            OutBytes.append(ModRmByte(3, 3, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }
    }

    if (Mnemonic == "shl" && OpList.size() == 2) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0 && OpList[1] == "cl") {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xD3));
            OutBytes.append(ModRmByte(3, 4, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }
        if (Reg64 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm) && Imm >= 0 && Imm <= 255) {
                OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
                if (Imm == 1) {
                    OutBytes.append(static_cast<char>(0xD1));
                    OutBytes.append(ModRmByte(3, 4, static_cast<uint8_t>(Reg64 & 7)));
                } else {
                    OutBytes.append(static_cast<char>(0xC1));
                    OutBytes.append(ModRmByte(3, 4, static_cast<uint8_t>(Reg64 & 7)));
                    OutBytes.append(static_cast<char>(Imm & 0xFF));
                }
                return true;
            }
        }
    }

    if (Mnemonic == "shr" && OpList.size() == 2) {
        int Reg64 = ParseRegister64(OpList[0]);
        if (Reg64 >= 0 && OpList[1] == "cl") {
            OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
            OutBytes.append(static_cast<char>(0xD3));
            OutBytes.append(ModRmByte(3, 5, static_cast<uint8_t>(Reg64 & 7)));
            return true;
        }
        if (Reg64 >= 0) {
            int64_t Imm;
            if (ParseImmediate(OpList[1], Imm) && Imm >= 0 && Imm <= 255) {
                OutBytes.append(RexByte(true, false, false, NeedsRex(Reg64)));
                if (Imm == 1) {
                    OutBytes.append(static_cast<char>(0xD1));
                    OutBytes.append(ModRmByte(3, 5, static_cast<uint8_t>(Reg64 & 7)));
                } else {
                    OutBytes.append(static_cast<char>(0xC1));
                    OutBytes.append(ModRmByte(3, 5, static_cast<uint8_t>(Reg64 & 7)));
                    OutBytes.append(static_cast<char>(Imm & 0xFF));
                }
                return true;
            }
        }
    }

    OutError = "Unsupported instruction: " + Mnemonic;
    return false;
}

bool PatchEngine::SavePatchedBinary(AnalysisDatabase* Db, const QString& OutputPath) {
    if (!Db) return false;

    BinaryInfo Info = Db->GetBinaryInfo();
    if (Info.FilePath.isEmpty()) return false;

    QFile SourceFile(Info.FilePath);
    if (!SourceFile.open(QIODevice::ReadOnly)) return false;
    QByteArray FileData = SourceFile.readAll();
    SourceFile.close();

    if (FileData.isEmpty()) return false;

    for (const PatchEntry& Entry : Patches) {
        if (!Entry.IsApplied) continue;

        bool Found = false;
        for (const Segment& Seg : Info.Segments) {
            if (Entry.Addr >= Seg.VirtualAddress && Entry.Addr < Seg.VirtualAddress + Seg.VirtualSize) {
                size_t OffsetInSeg = static_cast<size_t>(Entry.Addr - Seg.VirtualAddress);
                size_t FileOffset = Seg.RawOffset + OffsetInSeg;

                if (FileOffset + static_cast<size_t>(Entry.PatchedBytes.size()) > static_cast<size_t>(FileData.size())) {
                    return false;
                }

                memcpy(FileData.data() + FileOffset, Entry.PatchedBytes.constData(),
                       static_cast<size_t>(Entry.PatchedBytes.size()));
                Found = true;
                break;
            }
        }

        if (!Found) return false;
    }

    QFile OutFile(OutputPath);
    if (!OutFile.open(QIODevice::WriteOnly)) return false;
    OutFile.write(FileData);
    OutFile.close();

    return true;
}

bool PatchEngine::ExportPatches(const QString& Path) {
    QJsonArray PatchArr;

    for (const PatchEntry& Entry : Patches) {
        QJsonObject Obj;
        Obj["address"] = QString("0x%1").arg(Entry.Addr, 16, 16, QChar('0')).toUpper();
        Obj["original"] = QString(Entry.OriginalBytes.toHex(' ').toUpper());
        Obj["patched"] = QString(Entry.PatchedBytes.toHex(' ').toUpper());
        Obj["description"] = Entry.Description;
        Obj["applied"] = Entry.IsApplied;
        Obj["timestamp"] = Entry.Timestamp.toString(Qt::ISODate);
        PatchArr.append(Obj);
    }

    QJsonObject Root;
    Root["version"] = 1;
    Root["patches"] = PatchArr;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) return false;

    QJsonDocument Doc(Root);
    File.write(Doc.toJson(QJsonDocument::Indented));
    File.close();
    return true;
}

bool PatchEngine::ImportPatches(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) return false;

    QJsonParseError ParseError;
    QJsonDocument Doc = QJsonDocument::fromJson(File.readAll(), &ParseError);
    File.close();

    if (ParseError.error != QJsonParseError::NoError) return false;

    QJsonObject Root = Doc.object();
    QJsonArray PatchArr = Root["patches"].toArray();

    for (const QJsonValue& Val : PatchArr) {
        QJsonObject Obj = Val.toObject();

        PatchEntry Entry;
        Entry.Addr = Obj["address"].toString().toULongLong(nullptr, 0);
        Entry.OriginalBytes = QByteArray::fromHex(Obj["original"].toString().remove(' ').toLatin1());
        Entry.PatchedBytes = QByteArray::fromHex(Obj["patched"].toString().remove(' ').toLatin1());
        Entry.Description = Obj["description"].toString();
        Entry.IsApplied = Obj["applied"].toBool();
        Entry.Timestamp = QDateTime::fromString(Obj["timestamp"].toString(), Qt::ISODate);

        Patches.append(Entry);
    }

    return true;
}

QList<PatchEntry> PatchEngine::GetPatches() const {
    return Patches;
}

int PatchEngine::PatchCount() const {
    return Patches.size();
}

int PatchEngine::ParseRegister64(const QString& Name) const {
    auto It = RegisterMap64.constFind(Name);
    if (It != RegisterMap64.constEnd()) return It.value();
    return -1;
}

int PatchEngine::ParseRegister32(const QString& Name) const {
    auto It = RegisterMap32.constFind(Name);
    if (It != RegisterMap32.constEnd()) return It.value();
    return -1;
}

int PatchEngine::ParseRegister8(const QString& Name) const {
    auto It = RegisterMap8.constFind(Name);
    if (It != RegisterMap8.constEnd()) return It.value();
    return -1;
}

bool PatchEngine::ParseImmediate(const QString& Text, int64_t& OutValue) const {
    QString Trimmed = Text.trimmed();
    bool Ok = false;

    if (Trimmed.startsWith("0x") || Trimmed.startsWith("0X")) {
        OutValue = Trimmed.mid(2).toLongLong(&Ok, 16);
        return Ok;
    }

    if (Trimmed.startsWith("-0x") || Trimmed.startsWith("-0X")) {
        int64_t Abs = Trimmed.mid(3).toLongLong(&Ok, 16);
        if (Ok) OutValue = -Abs;
        return Ok;
    }

    if (Trimmed.endsWith('h') || Trimmed.endsWith('H')) {
        OutValue = Trimmed.left(Trimmed.size() - 1).toLongLong(&Ok, 16);
        return Ok;
    }

    OutValue = Trimmed.toLongLong(&Ok, 0);
    return Ok;
}

bool PatchEngine::NeedsRexW(const QString& RegName) const {
    return RegisterMap64.contains(RegName);
}

bool PatchEngine::NeedsRex(int Reg) const {
    return Reg >= 8;
}

uint8_t PatchEngine::RexByte(bool W, bool R, bool X, bool B) const {
    uint8_t Rex = 0x40;
    if (W) Rex |= 0x08;
    if (R) Rex |= 0x04;
    if (X) Rex |= 0x02;
    if (B) Rex |= 0x01;
    return Rex;
}

uint8_t PatchEngine::ModRmByte(uint8_t Mod, uint8_t Reg, uint8_t Rm) const {
    return static_cast<uint8_t>((Mod << 6) | ((Reg & 7) << 3) | (Rm & 7));
}

}
