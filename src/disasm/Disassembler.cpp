#include "Disassembler.h"

namespace Fidra {

Disassembler::Disassembler()
    : Handle(0)
    , HandleOpen(false)
    , CurrentArch(Architecture::Unknown) {
}

Disassembler::~Disassembler() {
    Close();
}

bool Disassembler::SetArchitecture(Architecture Arch) {
    Close();

    cs_arch CsArch;
    cs_mode CsMode;

    switch (Arch) {
    case Architecture::X86:
        CsArch = CS_ARCH_X86;
        CsMode = CS_MODE_32;
        break;
    case Architecture::X64:
        CsArch = CS_ARCH_X86;
        CsMode = CS_MODE_64;
        break;
    case Architecture::ARM:
        CsArch = CS_ARCH_ARM;
        CsMode = CS_MODE_ARM;
        break;
    case Architecture::ARM64:
        CsArch = CS_ARCH_ARM64;
        CsMode = CS_MODE_ARM;
        break;
    case Architecture::Unknown:
    default:
        ErrorMsg = QStringLiteral("Unsupported architecture");
        return false;
    }

    cs_err Result = cs_open(CsArch, CsMode, &Handle);
    if (Result != CS_ERR_OK) {
        ErrorMsg = QString::fromUtf8(cs_strerror(Result));
        return false;
    }

    HandleOpen = true;
    CurrentArch = Arch;

    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

    ErrorMsg.clear();
    return true;
}

Architecture Disassembler::GetArchitecture() const {
    return CurrentArch;
}

QList<DisasmInstruction> Disassembler::Disassemble(const QByteArray& Data, Address StartAddress, size_t MaxInstructions) {
    QList<DisasmInstruction> Results;

    if (!HandleOpen) {
        ErrorMsg = QStringLiteral("Disassembler not initialized");
        return Results;
    }

    cs_insn* Insns = nullptr;
    size_t Count = cs_disasm(Handle,
                             reinterpret_cast<const uint8_t*>(Data.constData()),
                             static_cast<size_t>(Data.size()),
                             StartAddress,
                             MaxInstructions,
                             &Insns);

    if (Count == 0) {
        cs_err Err = cs_errno(Handle);
        if (Err != CS_ERR_OK) {
            ErrorMsg = QString::fromUtf8(cs_strerror(Err));
        }
        return Results;
    }

    Results.reserve(static_cast<qsizetype>(Count));

    for (size_t I = 0; I < Count; ++I) {
        DisasmInstruction Inst;
        Inst.Location = Insns[I].address;
        Inst.Bytes = QByteArray(reinterpret_cast<const char*>(Insns[I].bytes),
                                static_cast<qsizetype>(Insns[I].size));
        Inst.Mnemonic = QString::fromUtf8(Insns[I].mnemonic);
        Inst.Operands = QString::fromUtf8(Insns[I].op_str);
        Results.append(std::move(Inst));
    }

    cs_free(Insns, Count);
    ErrorMsg.clear();
    return Results;
}

QList<DisasmInstruction> Disassembler::DisassembleOne(const QByteArray& Data, Address StartAddress) {
    return Disassemble(Data, StartAddress, 1);
}

bool Disassembler::IsOpen() const {
    return HandleOpen;
}

QString Disassembler::LastError() const {
    return ErrorMsg;
}

void Disassembler::Close() {
    if (HandleOpen) {
        cs_close(&Handle);
        HandleOpen = false;
        CurrentArch = Architecture::Unknown;
    }
}

}
