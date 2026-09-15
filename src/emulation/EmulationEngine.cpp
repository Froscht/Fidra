#include "EmulationEngine.h"
#include "../analysis/AnalysisDatabase.h"

#include <QDebug>

#ifdef FIDRA_HAS_UNICORN
#include <unicorn/unicorn.h>
#endif

namespace Fidra {

#ifdef FIDRA_HAS_UNICORN
static uc_arch ArchToUcArch(Architecture Arch) {
    switch (Arch) {
        case Architecture::X86:
        case Architecture::X64:   return UC_ARCH_X86;
        case Architecture::ARM:   return UC_ARCH_ARM;
        case Architecture::ARM64: return UC_ARCH_ARM64;
        default:                  return UC_ARCH_X86;
    }
}

static uc_mode ArchToUcMode(Architecture Arch) {
    switch (Arch) {
        case Architecture::X86:   return UC_MODE_32;
        case Architecture::X64:   return UC_MODE_64;
        case Architecture::ARM:   return UC_MODE_ARM;
        case Architecture::ARM64: return UC_MODE_ARM;
        default:                  return UC_MODE_64;
    }
}

static uint32_t PermsToUcPerms(bool R, bool W, bool X) {
    uint32_t P = 0;
    if (R) P |= UC_PROT_READ;
    if (W) P |= UC_PROT_WRITE;
    if (X) P |= UC_PROT_EXEC;
    return P;
}
#endif

EmulationEngine::EmulationEngine() : Uc(nullptr), CurrentArch(Architecture::Unknown) {}

EmulationEngine::~EmulationEngine() { Close(); }

bool EmulationEngine::IsAvailable() {
#ifdef FIDRA_HAS_UNICORN
    return true;
#else
    return false;
#endif
}

bool EmulationEngine::Open(Architecture Arch) {
#ifdef FIDRA_HAS_UNICORN
    Close();
    uc_engine* U = nullptr;
    uc_err Err = uc_open(ArchToUcArch(Arch), ArchToUcMode(Arch), &U);
    if (Err != UC_ERR_OK) return false;
    Uc = U;
    CurrentArch = Arch;
    return true;
#else
    (void)Arch; return false;
#endif
}

void EmulationEngine::Close() {
#ifdef FIDRA_HAS_UNICORN
    if (Uc) {
        uc_close(static_cast<uc_engine*>(Uc));
        Uc = nullptr;
    }
#endif
}

bool EmulationEngine::MapAllSegments(const AnalysisDatabase& Db) {
#ifdef FIDRA_HAS_UNICORN
    if (!Uc) return false;
    auto* U = static_cast<uc_engine*>(Uc);
    for (const auto& S : Db.GetBinaryInfo().Segments) {
        if (S.VirtualSize == 0) continue;
        constexpr size_t PageSize = 0x1000;
        uint64_t Base = S.VirtualAddress & ~(PageSize - 1);
        size_t Size = ((S.VirtualSize + (S.VirtualAddress - Base) + PageSize - 1) / PageSize) * PageSize;
        uint32_t Perms = PermsToUcPerms(S.IsReadable, S.IsWritable, S.IsExecutable);
        if (uc_mem_map(U, Base, Size, Perms) != UC_ERR_OK) continue;
        if (!S.Data.isEmpty()) {
            size_t Copy = std::min(static_cast<size_t>(S.Data.size()), S.VirtualSize);
            uc_mem_write(U, S.VirtualAddress, S.Data.constData(), Copy);
        }
    }
    return true;
#else
    (void)Db; return false;
#endif
}

bool EmulationEngine::MapStack(Address Base, size_t Size) {
#ifdef FIDRA_HAS_UNICORN
    if (!Uc) return false;
    auto* U = static_cast<uc_engine*>(Uc);
    return uc_mem_map(U, Base, Size, UC_PROT_READ | UC_PROT_WRITE) == UC_ERR_OK;
#else
    (void)Base; (void)Size; return false;
#endif
}

bool EmulationEngine::SetRip(Address Value) {
#ifdef FIDRA_HAS_UNICORN
    if (!Uc) return false;
    auto* U = static_cast<uc_engine*>(Uc);
    int Reg = (CurrentArch == Architecture::X64) ? UC_X86_REG_RIP :
              (CurrentArch == Architecture::X86) ? UC_X86_REG_EIP :
              (CurrentArch == Architecture::ARM64) ? UC_ARM64_REG_PC : UC_ARM_REG_PC;
    return uc_reg_write(U, Reg, &Value) == UC_ERR_OK;
#else
    (void)Value; return false;
#endif
}

bool EmulationEngine::SetRegister(int RegisterId, uint64_t Value) {
#ifdef FIDRA_HAS_UNICORN
    if (!Uc) return false;
    auto* U = static_cast<uc_engine*>(Uc);
    return uc_reg_write(U, RegisterId, &Value) == UC_ERR_OK;
#else
    (void)RegisterId; (void)Value; return false;
#endif
}

bool EmulationEngine::WriteMemory(Address Addr, const QByteArray& Data) {
#ifdef FIDRA_HAS_UNICORN
    if (!Uc || Data.isEmpty()) return false;
    auto* U = static_cast<uc_engine*>(Uc);
    return uc_mem_write(U, Addr, Data.constData(), Data.size()) == UC_ERR_OK;
#else
    (void)Addr; (void)Data; return false;
#endif
}

EmulationResult EmulationEngine::EmulateFunction(const AnalysisDatabase& Db, Address FunctionStart, size_t MaxInsn, uint64_t TimeoutUs) {
    EmulationResult Res;
#ifdef FIDRA_HAS_UNICORN
    AnalyzedFunction Func = Db.GetFunction(FunctionStart);
    if (Func.Start == 0 && Func.End == 0) {
        Res.Error = "Unknown function";
        return Res;
    }
    if (!Uc) {
        if (!Open(Db.GetBinaryInfo().Arch)) {
            Res.Error = "uc_open failed";
            return Res;
        }
        MapAllSegments(Db);
        MapStack(0x7FFF00000000ULL, 0x100000);
        uint64_t Rsp = 0x7FFF00080000ULL;
        auto* U = static_cast<uc_engine*>(Uc);
        int RspReg = (CurrentArch == Architecture::X64) ? UC_X86_REG_RSP : UC_X86_REG_ESP;
        uc_reg_write(U, RspReg, &Rsp);
    }
    SetRip(FunctionStart);
    auto* U = static_cast<uc_engine*>(Uc);
    uc_err E = uc_emu_start(U, FunctionStart, Func.End, TimeoutUs, MaxInsn);
    uint64_t Pc = 0;
    int PcReg = (CurrentArch == Architecture::X64) ? UC_X86_REG_RIP : UC_X86_REG_EIP;
    uc_reg_read(U, PcReg, &Pc);
    Res.FinalPc = Pc;
    if (E != UC_ERR_OK) {
        Res.Error = QString("uc_emu_start: %1").arg(uc_strerror(E));
    } else {
        Res.Ok = true;
    }
#else
    (void)Db; (void)FunctionStart; (void)MaxInsn; (void)TimeoutUs;
    Res.Error = "Unicorn not compiled in — build with -DFIDRA_ENABLE_UNICORN=ON";
#endif
    return Res;
}

}
