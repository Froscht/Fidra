#include "LibdecompBackend.h"

#include "../analysis/AnalysisDatabase.h"

#include <QByteArray>
#include <vector>
#include <cstddef>
#include <cstdint>

#ifdef FIDRA_HAS_LIBDECOMP
#include <capstone/capstone.h>

extern "C" int fidra_libdecomp_run(const uint8_t* code_bytes,
                                   const size_t* insn_offsets,
                                   const size_t* insn_sizes,
                                   const uint64_t* insn_addrs,
                                   size_t insn_count,
                                   int arch,
                                   int mode,
                                   int opt_level,
                                   char* out_buf,
                                   size_t out_buf_size);
#endif

namespace Fidra {

bool LibdecompBackend::IsAvailable() {
#ifdef FIDRA_HAS_LIBDECOMP
    return true;
#else
    return false;
#endif
}

QString LibdecompBackend::DecompileFunction(const AnalysisDatabase& Db, Address FunctionStart, int OptLevel) {
#ifdef FIDRA_HAS_LIBDECOMP
    AnalyzedFunction Func = Db.GetFunction(FunctionStart);
    if (Func.Start == 0 && Func.End == 0) return QString();

    QList<AnalyzedInstruction> Insns = Db.GetInstructions(Func.Start, Func.End);
    if (Insns.isEmpty()) return QString();

    std::vector<uint8_t> AllBytes;
    std::vector<size_t> Offsets;
    std::vector<size_t> Sizes;
    std::vector<uint64_t> Addrs;

    Offsets.reserve(Insns.size());
    Sizes.reserve(Insns.size());
    Addrs.reserve(Insns.size());

    for (const auto& I : Insns) {
        Offsets.push_back(AllBytes.size());
        Sizes.push_back(I.Size);
        Addrs.push_back(I.Addr);
        AllBytes.insert(AllBytes.end(), I.Bytes, I.Bytes + I.Size);
    }

    int Arch = CS_ARCH_X86;
    int Mode = CS_MODE_64;
    switch (Db.GetBinaryInfo().Arch) {
        case Architecture::X86:   Mode = CS_MODE_32; break;
        case Architecture::X64:   Mode = CS_MODE_64; break;
        case Architecture::ARM:   Arch = CS_ARCH_ARM;   Mode = CS_MODE_ARM; break;
        case Architecture::ARM64: Arch = CS_ARCH_ARM64; Mode = CS_MODE_ARM; break;
        default: break;
    }

    constexpr size_t OutSize = 1 << 16;
    std::vector<char> Out(OutSize, 0);
    int Err = fidra_libdecomp_run(AllBytes.data(),
                                  Offsets.data(),
                                  Sizes.data(),
                                  Addrs.data(),
                                  Insns.size(),
                                  Arch,
                                  Mode,
                                  OptLevel,
                                  Out.data(),
                                  OutSize);
    if (Err != 0) return QString("// libdecomp error: %1").arg(Err);
    return QString::fromUtf8(Out.data());
#else
    (void)Db; (void)FunctionStart; (void)OptLevel;
    return QString();
#endif
}

}
