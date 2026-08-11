#include "SignatureMatcher.h"

namespace Fidra {

SignatureMatcher::SignatureMatcher() = default;
SignatureMatcher::~SignatureMatcher() = default;

void SignatureMatcher::LoadBuiltinSignatures(bool Is64Bit) {
    Signatures.clear();

    if (Is64Bit) {
        AddSignature("__libc_start_main_wrapper", "libc", "48 89 E7 48 8D 35 ?? ?? ?? ?? 48 8D 3D", 10);
        AddSignature("_start", "crt", "31 ED 49 89 D1 5E 48 89 E2 48 83 E4 F0", 10);
        AddSignature("__stack_chk_fail", "libc", "48 8B 05 ?? ?? ?? ?? 64 48 33 04 25 28 00 00 00", 12);
        AddSignature("prologue_rbp_frame", "common", "55 48 89 E5", 4);
        AddSignature("prologue_sub_rsp", "common", "48 83 EC", 3);
        AddSignature("prologue_push_rbx_sub", "common", "40 53 48 83 EC", 5);
        AddSignature("prologue_save_rbx", "common", "48 89 5C 24", 4);
        AddSignature("prologue_save_rdi", "common", "48 89 7C 24", 4);
        AddSignature("prologue_save_rsi", "common", "48 89 74 24", 4);
        AddSignature("prologue_push_r12_r13", "common", "41 54 41 55 53 48 83 EC", 8);
        AddSignature("prologue_push_rbp_r12", "common", "41 54 55 53 48 83 EC", 7);
        AddSignature("memcpy", "libc", "48 89 F8 48 89 D1 48 C1 E9 03 F3 48 A5", 10);
        AddSignature("memset", "libc", "48 89 F8 40 0F B6 F6 48 89 D1 F3 AA", 10);
        AddSignature("memset_rep_stosb", "libc", "89 F0 48 89 D1 F3 AA 48 89 F8", 8);
        AddSignature("strlen", "libc", "48 89 F8 48 31 C9 48 83 C9 FF F2 AE 48 F7 D1 48 FF C9", 12);
        AddSignature("strcmp", "libc", "48 89 FE 48 89 F7 AC 3A 06 75 ?? 48 FF C6 84 C0 75", 12);
        AddSignature("malloc_wrapper", "libc", "48 83 EC 08 48 89 3C 24 E8 ?? ?? ?? ??", 8);
        AddSignature("free_wrapper", "libc", "48 85 FF 74 ?? 48 83 EC 08", 6);
        AddSignature("printf_wrapper", "libc", "48 83 EC 38 48 89 74 24 ?? 48 89 54 24 ?? 48 89 4C 24", 12);
        AddSignature("puts_call", "libc", "48 89 FE BF 01 00 00 00 E8", 8);
        AddSignature("lea_rip_relative", "common", "48 8D 05", 3);
        AddSignature("lea_rip_rdi", "common", "48 8D 3D", 3);
        AddSignature("call_rax", "common", "FF D0", 2);
        AddSignature("call_indirect", "common", "FF 15", 2);
        AddSignature("jmp_indirect", "common", "FF 25", 2);
        AddSignature("vtable_call", "cpp", "48 8B 07 FF 50", 5);
        AddSignature("vtable_call_offset", "cpp", "48 8B 07 48 8B 40 ?? FF D0", 6);
        AddSignature("constructor_pattern", "cpp", "55 48 89 E5 48 89 7D ?? 48 8D 05 ?? ?? ?? ?? 48 89 07", 12);
        AddSignature("destructor_pattern", "cpp", "55 48 89 E5 48 89 7D ?? 48 8D 05 ?? ?? ?? ?? 48 89 07 5D C3", 14);
        AddSignature("operator_new", "cpp", "48 83 FF 00 74 ?? E8 ?? ?? ?? ?? 48 85 C0", 8);
        AddSignature("operator_delete", "cpp", "48 85 FF 74 ?? 48 89 FE E8", 6);
        AddSignature("exception_handler", "cpp", "55 48 89 E5 41 56 53 48 83 EC ?? 48 89 7D", 10);
        AddSignature("atexit", "crt", "48 83 EC 08 48 89 FE 48 8D 3D", 8);
        AddSignature("exit", "crt", "89 FE BF 3C 00 00 00 0F 05", 6);
        AddSignature("syscall_wrapper", "libc", "B8 ?? ?? ?? ?? 0F 05 48 3D 00 F0 FF FF", 8);
        AddSignature("mmap_wrapper", "libc", "49 89 CA B8 09 00 00 00 0F 05", 8);
        AddSignature("ret_zero", "common", "31 C0 C3", 3);
        AddSignature("ret_one", "common", "B8 01 00 00 00 C3", 6);
        AddSignature("nop_ret", "common", "90 C3", 2);
    } else {
        AddSignature("_start_32", "crt", "31 ED 5E 89 E1 83 E4 F0", 8);
        AddSignature("prologue_ebp_frame", "common", "55 89 E5", 3);
        AddSignature("prologue_sub_esp", "common", "83 EC", 2);
        AddSignature("prologue_push_regs", "common", "53 56 57", 3);
        AddSignature("prologue_push_ebx_sub", "common", "53 83 EC", 3);
        AddSignature("__stack_chk_fail_32", "libc", "8B 15 ?? ?? ?? ?? 65 33 15 14 00 00 00", 10);
        AddSignature("memcpy_32", "libc", "57 56 8B 7C 24 ?? 8B 74 24 ?? 8B 4C 24 ?? F3 A4", 10);
        AddSignature("memset_32", "libc", "57 8B 7C 24 ?? 8B 44 24 ?? 8B 4C 24 ?? F3 AA", 10);
        AddSignature("strlen_32", "libc", "57 31 C0 8B 7C 24 ?? 83 C9 FF F2 AE F7 D1 49", 10);
        AddSignature("strcmp_32", "libc", "56 57 8B 74 24 ?? 8B 7C 24 ?? AC 3A 06", 10);
        AddSignature("malloc_32", "libc", "83 EC 04 89 3C 24 E8", 6);
        AddSignature("free_32", "libc", "8B 44 24 04 85 C0 74", 6);
        AddSignature("printf_32", "libc", "83 EC 0C 8D 44 24 10 50 FF 74 24 10 E8", 10);
        AddSignature("DllMain", "win32", "55 89 E5 83 EC ?? 8B 45 0C 83 F8 01 74", 10);
        AddSignature("WinMain", "win32", "55 89 E5 83 EC ?? E8 ?? ?? ?? ?? 6A 00 6A 00 6A 00 50", 12);
        AddSignature("_DllMainCRTStartup", "win32", "55 89 E5 83 EC ?? 8B 45 0C 85 C0 74", 10);
        AddSignature("vtable_call_32", "cpp", "8B 01 FF 50", 4);
        AddSignature("constructor_32", "cpp", "55 89 E5 8B 45 08 8D 15 ?? ?? ?? ?? 89 10", 10);
        AddSignature("destructor_32", "cpp", "55 89 E5 8B 45 08 8D 15 ?? ?? ?? ?? 89 10 5D C3", 12);
        AddSignature("ret_zero_32", "common", "31 C0 C3", 3);
        AddSignature("ret_one_32", "common", "B8 01 00 00 00 C3", 6);
        AddSignature("call_indirect_32", "common", "FF 15", 2);
        AddSignature("jmp_indirect_32", "common", "FF 25", 2);
        AddSignature("thunk_jmp", "common", "FF 25 ?? ?? ?? ??", 6);
    }
}

void SignatureMatcher::AddSignature(const QString& Name, const QString& Module, const QString& HexPattern, int MinSize) {
    FunctionSignature Sig;
    Sig.Name = Name;
    Sig.Module = Module;
    Sig.Pattern = ParsePattern(HexPattern);
    Sig.MinSize = MinSize > 0 ? MinSize : Sig.Pattern.size();
    if (!Sig.Pattern.isEmpty()) {
        Signatures.append(Sig);
    }
}

QList<int16_t> SignatureMatcher::ParsePattern(const QString& HexPattern) {
    QList<int16_t> Result;
    QStringList Tokens = HexPattern.split(' ', Qt::SkipEmptyParts);

    for (const QString& Token : Tokens) {
        if (Token == "??" || Token == "?") {
            Result.append(-1);
        } else {
            bool Ok = false;
            int Val = Token.toInt(&Ok, 16);
            if (Ok && Val >= 0 && Val <= 255) {
                Result.append(static_cast<int16_t>(Val));
            } else {
                Result.append(-1);
            }
        }
    }

    return Result;
}

bool SignatureMatcher::MatchPattern(const uint8_t* Data, size_t Size, const QList<int16_t>& Pattern) {
    if (static_cast<int>(Size) < Pattern.size()) return false;

    for (int I = 0; I < Pattern.size(); ++I) {
        if (Pattern[I] >= 0 && Data[I] != static_cast<uint8_t>(Pattern[I])) {
            return false;
        }
    }
    return true;
}

QList<SignatureMatch> SignatureMatcher::MatchFunctions(AnalysisDatabase* Db) {
    QList<SignatureMatch> Results;
    if (!Db) return Results;

    auto Functions = Db->GetAllFunctions();

    for (const auto& Func : Functions) {
        size_t ReadSize = qMin(static_cast<size_t>(64), Func.Size);
        QByteArray Bytes = Db->ReadBytes(Func.Start, ReadSize);
        if (Bytes.isEmpty()) continue;

        const uint8_t* DataPtr = reinterpret_cast<const uint8_t*>(Bytes.constData());

        int BestConfidence = 0;
        QString BestName;
        QString BestModule;

        for (const auto& Sig : Signatures) {
            if (Sig.Pattern.size() > Bytes.size()) continue;
            if (static_cast<int>(Func.Size) < Sig.MinSize) continue;

            if (MatchPattern(DataPtr, Bytes.size(), Sig.Pattern)) {
                int Confidence = (Sig.Pattern.size() * 100) / qMax(1, static_cast<int>(ReadSize));
                int WildcardCount = 0;
                for (int16_t B : Sig.Pattern) {
                    if (B < 0) WildcardCount++;
                }
                int DefiniteBytes = Sig.Pattern.size() - WildcardCount;
                Confidence = (DefiniteBytes * 100) / qMax(1, Sig.Pattern.size());

                if (Confidence > BestConfidence) {
                    BestConfidence = Confidence;
                    BestName = Sig.Name;
                    BestModule = Sig.Module;
                }
            }
        }

        if (BestConfidence > 30) {
            SignatureMatch Match;
            Match.Addr = Func.Start;
            Match.Name = BestName;
            Match.Module = BestModule;
            Match.Confidence = BestConfidence;
            Results.append(Match);
        }
    }

    std::sort(Results.begin(), Results.end(), [](const SignatureMatch& A, const SignatureMatch& B) {
        return A.Confidence > B.Confidence;
    });

    return Results;
}

SignatureMatch SignatureMatcher::MatchSingle(const uint8_t* Data, size_t Size, Address Addr) {
    SignatureMatch Best;
    Best.Addr = Addr;
    Best.Confidence = 0;

    for (const auto& Sig : Signatures) {
        if (static_cast<int>(Size) < Sig.Pattern.size()) continue;

        if (MatchPattern(Data, Size, Sig.Pattern)) {
            int WildcardCount = 0;
            for (int16_t B : Sig.Pattern) {
                if (B < 0) WildcardCount++;
            }
            int DefiniteBytes = Sig.Pattern.size() - WildcardCount;
            int Confidence = (DefiniteBytes * 100) / qMax(1, Sig.Pattern.size());

            if (Confidence > Best.Confidence) {
                Best.Name = Sig.Name;
                Best.Module = Sig.Module;
                Best.Confidence = Confidence;
            }
        }
    }

    return Best;
}

int SignatureMatcher::SignatureCount() const {
    return Signatures.size();
}

}
