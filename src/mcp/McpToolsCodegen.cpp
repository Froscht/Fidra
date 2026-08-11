#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <capstone/capstone.h>
#include <cstring>

namespace Fidra {

void McpToolRegistry::RegisterCodegenTools() {

    RegisterTool(QStringLiteral("generate_inline_hook"),
        QStringLiteral("Generate x64 inline hook C++ code with trampoline, backup, and unhook."),
        Schema::Build({
            {QStringLiteral("target_address"), Schema::String(QStringLiteral("Target function address in hex"))},
            {QStringLiteral("hook_function_name"), Schema::String(QStringLiteral("Name of the hook function"))}
        }, {QStringLiteral("target_address"), QStringLiteral("hook_function_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString TargetAddr = A.value(QStringLiteral("target_address")).toString();
            QString HookName = A.value(QStringLiteral("hook_function_name")).toString();

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstring>\n\n");
            Code += QStringLiteral("namespace InlineHook {\n\n");
            Code += QStringLiteral("static BYTE OriginalBytes[14];\n");
            Code += QStringLiteral("static void* TargetAddress = reinterpret_cast<void*>(") + TargetAddr + QStringLiteral(");\n");
            Code += QStringLiteral("static void* TrampolineBuffer = nullptr;\n\n");
            Code += QStringLiteral("void ") + HookName + QStringLiteral("() {\n");
            Code += QStringLiteral("    // Your hook logic here\n}\n\n");
            Code += QStringLiteral("bool Install() {\n");
            Code += QStringLiteral("    TrampolineBuffer = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n");
            Code += QStringLiteral("    if (!TrampolineBuffer) return false;\n\n");
            Code += QStringLiteral("    memcpy(OriginalBytes, TargetAddress, 14);\n\n");
            Code += QStringLiteral("    memcpy(TrampolineBuffer, OriginalBytes, 14);\n");
            Code += QStringLiteral("    BYTE JmpBack[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };\n");
            Code += QStringLiteral("    uintptr_t ReturnAddr = reinterpret_cast<uintptr_t>(TargetAddress) + 14;\n");
            Code += QStringLiteral("    memcpy(JmpBack + 6, &ReturnAddr, 8);\n");
            Code += QStringLiteral("    memcpy(reinterpret_cast<BYTE*>(TrampolineBuffer) + 14, JmpBack, 14);\n\n");
            Code += QStringLiteral("    DWORD OldProtect;\n");
            Code += QStringLiteral("    VirtualProtect(TargetAddress, 14, PAGE_EXECUTE_READWRITE, &OldProtect);\n\n");
            Code += QStringLiteral("    BYTE JmpHook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };\n");
            Code += QStringLiteral("    uintptr_t HookAddr = reinterpret_cast<uintptr_t>(&") + HookName + QStringLiteral(");\n");
            Code += QStringLiteral("    memcpy(JmpHook + 6, &HookAddr, 8);\n");
            Code += QStringLiteral("    memcpy(TargetAddress, JmpHook, 14);\n\n");
            Code += QStringLiteral("    VirtualProtect(TargetAddress, 14, OldProtect, &OldProtect);\n");
            Code += QStringLiteral("    return true;\n}\n\n");
            Code += QStringLiteral("bool Uninstall() {\n");
            Code += QStringLiteral("    DWORD OldProtect;\n");
            Code += QStringLiteral("    VirtualProtect(TargetAddress, 14, PAGE_EXECUTE_READWRITE, &OldProtect);\n");
            Code += QStringLiteral("    memcpy(TargetAddress, OriginalBytes, 14);\n");
            Code += QStringLiteral("    VirtualProtect(TargetAddress, 14, OldProtect, &OldProtect);\n");
            Code += QStringLiteral("    if (TrampolineBuffer) {\n");
            Code += QStringLiteral("        VirtualFree(TrampolineBuffer, 0, MEM_RELEASE);\n");
            Code += QStringLiteral("        TrampolineBuffer = nullptr;\n    }\n");
            Code += QStringLiteral("    return true;\n}\n\n");
            Code += QStringLiteral("} // namespace InlineHook\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("x64 inline hook with 14-byte JMP ABS [addr] shellcode, trampoline, and unhook");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_iat_hook"),
        QStringLiteral("Generate IAT hook C++ code that walks PEB, finds module, replaces import entry."),
        Schema::Build({
            {QStringLiteral("module_name"), Schema::String(QStringLiteral("Target module name (e.g. kernel32.dll)"))},
            {QStringLiteral("function_name"), Schema::String(QStringLiteral("Imported function name to hook"))},
            {QStringLiteral("hook_function_name"), Schema::String(QStringLiteral("Name of your hook function"))}
        }, {QStringLiteral("module_name"), QStringLiteral("function_name"), QStringLiteral("hook_function_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString ModuleName = A.value(QStringLiteral("module_name")).toString();
            QString FuncName = A.value(QStringLiteral("function_name")).toString();
            QString HookName = A.value(QStringLiteral("hook_function_name")).toString();

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstring>\n\n");
            Code += QStringLiteral("static void* Original_") + FuncName + QStringLiteral(" = nullptr;\n\n");
            Code += QStringLiteral("void* ") + HookName + QStringLiteral("(...) {\n");
            Code += QStringLiteral("    // Your hook logic - call Original_") + FuncName + QStringLiteral(" for passthrough\n");
            Code += QStringLiteral("    return nullptr;\n}\n\n");
            Code += QStringLiteral("bool HookIAT(HMODULE TargetModule, const char* ImportModule, const char* FunctionName, void* HookFunc, void** OriginalOut) {\n");
            Code += QStringLiteral("    BYTE* Base = reinterpret_cast<BYTE*>(TargetModule);\n");
            Code += QStringLiteral("    IMAGE_DOS_HEADER* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);\n");
            Code += QStringLiteral("    IMAGE_NT_HEADERS* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Base + Dos->e_lfanew);\n");
            Code += QStringLiteral("    IMAGE_DATA_DIRECTORY ImportDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n");
            Code += QStringLiteral("    if (ImportDir.VirtualAddress == 0) return false;\n\n");
            Code += QStringLiteral("    IMAGE_IMPORT_DESCRIPTOR* Imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Base + ImportDir.VirtualAddress);\n\n");
            Code += QStringLiteral("    for (; Imports->Name != 0; ++Imports) {\n");
            Code += QStringLiteral("        const char* DllName = reinterpret_cast<const char*>(Base + Imports->Name);\n");
            Code += QStringLiteral("        if (_stricmp(DllName, ImportModule) != 0) continue;\n\n");
            Code += QStringLiteral("        IMAGE_THUNK_DATA* OrigThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(Base + Imports->OriginalFirstThunk);\n");
            Code += QStringLiteral("        IMAGE_THUNK_DATA* FirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(Base + Imports->FirstThunk);\n\n");
            Code += QStringLiteral("        for (; OrigThunk->u1.AddressOfData != 0; ++OrigThunk, ++FirstThunk) {\n");
            Code += QStringLiteral("            if (IMAGE_SNAP_BY_ORDINAL(OrigThunk->u1.Ordinal)) continue;\n");
            Code += QStringLiteral("            IMAGE_IMPORT_BY_NAME* ImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(Base + OrigThunk->u1.AddressOfData);\n");
            Code += QStringLiteral("            if (strcmp(ImportByName->Name, FunctionName) != 0) continue;\n\n");
            Code += QStringLiteral("            DWORD OldProtect;\n");
            Code += QStringLiteral("            VirtualProtect(&FirstThunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &OldProtect);\n");
            Code += QStringLiteral("            if (OriginalOut) *OriginalOut = reinterpret_cast<void*>(FirstThunk->u1.Function);\n");
            Code += QStringLiteral("            FirstThunk->u1.Function = reinterpret_cast<uintptr_t>(HookFunc);\n");
            Code += QStringLiteral("            VirtualProtect(&FirstThunk->u1.Function, sizeof(uintptr_t), OldProtect, &OldProtect);\n");
            Code += QStringLiteral("            return true;\n");
            Code += QStringLiteral("        }\n    }\n    return false;\n}\n\n");
            Code += QStringLiteral("void Install() {\n");
            Code += QStringLiteral("    HMODULE Mod = GetModuleHandleA(nullptr);\n");
            Code += QStringLiteral("    HookIAT(Mod, \"") + ModuleName + QStringLiteral("\", \"") + FuncName + QStringLiteral("\", &") + HookName + QStringLiteral(", &Original_") + FuncName + QStringLiteral(");\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("IAT hook by walking PE import directory");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_vmt_hook"),
        QStringLiteral("Generate VMT (virtual method table) hook C++ code."),
        Schema::Build({
            {QStringLiteral("vtable_address"), Schema::String(QStringLiteral("Address of vtable in hex"))},
            {QStringLiteral("index"), Schema::Integer(QStringLiteral("Index of the virtual function to hook"), 0, 1024)},
            {QStringLiteral("hook_function_name"), Schema::String(QStringLiteral("Name of your hook function"))}
        }, {QStringLiteral("vtable_address"), QStringLiteral("index"), QStringLiteral("hook_function_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString VtAddr = A.value(QStringLiteral("vtable_address")).toString();
            int Idx = A.value(QStringLiteral("index")).toInt();
            QString HookName = A.value(QStringLiteral("hook_function_name")).toString();

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstdint>\n\n");
            Code += QStringLiteral("static uintptr_t OriginalFunction = 0;\n\n");
            Code += QStringLiteral("void* __fastcall ") + HookName + QStringLiteral("(void* ThisPtr, ...) {\n");
            Code += QStringLiteral("    // Your hook logic here\n");
            Code += QStringLiteral("    // Call original: reinterpret_cast<decltype(&") + HookName + QStringLiteral(")>(OriginalFunction)(ThisPtr, ...);\n");
            Code += QStringLiteral("    return nullptr;\n}\n\n");
            Code += QStringLiteral("bool HookVMT(uintptr_t ObjectPtr, int Index, void* HookFunc, uintptr_t* OriginalOut) {\n");
            Code += QStringLiteral("    uintptr_t* VTable = *reinterpret_cast<uintptr_t**>(ObjectPtr);\n");
            Code += QStringLiteral("    uintptr_t* Entry = &VTable[Index];\n\n");
            Code += QStringLiteral("    DWORD OldProtect;\n");
            Code += QStringLiteral("    VirtualProtect(Entry, sizeof(uintptr_t), PAGE_READWRITE, &OldProtect);\n");
            Code += QStringLiteral("    if (OriginalOut) *OriginalOut = *Entry;\n");
            Code += QStringLiteral("    *Entry = reinterpret_cast<uintptr_t>(HookFunc);\n");
            Code += QStringLiteral("    VirtualProtect(Entry, sizeof(uintptr_t), OldProtect, &OldProtect);\n");
            Code += QStringLiteral("    return true;\n}\n\n");
            Code += QStringLiteral("void Install() {\n");
            Code += QStringLiteral("    uintptr_t Obj = ") + VtAddr + QStringLiteral(";\n");
            Code += QStringLiteral("    HookVMT(Obj, ") + QString::number(Idx) + QStringLiteral(", &") + HookName + QStringLiteral(", &OriginalFunction);\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("VMT hook replacing vtable entry at specified index");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_detour"),
        QStringLiteral("Generate Microsoft Detours-style hook code."),
        Schema::Build({
            {QStringLiteral("original_function"), Schema::String(QStringLiteral("Name of the original function"))},
            {QStringLiteral("hook_function"), Schema::String(QStringLiteral("Name of the hook function"))},
            {QStringLiteral("return_type"), Schema::String(QStringLiteral("Return type (default: void)"))},
            {QStringLiteral("params"), Schema::String(QStringLiteral("Parameter list (e.g. 'int a, float b')"))}
        }, {QStringLiteral("original_function"), QStringLiteral("hook_function")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString OrigFunc = A.value(QStringLiteral("original_function")).toString();
            QString HookFunc = A.value(QStringLiteral("hook_function")).toString();
            QString RetType = A.value(QStringLiteral("return_type")).toString(QStringLiteral("void"));
            QString Params = A.value(QStringLiteral("params")).toString(QStringLiteral(""));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <detours.h>\n#pragma comment(lib, \"detours.lib\")\n\n");
            Code += QStringLiteral("typedef ") + RetType + QStringLiteral(" (WINAPI* fn") + OrigFunc + QStringLiteral(")(") + Params + QStringLiteral(");\n");
            Code += QStringLiteral("static fn") + OrigFunc + QStringLiteral(" Real_") + OrigFunc + QStringLiteral(" = ") + OrigFunc + QStringLiteral(";\n\n");
            Code += RetType + QStringLiteral(" WINAPI ") + HookFunc + QStringLiteral("(") + Params + QStringLiteral(") {\n");
            Code += QStringLiteral("    // Pre-hook logic\n");
            Code += QStringLiteral("    ") + RetType + QStringLiteral(" Result = Real_") + OrigFunc + QStringLiteral("(/* forward args */);\n");
            Code += QStringLiteral("    // Post-hook logic\n");
            Code += QStringLiteral("    return Result;\n}\n\n");
            Code += QStringLiteral("BOOL InstallHook() {\n");
            Code += QStringLiteral("    DetourRestoreAfterWith();\n");
            Code += QStringLiteral("    DetourTransactionBegin();\n");
            Code += QStringLiteral("    DetourUpdateThread(GetCurrentThread());\n");
            Code += QStringLiteral("    DetourAttach(&(PVOID&)Real_") + OrigFunc + QStringLiteral(", ") + HookFunc + QStringLiteral(");\n");
            Code += QStringLiteral("    LONG Error = DetourTransactionCommit();\n");
            Code += QStringLiteral("    return Error == NO_ERROR;\n}\n\n");
            Code += QStringLiteral("BOOL RemoveHook() {\n");
            Code += QStringLiteral("    DetourTransactionBegin();\n");
            Code += QStringLiteral("    DetourUpdateThread(GetCurrentThread());\n");
            Code += QStringLiteral("    DetourDetach(&(PVOID&)Real_") + OrigFunc + QStringLiteral(", ") + HookFunc + QStringLiteral(");\n");
            Code += QStringLiteral("    LONG Error = DetourTransactionCommit();\n");
            Code += QStringLiteral("    return Error == NO_ERROR;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Microsoft Detours hook with transaction-based install/remove");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_trampoline"),
        QStringLiteral("Generate trampoline hook with stolen bytes and jump-back stub."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Target address in hex"))},
            {QStringLiteral("num_stolen_bytes"), Schema::Integer(QStringLiteral("Number of bytes to steal (must be >= 14 for x64)"), 5, 64)},
            {QStringLiteral("hook_function_name"), Schema::String(QStringLiteral("Hook function name"))}
        }, {QStringLiteral("address"), QStringLiteral("num_stolen_bytes"), QStringLiteral("hook_function_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Addr = A.value(QStringLiteral("address")).toString();
            int StolenBytes = A.value(QStringLiteral("num_stolen_bytes")).toInt(14);
            QString HookName = A.value(QStringLiteral("hook_function_name")).toString();

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstring>\n\n");
            Code += QStringLiteral("static constexpr int STOLEN_BYTES = ") + QString::number(StolenBytes) + QStringLiteral(";\n");
            Code += QStringLiteral("static constexpr int JMP_SIZE = 14;\n\n");
            Code += QStringLiteral("static BYTE* TrampolineBuffer = nullptr;\n");
            Code += QStringLiteral("static BYTE OriginalBytes[STOLEN_BYTES];\n");
            Code += QStringLiteral("static uintptr_t TargetAddr = ") + Addr + QStringLiteral(";\n\n");
            Code += QStringLiteral("void ") + HookName + QStringLiteral("() {\n");
            Code += QStringLiteral("    // Hook logic here\n}\n\n");
            Code += QStringLiteral("typedef void (*TrampolineFunc)();\n");
            Code += QStringLiteral("static TrampolineFunc CallOriginal = nullptr;\n\n");
            Code += QStringLiteral("bool Install() {\n");
            Code += QStringLiteral("    TrampolineBuffer = reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));\n");
            Code += QStringLiteral("    if (!TrampolineBuffer) return false;\n\n");
            Code += QStringLiteral("    memcpy(OriginalBytes, reinterpret_cast<void*>(TargetAddr), STOLEN_BYTES);\n");
            Code += QStringLiteral("    memcpy(TrampolineBuffer, OriginalBytes, STOLEN_BYTES);\n\n");
            Code += QStringLiteral("    BYTE JmpBack[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };\n");
            Code += QStringLiteral("    uintptr_t RetAddr = TargetAddr + STOLEN_BYTES;\n");
            Code += QStringLiteral("    memcpy(JmpBack + 6, &RetAddr, 8);\n");
            Code += QStringLiteral("    memcpy(TrampolineBuffer + STOLEN_BYTES, JmpBack, 14);\n");
            Code += QStringLiteral("    CallOriginal = reinterpret_cast<TrampolineFunc>(TrampolineBuffer);\n\n");
            Code += QStringLiteral("    DWORD OldProtect;\n");
            Code += QStringLiteral("    VirtualProtect(reinterpret_cast<void*>(TargetAddr), STOLEN_BYTES, PAGE_EXECUTE_READWRITE, &OldProtect);\n");
            Code += QStringLiteral("    memset(reinterpret_cast<void*>(TargetAddr), 0x90, STOLEN_BYTES);\n");
            Code += QStringLiteral("    BYTE JmpHook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };\n");
            Code += QStringLiteral("    uintptr_t HookAddr = reinterpret_cast<uintptr_t>(&") + HookName + QStringLiteral(");\n");
            Code += QStringLiteral("    memcpy(JmpHook + 6, &HookAddr, 8);\n");
            Code += QStringLiteral("    memcpy(reinterpret_cast<void*>(TargetAddr), JmpHook, 14);\n");
            Code += QStringLiteral("    VirtualProtect(reinterpret_cast<void*>(TargetAddr), STOLEN_BYTES, OldProtect, &OldProtect);\n");
            Code += QStringLiteral("    return true;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Trampoline hook with stolen bytes, callable original via trampoline buffer");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_ida_signature"),
        QStringLiteral("Read bytes at address, generate IDA-style signature with wildcard relative offsets."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address to read from in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes for signature"), 1, 256)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();

            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(32);

            QByteArray Buffer(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buffer.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
                return Schema::Err(QStringLiteral("Capstone init failed"));
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

            cs_insn* Insns = nullptr;
            size_t Count = cs_disasm(Handle, reinterpret_cast<const uint8_t*>(Buffer.constData()),
                                     static_cast<size_t>(Size), Addr, 0, &Insns);

            QString Sig;
            for (size_t I = 0; I < Count; ++I) {
                cs_detail* Detail = Insns[I].detail;
                bool HasRelOffset = false;
                int RelOffsetStart = -1;
                int RelOffsetLen = 0;

                if (Detail) {
                    for (uint8_t G = 0; G < Detail->groups_count; ++G) {
                        if (Detail->groups[G] == CS_GRP_CALL || Detail->groups[G] == CS_GRP_JUMP) {
                            if (Insns[I].size > 1) {
                                HasRelOffset = true;
                                if (Insns[I].bytes[0] == 0xE8 || Insns[I].bytes[0] == 0xE9) {
                                    RelOffsetStart = 1;
                                    RelOffsetLen = 4;
                                } else if (Insns[I].bytes[0] == 0x0F &&
                                           (Insns[I].bytes[1] >= 0x80 && Insns[I].bytes[1] <= 0x8F)) {
                                    RelOffsetStart = 2;
                                    RelOffsetLen = 4;
                                } else if (Insns[I].size == 2) {
                                    RelOffsetStart = 1;
                                    RelOffsetLen = 1;
                                }
                            }
                            break;
                        }
                    }

                    if (!HasRelOffset) {
                        for (int X = 0; X < Detail->x86.op_count; ++X) {
                            if (Detail->x86.operands[X].type == X86_OP_MEM &&
                                Detail->x86.operands[X].mem.base == X86_REG_RIP) {
                                HasRelOffset = true;
                                RelOffsetStart = static_cast<int>(Insns[I].size) - 4;
                                RelOffsetLen = 4;
                                break;
                            }
                        }
                    }
                }

                for (uint16_t B = 0; B < Insns[I].size; ++B) {
                    if (!Sig.isEmpty()) Sig += QStringLiteral(" ");
                    if (HasRelOffset && RelOffsetStart >= 0 &&
                        B >= static_cast<uint16_t>(RelOffsetStart) &&
                        B < static_cast<uint16_t>(RelOffsetStart + RelOffsetLen)) {
                        Sig += QStringLiteral("?");
                    } else {
                        Sig += QString::number(Insns[I].bytes[B], 16).toUpper().rightJustified(2, '0');
                    }
                }
            }

            if (Count > 0) cs_free(Insns, Count);
            cs_close(&Handle);

            QJsonObject Result;
            Result[QStringLiteral("signature")] = Sig;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("code")] = QStringLiteral("// IDA Signature: \"") + Sig + QStringLiteral("\"");
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("IDA-style signature with wildcarded relative offsets");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_yara_rule"),
        QStringLiteral("Read bytes at address, generate a YARA rule."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Bytes to include"), 1, 1024)},
            {QStringLiteral("rule_name"), Schema::String(QStringLiteral("Name for the YARA rule"))}
        }, {QStringLiteral("address"), QStringLiteral("size"), QStringLiteral("rule_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();

            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(64);
            QString RuleName = A.value(QStringLiteral("rule_name")).toString();

            QByteArray Buffer(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buffer.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));

            QString HexStr;
            for (int I = 0; I < Buffer.size(); ++I) {
                if (I > 0 && I % 16 == 0) HexStr += QStringLiteral("\n            ");
                else if (I > 0) HexStr += QStringLiteral(" ");
                HexStr += QString::number(static_cast<uint8_t>(Buffer[I]), 16).toUpper().rightJustified(2, '0');
            }

            QString Code;
            Code += QStringLiteral("rule ") + RuleName + QStringLiteral(" {\n");
            Code += QStringLiteral("    meta:\n");
            Code += QStringLiteral("        description = \"Generated by Fidra from ") + Schema::FormatAddress(Addr) + QStringLiteral("\"\n");
            Code += QStringLiteral("        date = \"2024-01-01\"\n\n");
            Code += QStringLiteral("    strings:\n");
            Code += QStringLiteral("        $pattern = { ") + HexStr + QStringLiteral(" }\n\n");
            Code += QStringLiteral("    condition:\n");
            Code += QStringLiteral("        $pattern\n");
            Code += QStringLiteral("}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("yara");
            Result[QStringLiteral("description")] = QStringLiteral("YARA rule with hex pattern from memory");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_struct_def"),
        QStringLiteral("Generate C++ struct definition with proper padding from field list."),
        Schema::Build({
            {QStringLiteral("struct_name"), Schema::String(QStringLiteral("Name of the struct"))},
            {QStringLiteral("fields"), Schema::Array(QStringLiteral("Array of {name, type, offset} objects"))}
        }, {QStringLiteral("struct_name"), QStringLiteral("fields")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString StructName = A.value(QStringLiteral("struct_name")).toString();
            QJsonArray Fields = A.value(QStringLiteral("fields")).toArray();

            struct FieldInfo {
                QString Name;
                QString Type;
                int Offset;
            };
            QVector<FieldInfo> SortedFields;
            for (const auto& F : Fields) {
                QJsonObject Fobj = F.toObject();
                FieldInfo Fi;
                Fi.Name = Fobj.value(QStringLiteral("name")).toString();
                Fi.Type = Fobj.value(QStringLiteral("type")).toString(QStringLiteral("uint8_t"));
                Fi.Offset = Fobj.value(QStringLiteral("offset")).toInt();
                SortedFields.append(Fi);
            }
            std::sort(SortedFields.begin(), SortedFields.end(), [](const FieldInfo& X, const FieldInfo& Y) {
                return X.Offset < Y.Offset;
            });

            auto TypeSize = [](const QString& T) -> int {
                if (T == QStringLiteral("uint8_t") || T == QStringLiteral("int8_t") || T == QStringLiteral("char") || T == QStringLiteral("BYTE") || T == QStringLiteral("bool")) return 1;
                if (T == QStringLiteral("uint16_t") || T == QStringLiteral("int16_t") || T == QStringLiteral("short") || T == QStringLiteral("WORD")) return 2;
                if (T == QStringLiteral("uint32_t") || T == QStringLiteral("int32_t") || T == QStringLiteral("int") || T == QStringLiteral("DWORD") || T == QStringLiteral("float")) return 4;
                if (T == QStringLiteral("uint64_t") || T == QStringLiteral("int64_t") || T == QStringLiteral("double") || T == QStringLiteral("QWORD") || T == QStringLiteral("uintptr_t") || T == QStringLiteral("void*")) return 8;
                return 4;
            };

            QString Code;
            Code += QStringLiteral("#pragma pack(push, 1)\nstruct ") + StructName + QStringLiteral(" {\n");

            int CurrentOffset = 0;
            int PadIndex = 0;
            for (const auto& Fi : SortedFields) {
                if (Fi.Offset > CurrentOffset) {
                    int Gap = Fi.Offset - CurrentOffset;
                    Code += QStringLiteral("    uint8_t _pad") + QString::number(PadIndex++) + QStringLiteral("[") + QString::number(Gap) + QStringLiteral("];\n");
                }
                Code += QStringLiteral("    ") + Fi.Type + QStringLiteral(" ") + Fi.Name + QStringLiteral(";\n");
                CurrentOffset = Fi.Offset + TypeSize(Fi.Type);
            }

            Code += QStringLiteral("};\n#pragma pack(pop)\n");
            Code += QStringLiteral("\nstatic_assert(offsetof(") + StructName + QStringLiteral(", ");
            if (!SortedFields.isEmpty()) {
                Code += SortedFields.last().Name + QStringLiteral(") == ") + QString::number(SortedFields.last().Offset);
            } else {
                Code += QStringLiteral("/* no fields */");
            }
            Code += QStringLiteral(");\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Packed struct with padding bytes to match specified offsets");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_class_def"),
        QStringLiteral("Generate C++ class definition with virtual functions and member fields."),
        Schema::Build({
            {QStringLiteral("class_name"), Schema::String(QStringLiteral("Class name"))},
            {QStringLiteral("vtable_count"), Schema::Integer(QStringLiteral("Number of virtual functions"), 0, 512)},
            {QStringLiteral("fields"), Schema::Array(QStringLiteral("Array of {name, type, offset}"))}
        }, {QStringLiteral("class_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString ClassName = A.value(QStringLiteral("class_name")).toString();
            int VtCount = A.value(QStringLiteral("vtable_count")).toInt(0);
            QJsonArray Fields = A.value(QStringLiteral("fields")).toArray();

            QString Code;
            Code += QStringLiteral("class ") + ClassName + QStringLiteral(" {\npublic:\n");

            for (int I = 0; I < VtCount; ++I) {
                Code += QStringLiteral("    virtual void VFunc") + QString::number(I) + QStringLiteral("();\n");
            }

            if (VtCount > 0) Code += QStringLiteral("\n");

            for (int FieldIdx = 0; FieldIdx < Fields.size(); ++FieldIdx) {
                QJsonObject Fobj = Fields[FieldIdx].toObject();
                QString FName = Fobj.value(QStringLiteral("name")).toString(QStringLiteral("Field") + QString::number(FieldIdx));
                QString FType = Fobj.value(QStringLiteral("type")).toString(QStringLiteral("int"));
                Code += QStringLiteral("    ") + FType + QStringLiteral(" ") + FName + QStringLiteral(";\n");
            }

            Code += QStringLiteral("};\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("C++ class with virtual functions and member fields");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_sdk_header"),
        QStringLiteral("Generate SDK header with function pointer typedefs from module exports."),
        Schema::Build({
            {QStringLiteral("module_name"), Schema::String(QStringLiteral("Module to generate SDK for"))},
            {QStringLiteral("header_guard"), Schema::String(QStringLiteral("Header guard name (optional)"))}
        }, {QStringLiteral("module_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString ModuleName = A.value(QStringLiteral("module_name")).toString();
            QString Guard = A.value(QStringLiteral("header_guard")).toString(
                ModuleName.toUpper().replace('.', '_') + QStringLiteral("_SDK_H"));

            QString Code;
            Code += QStringLiteral("#pragma once\n#ifndef ") + Guard + QStringLiteral("\n#define ") + Guard + QStringLiteral("\n\n");
            Code += QStringLiteral("#include <Windows.h>\n\n");
            Code += QStringLiteral("namespace ") + ModuleName.section('.', 0, 0) + QStringLiteral("_SDK {\n\n");
            Code += QStringLiteral("static HMODULE ModuleHandle = nullptr;\n\n");
            Code += QStringLiteral("inline bool Initialize() {\n");
            Code += QStringLiteral("    ModuleHandle = GetModuleHandleA(\"") + ModuleName + QStringLiteral("\");\n");
            Code += QStringLiteral("    if (!ModuleHandle) ModuleHandle = LoadLibraryA(\"") + ModuleName + QStringLiteral("\");\n");
            Code += QStringLiteral("    return ModuleHandle != nullptr;\n}\n\n");

            if (CoreRef && CoreRef->IsAttached()) {
                QJsonObject ExportArgs;
                ExportArgs[QStringLiteral("module")] = ModuleName;
                QJsonValue ExportResult = CallTool(QStringLiteral("get_exports"), ExportArgs);
                if (ExportResult.isObject()) {
                    QJsonArray Exports = ExportResult.toObject().value(QStringLiteral("exports")).toArray();
                    for (const auto& E : Exports) {
                        QString FnName = E.toObject().value(QStringLiteral("name")).toString();
                        if (FnName.isEmpty()) continue;
                        Code += QStringLiteral("typedef void* (*fn_") + FnName + QStringLiteral(")();\n");
                        Code += QStringLiteral("inline fn_") + FnName + QStringLiteral(" p") + FnName + QStringLiteral(" = nullptr;\n\n");
                    }
                    Code += QStringLiteral("\ninline void ResolveAll() {\n");
                    for (const auto& E : Exports) {
                        QString FnName = E.toObject().value(QStringLiteral("name")).toString();
                        if (FnName.isEmpty()) continue;
                        Code += QStringLiteral("    p") + FnName + QStringLiteral(" = reinterpret_cast<fn_") + FnName + QStringLiteral(">(GetProcAddress(ModuleHandle, \"") + FnName + QStringLiteral("\"));\n");
                    }
                    Code += QStringLiteral("}\n\n");
                }
            } else {
                Code += QStringLiteral("// Attach to a process with the module loaded to auto-generate export typedefs\n\n");
                Code += QStringLiteral("template<typename T>\ninline T GetFunction(const char* Name) {\n");
                Code += QStringLiteral("    return reinterpret_cast<T>(GetProcAddress(ModuleHandle, Name));\n}\n\n");
            }

            Code += QStringLiteral("} // namespace\n\n#endif // ") + Guard + QStringLiteral("\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("SDK header with GetProcAddress resolution for all exports");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_ida_script"),
        QStringLiteral("Generate IDA Python script for common actions."),
        Schema::Build({
            {QStringLiteral("action"), Schema::StringEnum(QStringLiteral("Action type"),
                {QStringLiteral("rename_function"), QStringLiteral("set_type"), QStringLiteral("add_comment"),
                 QStringLiteral("create_struct"), QStringLiteral("set_name"), QStringLiteral("make_code")})},
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex (if applicable)"))},
            {QStringLiteral("name"), Schema::String(QStringLiteral("Name or value for the action"))},
            {QStringLiteral("comment"), Schema::String(QStringLiteral("Comment text (for add_comment)"))}
        }, {QStringLiteral("action")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Action = A.value(QStringLiteral("action")).toString();
            QString Addr = A.value(QStringLiteral("address")).toString(QStringLiteral("0x0"));
            QString Name = A.value(QStringLiteral("name")).toString(QStringLiteral("unnamed"));
            QString Comment = A.value(QStringLiteral("comment")).toString();

            QString Code;
            Code += QStringLiteral("import idaapi\nimport idc\nimport ida_name\nimport ida_struct\n\n");

            if (Action == QStringLiteral("rename_function")) {
                Code += QStringLiteral("addr = ") + Addr + QStringLiteral("\n");
                Code += QStringLiteral("ida_name.set_name(addr, \"") + Name + QStringLiteral("\", ida_name.SN_FORCE)\n");
                Code += QStringLiteral("print(f\"Renamed function at {addr:#x} to ") + Name + QStringLiteral("\")\n");
            } else if (Action == QStringLiteral("set_type")) {
                Code += QStringLiteral("addr = ") + Addr + QStringLiteral("\n");
                Code += QStringLiteral("idc.SetType(addr, \"") + Name + QStringLiteral("\")\n");
                Code += QStringLiteral("print(f\"Set type at {addr:#x}\")\n");
            } else if (Action == QStringLiteral("add_comment")) {
                Code += QStringLiteral("addr = ") + Addr + QStringLiteral("\n");
                Code += QStringLiteral("idc.set_cmt(addr, \"") + Comment + QStringLiteral("\", 0)\n");
                Code += QStringLiteral("print(f\"Added comment at {addr:#x}\")\n");
            } else if (Action == QStringLiteral("create_struct")) {
                Code += QStringLiteral("sid = ida_struct.add_struc(-1, \"") + Name + QStringLiteral("\", False)\n");
                Code += QStringLiteral("sptr = ida_struct.get_struc(sid)\n");
                Code += QStringLiteral("ida_struct.add_struc_member(sptr, \"field_0\", 0, idc.FF_DWORD, None, 4)\n");
                Code += QStringLiteral("ida_struct.add_struc_member(sptr, \"field_4\", 4, idc.FF_DWORD, None, 4)\n");
                Code += QStringLiteral("print(f\"Created struct ") + Name + QStringLiteral("\")\n");
            } else if (Action == QStringLiteral("set_name")) {
                Code += QStringLiteral("addr = ") + Addr + QStringLiteral("\n");
                Code += QStringLiteral("ida_name.set_name(addr, \"") + Name + QStringLiteral("\", ida_name.SN_NOCHECK)\n");
            } else if (Action == QStringLiteral("make_code")) {
                Code += QStringLiteral("addr = ") + Addr + QStringLiteral("\n");
                Code += QStringLiteral("idc.create_insn(addr)\nprint(f\"Made code at {addr:#x}\")\n");
            }

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("python");
            Result[QStringLiteral("description")] = QStringLiteral("IDA Python script for ") + Action;
            return Result;
        });

    RegisterTool(QStringLiteral("generate_ghidra_script"),
        QStringLiteral("Generate Ghidra script (Java) for common RE actions."),
        Schema::Build({
            {QStringLiteral("action"), Schema::StringEnum(QStringLiteral("Action type"),
                {QStringLiteral("rename_function"), QStringLiteral("add_comment"), QStringLiteral("set_type"),
                 QStringLiteral("list_functions")})},
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))},
            {QStringLiteral("name"), Schema::String(QStringLiteral("Name or value"))},
            {QStringLiteral("comment"), Schema::String(QStringLiteral("Comment text"))}
        }, {QStringLiteral("action")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Action = A.value(QStringLiteral("action")).toString();
            QString Addr = A.value(QStringLiteral("address")).toString(QStringLiteral("0x0"));
            QString Name = A.value(QStringLiteral("name")).toString();
            QString Comment = A.value(QStringLiteral("comment")).toString();

            QString Code;
            Code += QStringLiteral("// Ghidra Script - ") + Action + QStringLiteral("\n");
            Code += QStringLiteral("// @category Fidra\n\n");
            Code += QStringLiteral("import ghidra.program.model.address.AddressFactory;\nimport ghidra.program.model.symbol.SourceType;\n\n");

            if (Action == QStringLiteral("rename_function")) {
                Code += QStringLiteral("var addr = currentProgram.getAddressFactory().getAddress(\"") + Addr + QStringLiteral("\");\n");
                Code += QStringLiteral("var func = getFunctionAt(addr);\n");
                Code += QStringLiteral("if (func != null) {\n");
                Code += QStringLiteral("    func.setName(\"") + Name + QStringLiteral("\", SourceType.USER_DEFINED);\n");
                Code += QStringLiteral("    println(\"Renamed to ") + Name + QStringLiteral("\");\n} else {\n");
                Code += QStringLiteral("    println(\"No function at address\");\n}\n");
            } else if (Action == QStringLiteral("add_comment")) {
                Code += QStringLiteral("var addr = currentProgram.getAddressFactory().getAddress(\"") + Addr + QStringLiteral("\");\n");
                Code += QStringLiteral("var listing = currentProgram.getListing();\n");
                Code += QStringLiteral("var cu = listing.getCodeUnitAt(addr);\n");
                Code += QStringLiteral("if (cu != null) {\n");
                Code += QStringLiteral("    cu.setComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, \"") + Comment + QStringLiteral("\");\n}\n");
            } else if (Action == QStringLiteral("list_functions")) {
                Code += QStringLiteral("var fm = currentProgram.getFunctionManager();\n");
                Code += QStringLiteral("var iter = fm.getFunctions(true);\n");
                Code += QStringLiteral("while (iter.hasNext()) {\n");
                Code += QStringLiteral("    var func = iter.next();\n");
                Code += QStringLiteral("    println(func.getEntryPoint() + \" \" + func.getName());\n}\n");
            } else {
                Code += QStringLiteral("println(\"Action: ") + Action + QStringLiteral("\");\n");
            }

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("java");
            Result[QStringLiteral("description")] = QStringLiteral("Ghidra script for ") + Action;
            return Result;
        });

    RegisterTool(QStringLiteral("generate_frida_script"),
        QStringLiteral("Generate Frida JavaScript hook script."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (e.g. game.exe)"))},
            {QStringLiteral("function_name"), Schema::String(QStringLiteral("Export name to hook (optional)"))},
            {QStringLiteral("offset"), Schema::String(QStringLiteral("Offset from module base in hex (if no export name)"))},
            {QStringLiteral("num_args"), Schema::Integer(QStringLiteral("Number of arguments to log"), 0, 16)}
        }, {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Module = A.value(QStringLiteral("module")).toString();
            QString FuncName = A.value(QStringLiteral("function_name")).toString();
            QString Offset = A.value(QStringLiteral("offset")).toString();
            int NumArgs = A.value(QStringLiteral("num_args")).toInt(4);

            QString Code;
            Code += QStringLiteral("'use strict';\n\n");

            if (!FuncName.isEmpty()) {
                Code += QStringLiteral("const targetFunc = Module.findExportByName('") + Module + QStringLiteral("', '") + FuncName + QStringLiteral("');\n");
            } else if (!Offset.isEmpty()) {
                Code += QStringLiteral("const baseAddr = Module.findBaseAddress('") + Module + QStringLiteral("');\n");
                Code += QStringLiteral("const targetFunc = baseAddr.add(") + Offset + QStringLiteral(");\n");
            } else {
                Code += QStringLiteral("const baseAddr = Module.findBaseAddress('") + Module + QStringLiteral("');\n");
                Code += QStringLiteral("const targetFunc = baseAddr;\n");
            }

            Code += QStringLiteral("\nconsole.log('[*] Hooking at: ' + targetFunc);\n\n");
            Code += QStringLiteral("Interceptor.attach(targetFunc, {\n");
            Code += QStringLiteral("    onEnter: function(args) {\n");
            Code += QStringLiteral("        console.log('[+] Called!');\n");
            for (int I = 0; I < NumArgs; ++I) {
                Code += QStringLiteral("        console.log('  arg") + QString::number(I) + QStringLiteral(": ' + args[") + QString::number(I) + QStringLiteral("]);\n");
            }
            Code += QStringLiteral("        this.retAddr = this.returnAddress;\n");
            Code += QStringLiteral("    },\n");
            Code += QStringLiteral("    onLeave: function(retval) {\n");
            Code += QStringLiteral("        console.log('  retval: ' + retval);\n");
            Code += QStringLiteral("    }\n});\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("javascript");
            Result[QStringLiteral("description")] = QStringLiteral("Frida Interceptor.attach hook script");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_driver_template"),
        QStringLiteral("Generate complete KMDF/WDM kernel driver template."),
        Schema::Build({
            {QStringLiteral("driver_name"), Schema::String(QStringLiteral("Driver name"))},
            {QStringLiteral("device_name"), Schema::String(QStringLiteral("Device name (e.g. MyDriver)"))},
            {QStringLiteral("include_memory_rw"), Schema::Boolean(QStringLiteral("Include memory read/write IOCTL handlers"))}
        }, {QStringLiteral("driver_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString DriverName = A.value(QStringLiteral("driver_name")).toString();
            QString DeviceName = A.value(QStringLiteral("device_name")).toString(DriverName);
            bool IncludeMemRw = A.value(QStringLiteral("include_memory_rw")).toBool(true);

            QString Code;
            Code += QStringLiteral("#include <ntddk.h>\n\n");
            Code += QStringLiteral("#define DEVICE_NAME L\"\\\\Device\\\\") + DeviceName + QStringLiteral("\"\n");
            Code += QStringLiteral("#define SYMLINK_NAME L\"\\\\DosDevices\\\\") + DeviceName + QStringLiteral("\"\n\n");

            if (IncludeMemRw) {
                Code += QStringLiteral("#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)\n");
                Code += QStringLiteral("#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)\n\n");
                Code += QStringLiteral("typedef struct _MEMORY_REQUEST {\n");
                Code += QStringLiteral("    ULONG ProcessId;\n");
                Code += QStringLiteral("    PVOID Address;\n");
                Code += QStringLiteral("    PVOID Buffer;\n");
                Code += QStringLiteral("    SIZE_T Size;\n");
                Code += QStringLiteral("} MEMORY_REQUEST, *PMEMORY_REQUEST;\n\n");
            }

            Code += QStringLiteral("PDEVICE_OBJECT DeviceObject = NULL;\n\n");
            Code += QStringLiteral("VOID DriverUnload(PDRIVER_OBJECT DriverObject) {\n");
            Code += QStringLiteral("    UNICODE_STRING SymLink;\n");
            Code += QStringLiteral("    RtlInitUnicodeString(&SymLink, SYMLINK_NAME);\n");
            Code += QStringLiteral("    IoDeleteSymbolicLink(&SymLink);\n");
            Code += QStringLiteral("    if (DriverObject->DeviceObject)\n");
            Code += QStringLiteral("        IoDeleteDevice(DriverObject->DeviceObject);\n");
            Code += QStringLiteral("    DbgPrint(\"[") + DriverName + QStringLiteral("] Unloaded\\n\");\n}\n\n");
            Code += QStringLiteral("NTSTATUS IrpCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp) {\n");
            Code += QStringLiteral("    UNREFERENCED_PARAMETER(DevObj);\n");
            Code += QStringLiteral("    Irp->IoStatus.Status = STATUS_SUCCESS;\n");
            Code += QStringLiteral("    Irp->IoStatus.Information = 0;\n");
            Code += QStringLiteral("    IoCompleteRequest(Irp, IO_NO_INCREMENT);\n");
            Code += QStringLiteral("    return STATUS_SUCCESS;\n}\n\n");

            if (IncludeMemRw) {
                Code += QStringLiteral("NTSTATUS ReadProcessMemory(ULONG Pid, PVOID Addr, PVOID Out, SIZE_T Size) {\n");
                Code += QStringLiteral("    PEPROCESS Process;\n");
                Code += QStringLiteral("    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);\n");
                Code += QStringLiteral("    if (!NT_SUCCESS(Status)) return Status;\n");
                Code += QStringLiteral("    SIZE_T BytesCopied = 0;\n");
                Code += QStringLiteral("    Status = MmCopyVirtualMemory(Process, Addr, PsGetCurrentProcess(), Out, Size, KernelMode, &BytesCopied);\n");
                Code += QStringLiteral("    ObDereferenceObject(Process);\n");
                Code += QStringLiteral("    return Status;\n}\n\n");
                Code += QStringLiteral("NTSTATUS WriteProcessMemory(ULONG Pid, PVOID Addr, PVOID Src, SIZE_T Size) {\n");
                Code += QStringLiteral("    PEPROCESS Process;\n");
                Code += QStringLiteral("    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);\n");
                Code += QStringLiteral("    if (!NT_SUCCESS(Status)) return Status;\n");
                Code += QStringLiteral("    SIZE_T BytesCopied = 0;\n");
                Code += QStringLiteral("    Status = MmCopyVirtualMemory(PsGetCurrentProcess(), Src, Process, Addr, Size, KernelMode, &BytesCopied);\n");
                Code += QStringLiteral("    ObDereferenceObject(Process);\n");
                Code += QStringLiteral("    return Status;\n}\n\n");
            }

            Code += QStringLiteral("NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {\n");
            Code += QStringLiteral("    UNREFERENCED_PARAMETER(DevObj);\n");
            Code += QStringLiteral("    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);\n");
            Code += QStringLiteral("    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;\n");
            Code += QStringLiteral("    ULONG BytesReturned = 0;\n\n");
            Code += QStringLiteral("    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {\n");

            if (IncludeMemRw) {
                Code += QStringLiteral("    case IOCTL_READ_MEMORY: {\n");
                Code += QStringLiteral("        PMEMORY_REQUEST Req = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;\n");
                Code += QStringLiteral("        Status = ReadProcessMemory(Req->ProcessId, Req->Address, Req->Buffer, Req->Size);\n");
                Code += QStringLiteral("        BytesReturned = sizeof(MEMORY_REQUEST);\n");
                Code += QStringLiteral("        break;\n    }\n");
                Code += QStringLiteral("    case IOCTL_WRITE_MEMORY: {\n");
                Code += QStringLiteral("        PMEMORY_REQUEST Req = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;\n");
                Code += QStringLiteral("        Status = WriteProcessMemory(Req->ProcessId, Req->Address, Req->Buffer, Req->Size);\n");
                Code += QStringLiteral("        BytesReturned = sizeof(MEMORY_REQUEST);\n");
                Code += QStringLiteral("        break;\n    }\n");
            }

            Code += QStringLiteral("    default:\n        Status = STATUS_INVALID_DEVICE_REQUEST;\n        break;\n    }\n\n");
            Code += QStringLiteral("    Irp->IoStatus.Status = Status;\n");
            Code += QStringLiteral("    Irp->IoStatus.Information = BytesReturned;\n");
            Code += QStringLiteral("    IoCompleteRequest(Irp, IO_NO_INCREMENT);\n");
            Code += QStringLiteral("    return Status;\n}\n\n");
            Code += QStringLiteral("extern \"C\" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {\n");
            Code += QStringLiteral("    UNREFERENCED_PARAMETER(RegistryPath);\n\n");
            Code += QStringLiteral("    DriverObject->DriverUnload = DriverUnload;\n");
            Code += QStringLiteral("    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateClose;\n");
            Code += QStringLiteral("    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateClose;\n");
            Code += QStringLiteral("    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;\n\n");
            Code += QStringLiteral("    UNICODE_STRING DevName, SymLink;\n");
            Code += QStringLiteral("    RtlInitUnicodeString(&DevName, DEVICE_NAME);\n");
            Code += QStringLiteral("    RtlInitUnicodeString(&SymLink, SYMLINK_NAME);\n\n");
            Code += QStringLiteral("    NTSTATUS Status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);\n");
            Code += QStringLiteral("    if (!NT_SUCCESS(Status)) return Status;\n\n");
            Code += QStringLiteral("    Status = IoCreateSymbolicLink(&SymLink, &DevName);\n");
            Code += QStringLiteral("    if (!NT_SUCCESS(Status)) {\n");
            Code += QStringLiteral("        IoDeleteDevice(DeviceObject);\n        return Status;\n    }\n\n");
            Code += QStringLiteral("    DbgPrint(\"[") + DriverName + QStringLiteral("] Loaded\\n\");\n");
            Code += QStringLiteral("    return STATUS_SUCCESS;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Complete WDM kernel driver with device creation, symlink, and IOCTL dispatch");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_ioctl_handler"),
        QStringLiteral("Generate IOCTL dispatch handler with switch-case for custom codes."),
        Schema::Build({
            {QStringLiteral("ioctls"), Schema::Array(QStringLiteral("Array of {code_hex, name, description} objects"))},
            {QStringLiteral("device_type"), Schema::String(QStringLiteral("Device type constant (default FILE_DEVICE_UNKNOWN)"))}
        }, {QStringLiteral("ioctls")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QJsonArray Ioctls = A.value(QStringLiteral("ioctls")).toArray();
            QString DevType = A.value(QStringLiteral("device_type")).toString(QStringLiteral("FILE_DEVICE_UNKNOWN"));

            QString Code;
            Code += QStringLiteral("#include <ntddk.h>\n\n");

            for (const auto& Ioctl : Ioctls) {
                QJsonObject Obj = Ioctl.toObject();
                QString IName = Obj.value(QStringLiteral("name")).toString();
                QString ICode = Obj.value(QStringLiteral("code_hex")).toString();
                Code += QStringLiteral("#define ") + IName + QStringLiteral(" CTL_CODE(") + DevType + QStringLiteral(", ") + ICode + QStringLiteral(", METHOD_BUFFERED, FILE_SPECIAL_ACCESS)\n");
            }

            Code += QStringLiteral("\nNTSTATUS DeviceIoControl(PDEVICE_OBJECT DevObj, PIRP Irp) {\n");
            Code += QStringLiteral("    UNREFERENCED_PARAMETER(DevObj);\n");
            Code += QStringLiteral("    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);\n");
            Code += QStringLiteral("    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;\n");
            Code += QStringLiteral("    ULONG InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;\n");
            Code += QStringLiteral("    ULONG OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;\n");
            Code += QStringLiteral("    NTSTATUS Status = STATUS_SUCCESS;\n");
            Code += QStringLiteral("    ULONG BytesReturned = 0;\n\n");
            Code += QStringLiteral("    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {\n");

            for (const auto& Ioctl : Ioctls) {
                QJsonObject Obj = Ioctl.toObject();
                QString IName = Obj.value(QStringLiteral("name")).toString();
                QString Desc = Obj.value(QStringLiteral("description")).toString();
                Code += QStringLiteral("    case ") + IName + QStringLiteral(": {\n");
                Code += QStringLiteral("        // ") + Desc + QStringLiteral("\n");
                Code += QStringLiteral("        Status = STATUS_SUCCESS;\n");
                Code += QStringLiteral("        break;\n    }\n");
            }

            Code += QStringLiteral("    default:\n        Status = STATUS_INVALID_DEVICE_REQUEST;\n        break;\n    }\n\n");
            Code += QStringLiteral("    Irp->IoStatus.Status = Status;\n");
            Code += QStringLiteral("    Irp->IoStatus.Information = BytesReturned;\n");
            Code += QStringLiteral("    IoCompleteRequest(Irp, IO_NO_INCREMENT);\n");
            Code += QStringLiteral("    return Status;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("IOCTL dispatch handler for ") + QString::number(Ioctls.size()) + QStringLiteral(" IOCTLs");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_shellcode_x64"),
        QStringLiteral("Generate x64 shellcode hex bytes for common payloads."),
        Schema::Build({
            {QStringLiteral("payload"), Schema::StringEnum(QStringLiteral("Payload type"),
                {QStringLiteral("exec_calc"), QStringLiteral("messagebox"), QStringLiteral("infinite_loop"),
                 QStringLiteral("breakpoint"), QStringLiteral("nop_sled")})}
        }, {QStringLiteral("payload")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Payload = A.value(QStringLiteral("payload")).toString();

            QString HexBytes;
            QString Desc;

            if (Payload == QStringLiteral("exec_calc")) {
                HexBytes = QStringLiteral(
                    "48 31 C9 48 81 E9 DD FF FF FF 48 8D 05 EF FF FF FF "
                    "48 BB 58 64 C3 4D 90 7B 12 10 48 31 58 27 48 2D "
                    "F8 FF FF FF E2 F4 A4 2C 40 A9 60 93 D2 58 12 0F "
                    "AC 15 D8 2B 41 B1 0E 2C F2 1F D1 33 99 42 18 2C "
                    "F2 1F 91 33 99 42 58 3C 8C 0E 04 F3 33 13 69 12 "
                    "6D 2F 35 C8 33 82 D2");
                Desc = QStringLiteral("x64 calc.exe shellcode (WinExec)");
            } else if (Payload == QStringLiteral("messagebox")) {
                HexBytes = QStringLiteral(
                    "48 83 EC 28 48 83 E4 F0 48 31 C9 48 31 D2 4D 31 "
                    "C0 4D 31 C9 48 B8 00 00 00 00 00 00 00 00 FF D0 "
                    "48 83 C4 28 C3");
                Desc = QStringLiteral("x64 MessageBoxA stub (needs address patching at offset 18)");
            } else if (Payload == QStringLiteral("infinite_loop")) {
                HexBytes = QStringLiteral("EB FE");
                Desc = QStringLiteral("x64 infinite loop (jmp $)");
            } else if (Payload == QStringLiteral("breakpoint")) {
                HexBytes = QStringLiteral("CC C3");
                Desc = QStringLiteral("x64 int3 breakpoint + ret");
            } else if (Payload == QStringLiteral("nop_sled")) {
                HexBytes = QStringLiteral(
                    "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 "
                    "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 C3");
                Desc = QStringLiteral("32-byte NOP sled + ret");
            }

            QString Code;
            Code += QStringLiteral("unsigned char Shellcode[] = {\n    ");
            QStringList Bytes = HexBytes.split(' ', Qt::SkipEmptyParts);
            for (int I = 0; I < Bytes.size(); ++I) {
                Code += QStringLiteral("0x") + Bytes[I];
                if (I < Bytes.size() - 1) Code += QStringLiteral(", ");
                if ((I + 1) % 12 == 0 && I < Bytes.size() - 1) Code += QStringLiteral("\n    ");
            }
            Code += QStringLiteral("\n};\n\n");
            Code += QStringLiteral("void ExecuteShellcode() {\n");
            Code += QStringLiteral("    void* Exec = VirtualAlloc(nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n");
            Code += QStringLiteral("    memcpy(Exec, Shellcode, sizeof(Shellcode));\n");
            Code += QStringLiteral("    ((void(*)())Exec)();\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("hex")] = HexBytes;
            Result[QStringLiteral("size")] = Bytes.size();
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = Desc;
            return Result;
        });

    RegisterTool(QStringLiteral("generate_dll_template"),
        QStringLiteral("Generate DllMain template with thread creation."),
        Schema::Build({
            {QStringLiteral("dll_name"), Schema::String(QStringLiteral("DLL name"))},
            {QStringLiteral("create_thread"), Schema::Boolean(QStringLiteral("Create worker thread on attach (default true)"))}
        }, {QStringLiteral("dll_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString DllName = A.value(QStringLiteral("dll_name")).toString();
            bool CreateThread = A.value(QStringLiteral("create_thread")).toBool(true);

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n\n");
            Code += QStringLiteral("static HMODULE ModuleHandle = nullptr;\n\n");

            if (CreateThread) {
                Code += QStringLiteral("DWORD WINAPI MainThread(LPVOID Param) {\n");
                Code += QStringLiteral("    UNREFERENCED_PARAMETER(Param);\n\n");
                Code += QStringLiteral("    // Wait for modules to load\n");
                Code += QStringLiteral("    Sleep(1000);\n\n");
                Code += QStringLiteral("    // Main logic here\n\n");
                Code += QStringLiteral("    // Cleanup and unload\n");
                Code += QStringLiteral("    FreeLibraryAndExitThread(ModuleHandle, 0);\n");
                Code += QStringLiteral("    return 0;\n}\n\n");
            }

            Code += QStringLiteral("BOOL APIENTRY DllMain(HMODULE Module, DWORD Reason, LPVOID Reserved) {\n");
            Code += QStringLiteral("    UNREFERENCED_PARAMETER(Reserved);\n\n");
            Code += QStringLiteral("    switch (Reason) {\n");
            Code += QStringLiteral("    case DLL_PROCESS_ATTACH:\n");
            Code += QStringLiteral("        ModuleHandle = Module;\n");
            Code += QStringLiteral("        DisableThreadLibraryCalls(Module);\n");
            if (CreateThread) {
                Code += QStringLiteral("        CloseHandle(CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr));\n");
            }
            Code += QStringLiteral("        break;\n");
            Code += QStringLiteral("    case DLL_PROCESS_DETACH:\n");
            Code += QStringLiteral("        break;\n    }\n");
            Code += QStringLiteral("    return TRUE;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("DLL template with DllMain and optional worker thread");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_inject_code"),
        QStringLiteral("Generate DLL injection code using CreateRemoteThread + LoadLibraryA."),
        Schema::Build({
            {QStringLiteral("dll_path"), Schema::String(QStringLiteral("Full path to DLL to inject"))},
            {QStringLiteral("target_process"), Schema::String(QStringLiteral("Target process name or PID"))}
        }, {QStringLiteral("dll_path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString DllPath = A.value(QStringLiteral("dll_path")).toString();
            QString Target = A.value(QStringLiteral("target_process")).toString(QStringLiteral("target.exe"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <TlHelp32.h>\n#include <cstdio>\n\n");
            Code += QStringLiteral("DWORD FindProcessId(const char* ProcessName) {\n");
            Code += QStringLiteral("    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n");
            Code += QStringLiteral("    if (Snap == INVALID_HANDLE_VALUE) return 0;\n\n");
            Code += QStringLiteral("    PROCESSENTRY32 Pe;\n    Pe.dwSize = sizeof(Pe);\n");
            Code += QStringLiteral("    DWORD Pid = 0;\n\n");
            Code += QStringLiteral("    if (Process32First(Snap, &Pe)) {\n");
            Code += QStringLiteral("        do {\n");
            Code += QStringLiteral("            if (_stricmp(Pe.szExeFile, ProcessName) == 0) {\n");
            Code += QStringLiteral("                Pid = Pe.th32ProcessID;\n                break;\n            }\n");
            Code += QStringLiteral("        } while (Process32Next(Snap, &Pe));\n    }\n\n");
            Code += QStringLiteral("    CloseHandle(Snap);\n    return Pid;\n}\n\n");
            Code += QStringLiteral("bool InjectDll(DWORD Pid, const char* DllPath) {\n");
            Code += QStringLiteral("    HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);\n");
            Code += QStringLiteral("    if (!Process) {\n");
            Code += QStringLiteral("        printf(\"OpenProcess failed: %lu\\n\", GetLastError());\n");
            Code += QStringLiteral("        return false;\n    }\n\n");
            Code += QStringLiteral("    SIZE_T PathLen = strlen(DllPath) + 1;\n");
            Code += QStringLiteral("    LPVOID RemoteBuf = VirtualAllocEx(Process, nullptr, PathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n");
            Code += QStringLiteral("    if (!RemoteBuf) {\n");
            Code += QStringLiteral("        printf(\"VirtualAllocEx failed: %lu\\n\", GetLastError());\n");
            Code += QStringLiteral("        CloseHandle(Process);\n        return false;\n    }\n\n");
            Code += QStringLiteral("    if (!WriteProcessMemory(Process, RemoteBuf, DllPath, PathLen, nullptr)) {\n");
            Code += QStringLiteral("        printf(\"WriteProcessMemory failed: %lu\\n\", GetLastError());\n");
            Code += QStringLiteral("        VirtualFreeEx(Process, RemoteBuf, 0, MEM_RELEASE);\n");
            Code += QStringLiteral("        CloseHandle(Process);\n        return false;\n    }\n\n");
            Code += QStringLiteral("    HMODULE K32 = GetModuleHandleA(\"kernel32.dll\");\n");
            Code += QStringLiteral("    LPTHREAD_START_ROUTINE LoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(K32, \"LoadLibraryA\");\n\n");
            Code += QStringLiteral("    HANDLE Thread = CreateRemoteThread(Process, nullptr, 0, LoadLib, RemoteBuf, 0, nullptr);\n");
            Code += QStringLiteral("    if (!Thread) {\n");
            Code += QStringLiteral("        printf(\"CreateRemoteThread failed: %lu\\n\", GetLastError());\n");
            Code += QStringLiteral("        VirtualFreeEx(Process, RemoteBuf, 0, MEM_RELEASE);\n");
            Code += QStringLiteral("        CloseHandle(Process);\n        return false;\n    }\n\n");
            Code += QStringLiteral("    WaitForSingleObject(Thread, INFINITE);\n");
            Code += QStringLiteral("    VirtualFreeEx(Process, RemoteBuf, 0, MEM_RELEASE);\n");
            Code += QStringLiteral("    CloseHandle(Thread);\n    CloseHandle(Process);\n");
            Code += QStringLiteral("    printf(\"Injection successful\\n\");\n");
            Code += QStringLiteral("    return true;\n}\n\n");
            Code += QStringLiteral("int main() {\n");
            Code += QStringLiteral("    DWORD Pid = FindProcessId(\"") + Target + QStringLiteral("\");\n");
            Code += QStringLiteral("    if (Pid == 0) {\n        printf(\"Process not found\\n\");\n        return 1;\n    }\n");
            Code += QStringLiteral("    printf(\"Found PID: %lu\\n\", Pid);\n");
            Code += QStringLiteral("    InjectDll(Pid, \"") + DllPath + QStringLiteral("\");\n");
            Code += QStringLiteral("    return 0;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("DLL injection via CreateRemoteThread + LoadLibraryA");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_pattern_scan"),
        QStringLiteral("Generate C++ pattern scan function with wildcard support."),
        Schema::Build({
            {QStringLiteral("function_name"), Schema::String(QStringLiteral("Name for the scan function (default PatternScan)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString FuncName = A.value(QStringLiteral("function_name")).toString(QStringLiteral("PatternScan"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <vector>\n#include <string>\n#include <sstream>\n\n");
            Code += QStringLiteral("struct PatternByte {\n    uint8_t Value;\n    bool IsWildcard;\n};\n\n");
            Code += QStringLiteral("std::vector<PatternByte> ParsePattern(const std::string& Pattern) {\n");
            Code += QStringLiteral("    std::vector<PatternByte> Result;\n");
            Code += QStringLiteral("    std::istringstream Stream(Pattern);\n    std::string Token;\n\n");
            Code += QStringLiteral("    while (Stream >> Token) {\n");
            Code += QStringLiteral("        PatternByte Pb;\n");
            Code += QStringLiteral("        if (Token == \"?\" || Token == \"??\") {\n");
            Code += QStringLiteral("            Pb.Value = 0;\n            Pb.IsWildcard = true;\n");
            Code += QStringLiteral("        } else {\n");
            Code += QStringLiteral("            Pb.Value = static_cast<uint8_t>(std::stoul(Token, nullptr, 16));\n");
            Code += QStringLiteral("            Pb.IsWildcard = false;\n        }\n");
            Code += QStringLiteral("        Result.push_back(Pb);\n    }\n    return Result;\n}\n\n");
            Code += QStringLiteral("uintptr_t ") + FuncName + QStringLiteral("(uintptr_t Start, size_t Size, const std::string& Pattern) {\n");
            Code += QStringLiteral("    auto Bytes = ParsePattern(Pattern);\n");
            Code += QStringLiteral("    if (Bytes.empty()) return 0;\n\n");
            Code += QStringLiteral("    const uint8_t* Data = reinterpret_cast<const uint8_t*>(Start);\n\n");
            Code += QStringLiteral("    for (size_t I = 0; I <= Size - Bytes.size(); ++I) {\n");
            Code += QStringLiteral("        bool Found = true;\n");
            Code += QStringLiteral("        for (size_t J = 0; J < Bytes.size(); ++J) {\n");
            Code += QStringLiteral("            if (!Bytes[J].IsWildcard && Data[I + J] != Bytes[J].Value) {\n");
            Code += QStringLiteral("                Found = false;\n                break;\n            }\n        }\n");
            Code += QStringLiteral("        if (Found) return Start + I;\n    }\n    return 0;\n}\n\n");
            Code += QStringLiteral("uintptr_t ") + FuncName + QStringLiteral("Module(const char* ModuleName, const std::string& Pattern) {\n");
            Code += QStringLiteral("    HMODULE Mod = GetModuleHandleA(ModuleName);\n");
            Code += QStringLiteral("    if (!Mod) return 0;\n\n");
            Code += QStringLiteral("    MODULEINFO Info;\n");
            Code += QStringLiteral("    GetModuleInformation(GetCurrentProcess(), Mod, &Info, sizeof(Info));\n");
            Code += QStringLiteral("    return ") + FuncName + QStringLiteral("(reinterpret_cast<uintptr_t>(Mod), Info.SizeOfImage, Pattern);\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Pattern scan with wildcard support and module-based scanning");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_enum_def"),
        QStringLiteral("Generate C++ enum definition from name/value pairs."),
        Schema::Build({
            {QStringLiteral("enum_name"), Schema::String(QStringLiteral("Enum name"))},
            {QStringLiteral("values"), Schema::Array(QStringLiteral("Array of {name, value} objects"))},
            {QStringLiteral("use_class"), Schema::Boolean(QStringLiteral("Use enum class (default true)"))}
        }, {QStringLiteral("enum_name"), QStringLiteral("values")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString EnumName = A.value(QStringLiteral("enum_name")).toString();
            QJsonArray Values = A.value(QStringLiteral("values")).toArray();
            bool UseClass = A.value(QStringLiteral("use_class")).toBool(true);

            QString Code;
            if (UseClass) {
                Code += QStringLiteral("enum class ") + EnumName + QStringLiteral(" : uint32_t {\n");
            } else {
                Code += QStringLiteral("enum ") + EnumName + QStringLiteral(" {\n");
            }

            for (int I = 0; I < Values.size(); ++I) {
                QJsonObject V = Values[I].toObject();
                QString VName = V.value(QStringLiteral("name")).toString();
                int VVal = V.value(QStringLiteral("value")).toInt();
                Code += QStringLiteral("    ") + VName + QStringLiteral(" = 0x") + QString::number(VVal, 16).toUpper();
                if (I < Values.size() - 1) Code += QStringLiteral(",");
                Code += QStringLiteral("\n");
            }
            Code += QStringLiteral("};\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("C++ enum with hex values");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_function_typedef"),
        QStringLiteral("Generate C++ function pointer typedef."),
        Schema::Build({
            {QStringLiteral("typedef_name"), Schema::String(QStringLiteral("Name for the typedef"))},
            {QStringLiteral("return_type"), Schema::String(QStringLiteral("Return type"))},
            {QStringLiteral("calling_convention"), Schema::StringEnum(QStringLiteral("Calling convention"),
                {QStringLiteral("__cdecl"), QStringLiteral("__stdcall"), QStringLiteral("__fastcall"), QStringLiteral("__thiscall")})},
            {QStringLiteral("params"), Schema::String(QStringLiteral("Parameter list (e.g. 'int, float, void*')"))}
        }, {QStringLiteral("typedef_name"), QStringLiteral("return_type")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString TypedefName = A.value(QStringLiteral("typedef_name")).toString();
            QString RetType = A.value(QStringLiteral("return_type")).toString();
            QString CallConv = A.value(QStringLiteral("calling_convention")).toString(QStringLiteral("__fastcall"));
            QString Params = A.value(QStringLiteral("params")).toString(QStringLiteral(""));

            QString Code;
            Code += QStringLiteral("typedef ") + RetType + QStringLiteral("(") + CallConv + QStringLiteral("* ") + TypedefName + QStringLiteral(")(") + Params + QStringLiteral(");\n");
            Code += QStringLiteral("\nstatic ") + TypedefName + QStringLiteral(" p") + TypedefName + QStringLiteral(" = nullptr;\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Function pointer typedef with calling convention");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_vtable_struct"),
        QStringLiteral("Generate vtable struct with function pointer array and call macros."),
        Schema::Build({
            {QStringLiteral("struct_name"), Schema::String(QStringLiteral("Name for the vtable struct"))},
            {QStringLiteral("entry_count"), Schema::Integer(QStringLiteral("Number of vtable entries"), 1, 1024)}
        }, {QStringLiteral("struct_name"), QStringLiteral("entry_count")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString StructName = A.value(QStringLiteral("struct_name")).toString();
            int Count = A.value(QStringLiteral("entry_count")).toInt();

            QString Code;
            Code += QStringLiteral("#include <cstdint>\n\n");
            Code += QStringLiteral("#define CALL_VIRTUAL(RetType, Idx, ...) \\\n");
            Code += QStringLiteral("    reinterpret_cast<RetType(__fastcall*)(void*, __VA_ARGS__)>( \\\n");
            Code += QStringLiteral("        (*reinterpret_cast<uintptr_t**>(this))[Idx] \\\n");
            Code += QStringLiteral("    )(this, __VA_ARGS__)\n\n");

            Code += QStringLiteral("struct ") + StructName + QStringLiteral(" {\n");
            Code += QStringLiteral("    void** VTable;\n\n");

            for (int I = 0; I < Count; ++I) {
                Code += QStringLiteral("    void* GetVFunc") + QString::number(I) + QStringLiteral("() {\n");
                Code += QStringLiteral("        return VTable[") + QString::number(I) + QStringLiteral("];\n    }\n\n");
            }

            Code += QStringLiteral("    template<typename T>\n");
            Code += QStringLiteral("    T CallVFunc(int Index) {\n");
            Code += QStringLiteral("        return reinterpret_cast<T>(VTable[Index]);\n    }\n");
            Code += QStringLiteral("};\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("VTable struct with ") + QString::number(Count) + QStringLiteral(" entries and call helpers");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_syscall_stub"),
        QStringLiteral("Generate x64 direct syscall stub that bypasses ntdll."),
        Schema::Build({
            {QStringLiteral("syscall_number"), Schema::Integer(QStringLiteral("Syscall number (SSN)"), 0, 4096)},
            {QStringLiteral("function_name"), Schema::String(QStringLiteral("Name for the syscall function"))}
        }, {QStringLiteral("syscall_number"), QStringLiteral("function_name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            int SyscallNum = A.value(QStringLiteral("syscall_number")).toInt();
            QString FuncName = A.value(QStringLiteral("function_name")).toString();

            QString Code;
            Code += QStringLiteral("// x64 Direct Syscall Stub\n");
            Code += QStringLiteral("// SSN: ") + QString::number(SyscallNum) + QStringLiteral(" (0x") + QString::number(SyscallNum, 16).toUpper() + QStringLiteral(")\n\n");

            Code += QStringLiteral("extern \"C\" NTSTATUS ") + FuncName + QStringLiteral("(...);\n\n");

            Code += QStringLiteral("// MASM (.asm file):\n");
            Code += QStringLiteral("// .code\n");
            Code += QStringLiteral("// ") + FuncName + QStringLiteral(" PROC\n");
            Code += QStringLiteral("//     mov r10, rcx\n");
            Code += QStringLiteral("//     mov eax, 0") + QString::number(SyscallNum, 16).toUpper() + QStringLiteral("h\n");
            Code += QStringLiteral("//     syscall\n");
            Code += QStringLiteral("//     ret\n");
            Code += QStringLiteral("// ") + FuncName + QStringLiteral(" ENDP\n");
            Code += QStringLiteral("// END\n\n");

            Code += QStringLiteral("// Inline shellcode version:\n");
            Code += QStringLiteral("static unsigned char SyscallShellcode[] = {\n");
            Code += QStringLiteral("    0x4C, 0x8B, 0xD1,                   // mov r10, rcx\n");
            Code += QStringLiteral("    0xB8, ");

            Code += QStringLiteral("0x") + QString::number(SyscallNum & 0xFF, 16).toUpper().rightJustified(2, '0') + QStringLiteral(", ");
            Code += QStringLiteral("0x") + QString::number((SyscallNum >> 8) & 0xFF, 16).toUpper().rightJustified(2, '0') + QStringLiteral(", ");
            Code += QStringLiteral("0x00, 0x00,   // mov eax, 0x") + QString::number(SyscallNum, 16).toUpper() + QStringLiteral("\n");
            Code += QStringLiteral("    0x0F, 0x05,                         // syscall\n");
            Code += QStringLiteral("    0xC3                                // ret\n};\n\n");

            Code += QStringLiteral("typedef NTSTATUS(NTAPI* fn_") + FuncName + QStringLiteral(")(...);\n\n");
            Code += QStringLiteral("fn_") + FuncName + QStringLiteral(" Get") + FuncName + QStringLiteral("() {\n");
            Code += QStringLiteral("    void* Buf = VirtualAlloc(nullptr, sizeof(SyscallShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n");
            Code += QStringLiteral("    memcpy(Buf, SyscallShellcode, sizeof(SyscallShellcode));\n");
            Code += QStringLiteral("    return reinterpret_cast<fn_") + FuncName + QStringLiteral(">(Buf);\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Direct syscall stub for SSN ") + QString::number(SyscallNum);
            return Result;
        });

    RegisterTool(QStringLiteral("generate_pe_parser"),
        QStringLiteral("Generate C++ code that parses PE headers from a buffer."),
        Schema::Build({
            {QStringLiteral("include_sections"), Schema::Boolean(QStringLiteral("Include section parsing (default true)"))},
            {QStringLiteral("include_imports"), Schema::Boolean(QStringLiteral("Include import parsing (default true)"))},
            {QStringLiteral("include_exports"), Schema::Boolean(QStringLiteral("Include export parsing (default true)"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            bool IncSections = A.value(QStringLiteral("include_sections")).toBool(true);
            bool IncImports = A.value(QStringLiteral("include_imports")).toBool(true);
            bool IncExports = A.value(QStringLiteral("include_exports")).toBool(true);

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstdio>\n#include <vector>\n#include <string>\n\n");
            Code += QStringLiteral("struct PeInfo {\n");
            Code += QStringLiteral("    bool Is64Bit;\n    DWORD EntryPoint;\n    DWORD ImageSize;\n");
            Code += QStringLiteral("    WORD NumberOfSections;\n    DWORD TimeDateStamp;\n");
            Code += QStringLiteral("    std::vector<IMAGE_SECTION_HEADER> Sections;\n");
            Code += QStringLiteral("    std::vector<std::pair<std::string, std::vector<std::string>>> Imports;\n");
            Code += QStringLiteral("    std::vector<std::pair<std::string, DWORD>> Exports;\n};\n\n");

            Code += QStringLiteral("bool ParsePE(const BYTE* Data, size_t DataSize, PeInfo& Info) {\n");
            Code += QStringLiteral("    if (DataSize < sizeof(IMAGE_DOS_HEADER)) return false;\n\n");
            Code += QStringLiteral("    auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Data);\n");
            Code += QStringLiteral("    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return false;\n\n");
            Code += QStringLiteral("    if (static_cast<size_t>(Dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > DataSize) return false;\n");
            Code += QStringLiteral("    auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(Data + Dos->e_lfanew);\n");
            Code += QStringLiteral("    if (Nt->Signature != IMAGE_NT_SIGNATURE) return false;\n\n");
            Code += QStringLiteral("    Info.Is64Bit = (Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);\n");
            Code += QStringLiteral("    Info.NumberOfSections = Nt->FileHeader.NumberOfSections;\n");
            Code += QStringLiteral("    Info.TimeDateStamp = Nt->FileHeader.TimeDateStamp;\n\n");

            Code += QStringLiteral("    if (Info.Is64Bit) {\n");
            Code += QStringLiteral("        auto* Nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Data + Dos->e_lfanew);\n");
            Code += QStringLiteral("        Info.EntryPoint = Nt64->OptionalHeader.AddressOfEntryPoint;\n");
            Code += QStringLiteral("        Info.ImageSize = Nt64->OptionalHeader.SizeOfImage;\n    } else {\n");
            Code += QStringLiteral("        auto* Nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(Data + Dos->e_lfanew);\n");
            Code += QStringLiteral("        Info.EntryPoint = Nt32->OptionalHeader.AddressOfEntryPoint;\n");
            Code += QStringLiteral("        Info.ImageSize = Nt32->OptionalHeader.SizeOfImage;\n    }\n\n");

            if (IncSections) {
                Code += QStringLiteral("    auto* Section = IMAGE_FIRST_SECTION(Nt);\n");
                Code += QStringLiteral("    for (WORD I = 0; I < Info.NumberOfSections; ++I) {\n");
                Code += QStringLiteral("        Info.Sections.push_back(Section[I]);\n    }\n\n");
            }

            if (IncImports) {
                Code += QStringLiteral("    DWORD ImportRva = 0;\n");
                Code += QStringLiteral("    if (Info.Is64Bit) {\n");
                Code += QStringLiteral("        auto* Nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Data + Dos->e_lfanew);\n");
                Code += QStringLiteral("        ImportRva = Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;\n");
                Code += QStringLiteral("    } else {\n");
                Code += QStringLiteral("        auto* Nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(Data + Dos->e_lfanew);\n");
                Code += QStringLiteral("        ImportRva = Nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;\n    }\n");
                Code += QStringLiteral("    // Import parsing requires RVA-to-offset resolution using section headers\n\n");
            }

            if (IncExports) {
                Code += QStringLiteral("    DWORD ExportRva = 0;\n");
                Code += QStringLiteral("    if (Info.Is64Bit) {\n");
                Code += QStringLiteral("        auto* Nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Data + Dos->e_lfanew);\n");
                Code += QStringLiteral("        ExportRva = Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;\n");
                Code += QStringLiteral("    } else {\n");
                Code += QStringLiteral("        auto* Nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(Data + Dos->e_lfanew);\n");
                Code += QStringLiteral("        ExportRva = Nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;\n    }\n");
                Code += QStringLiteral("    // Export parsing requires RVA-to-offset resolution using section headers\n\n");
            }

            Code += QStringLiteral("    return true;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("PE parser reading DOS/NT headers, sections, imports, exports from buffer");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_exception_handler"),
        QStringLiteral("Generate VEH/SEH exception handler code."),
        Schema::Build({
            {QStringLiteral("handler_type"), Schema::StringEnum(QStringLiteral("Handler type"), {QStringLiteral("veh"), QStringLiteral("seh")})},
            {QStringLiteral("handler_name"), Schema::String(QStringLiteral("Handler function name"))}
        }, {QStringLiteral("handler_type")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Type = A.value(QStringLiteral("handler_type")).toString(QStringLiteral("veh"));
            QString Name = A.value(QStringLiteral("handler_name")).toString(QStringLiteral("ExceptionHandler"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstdio>\n\n");

            if (Type == QStringLiteral("veh")) {
                Code += QStringLiteral("LONG CALLBACK ") + Name + QStringLiteral("(PEXCEPTION_POINTERS ExInfo) {\n");
                Code += QStringLiteral("    DWORD Code = ExInfo->ExceptionRecord->ExceptionCode;\n");
                Code += QStringLiteral("    PVOID Addr = ExInfo->ExceptionRecord->ExceptionAddress;\n\n");
                Code += QStringLiteral("    switch (Code) {\n");
                Code += QStringLiteral("    case EXCEPTION_ACCESS_VIOLATION:\n");
                Code += QStringLiteral("        printf(\"Access violation at %p\\n\", Addr);\n");
                Code += QStringLiteral("        break;\n");
                Code += QStringLiteral("    case EXCEPTION_BREAKPOINT:\n");
                Code += QStringLiteral("        printf(\"Breakpoint at %p\\n\", Addr);\n");
                Code += QStringLiteral("        ExInfo->ContextRecord->Rip += 1;\n");
                Code += QStringLiteral("        return EXCEPTION_CONTINUE_EXECUTION;\n");
                Code += QStringLiteral("    case EXCEPTION_SINGLE_STEP:\n");
                Code += QStringLiteral("        printf(\"Single step at %p\\n\", Addr);\n");
                Code += QStringLiteral("        return EXCEPTION_CONTINUE_EXECUTION;\n");
                Code += QStringLiteral("    case EXCEPTION_GUARD_PAGE:\n");
                Code += QStringLiteral("        printf(\"Guard page at %p\\n\", Addr);\n");
                Code += QStringLiteral("        return EXCEPTION_CONTINUE_EXECUTION;\n");
                Code += QStringLiteral("    default:\n");
                Code += QStringLiteral("        printf(\"Exception 0x%08X at %p\\n\", Code, Addr);\n");
                Code += QStringLiteral("        break;\n    }\n\n");
                Code += QStringLiteral("    return EXCEPTION_CONTINUE_SEARCH;\n}\n\n");
                Code += QStringLiteral("void Install() {\n");
                Code += QStringLiteral("    AddVectoredExceptionHandler(1, ") + Name + QStringLiteral(");\n}\n\n");
                Code += QStringLiteral("void Uninstall() {\n");
                Code += QStringLiteral("    RemoveVectoredExceptionHandler(") + Name + QStringLiteral(");\n}\n");
            } else {
                Code += QStringLiteral("EXCEPTION_DISPOSITION __cdecl ") + Name + QStringLiteral("(\n");
                Code += QStringLiteral("    EXCEPTION_RECORD* ExRecord, void* EstablisherFrame,\n");
                Code += QStringLiteral("    CONTEXT* ContextRecord, void* DispatcherContext) {\n\n");
                Code += QStringLiteral("    UNREFERENCED_PARAMETER(EstablisherFrame);\n");
                Code += QStringLiteral("    UNREFERENCED_PARAMETER(DispatcherContext);\n\n");
                Code += QStringLiteral("    printf(\"SEH: Exception 0x%08X at %p\\n\", ExRecord->ExceptionCode, ExRecord->ExceptionAddress);\n\n");
                Code += QStringLiteral("    if (ExRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {\n");
                Code += QStringLiteral("        ContextRecord->Rip += 1;\n");
                Code += QStringLiteral("        return ExceptionContinueExecution;\n    }\n\n");
                Code += QStringLiteral("    return ExceptionContinueSearch;\n}\n\n");
                Code += QStringLiteral("void ProtectedFunction() {\n");
                Code += QStringLiteral("    __try {\n        // Protected code\n    }\n");
                Code += QStringLiteral("    __except(EXCEPTION_EXECUTE_HANDLER) {\n");
                Code += QStringLiteral("        printf(\"Exception caught: 0x%08X\\n\", GetExceptionCode());\n    }\n}\n");
            }

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = Type.toUpper() + QStringLiteral(" exception handler with common exception types");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_thread_hijack"),
        QStringLiteral("Generate thread hijacking injection code."),
        Schema::Build({
            {QStringLiteral("shellcode_var"), Schema::String(QStringLiteral("Name of shellcode variable"))},
            {QStringLiteral("target_pid"), Schema::String(QStringLiteral("Target process PID or variable name"))}
        }, {QStringLiteral("shellcode_var")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString ShellcodeVar = A.value(QStringLiteral("shellcode_var")).toString();
            QString TargetPid = A.value(QStringLiteral("target_pid")).toString(QStringLiteral("TargetPid"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <TlHelp32.h>\n#include <cstdio>\n\n");
            Code += QStringLiteral("DWORD GetMainThreadId(DWORD Pid) {\n");
            Code += QStringLiteral("    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n");
            Code += QStringLiteral("    if (Snap == INVALID_HANDLE_VALUE) return 0;\n\n");
            Code += QStringLiteral("    THREADENTRY32 Te;\n    Te.dwSize = sizeof(Te);\n    DWORD Tid = 0;\n\n");
            Code += QStringLiteral("    if (Thread32First(Snap, &Te)) {\n");
            Code += QStringLiteral("        do {\n");
            Code += QStringLiteral("            if (Te.th32OwnerProcessID == Pid) {\n");
            Code += QStringLiteral("                Tid = Te.th32ThreadID;\n                break;\n            }\n");
            Code += QStringLiteral("        } while (Thread32Next(Snap, &Te));\n    }\n");
            Code += QStringLiteral("    CloseHandle(Snap);\n    return Tid;\n}\n\n");
            Code += QStringLiteral("bool HijackThread(DWORD Pid, const BYTE* Shellcode, SIZE_T ShellcodeSize) {\n");
            Code += QStringLiteral("    HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);\n");
            Code += QStringLiteral("    if (!Process) return false;\n\n");
            Code += QStringLiteral("    LPVOID RemoteBuf = VirtualAllocEx(Process, nullptr, ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n");
            Code += QStringLiteral("    if (!RemoteBuf) { CloseHandle(Process); return false; }\n\n");
            Code += QStringLiteral("    WriteProcessMemory(Process, RemoteBuf, Shellcode, ShellcodeSize, nullptr);\n\n");
            Code += QStringLiteral("    DWORD Tid = GetMainThreadId(Pid);\n");
            Code += QStringLiteral("    HANDLE Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, Tid);\n");
            Code += QStringLiteral("    if (!Thread) { CloseHandle(Process); return false; }\n\n");
            Code += QStringLiteral("    SuspendThread(Thread);\n\n");
            Code += QStringLiteral("    CONTEXT Ctx;\n    Ctx.ContextFlags = CONTEXT_FULL;\n");
            Code += QStringLiteral("    GetThreadContext(Thread, &Ctx);\n\n");
            Code += QStringLiteral("    Ctx.Rip = reinterpret_cast<DWORD64>(RemoteBuf);\n\n");
            Code += QStringLiteral("    SetThreadContext(Thread, &Ctx);\n");
            Code += QStringLiteral("    ResumeThread(Thread);\n\n");
            Code += QStringLiteral("    CloseHandle(Thread);\n    CloseHandle(Process);\n");
            Code += QStringLiteral("    printf(\"Thread hijacked successfully\\n\");\n");
            Code += QStringLiteral("    return true;\n}\n\n");
            Code += QStringLiteral("int main() {\n");
            Code += QStringLiteral("    DWORD Pid = ") + TargetPid + QStringLiteral(";\n");
            Code += QStringLiteral("    HijackThread(Pid, ") + ShellcodeVar + QStringLiteral(", sizeof(") + ShellcodeVar + QStringLiteral("));\n");
            Code += QStringLiteral("    return 0;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Thread hijacking: suspend, modify RIP to shellcode, resume");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_manual_map"),
        QStringLiteral("Generate manual mapping DLL loader outline."),
        Schema::Build({
            {QStringLiteral("target_pid"), Schema::String(QStringLiteral("Target process PID variable name"))},
            {QStringLiteral("dll_path_var"), Schema::String(QStringLiteral("Variable holding DLL file path"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString TargetPid = A.value(QStringLiteral("target_pid")).toString(QStringLiteral("TargetPid"));
            QString DllPathVar = A.value(QStringLiteral("dll_path_var")).toString(QStringLiteral("DllPath"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstdio>\n#include <fstream>\n#include <vector>\n\n");

            Code += QStringLiteral("struct ManualMapData {\n");
            Code += QStringLiteral("    HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);\n");
            Code += QStringLiteral("    FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);\n");
            Code += QStringLiteral("    BYTE* ImageBase;\n};\n\n");

            Code += QStringLiteral("void __stdcall ShellcodeEntry(ManualMapData* Data) {\n");
            Code += QStringLiteral("    BYTE* Base = Data->ImageBase;\n");
            Code += QStringLiteral("    auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);\n");
            Code += QStringLiteral("    auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Base + Dos->e_lfanew);\n");
            Code += QStringLiteral("    auto* Opt = &Nt->OptionalHeader;\n\n");

            Code += QStringLiteral("    // Process relocations\n");
            Code += QStringLiteral("    DWORD64 Delta = reinterpret_cast<DWORD64>(Base) - Opt->ImageBase;\n");
            Code += QStringLiteral("    if (Delta) {\n");
            Code += QStringLiteral("        auto& RelocDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n");
            Code += QStringLiteral("        if (RelocDir.Size) {\n");
            Code += QStringLiteral("            auto* Reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(Base + RelocDir.VirtualAddress);\n");
            Code += QStringLiteral("            while (Reloc->VirtualAddress) {\n");
            Code += QStringLiteral("                WORD* List = reinterpret_cast<WORD*>(Reloc + 1);\n");
            Code += QStringLiteral("                int Count = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n");
            Code += QStringLiteral("                for (int I = 0; I < Count; ++I) {\n");
            Code += QStringLiteral("                    if ((List[I] >> 12) == IMAGE_REL_BASED_DIR64) {\n");
            Code += QStringLiteral("                        DWORD64* Patch = reinterpret_cast<DWORD64*>(Base + Reloc->VirtualAddress + (List[I] & 0xFFF));\n");
            Code += QStringLiteral("                        *Patch += Delta;\n                    }\n                }\n");
            Code += QStringLiteral("                Reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(Reloc) + Reloc->SizeOfBlock);\n");
            Code += QStringLiteral("            }\n        }\n    }\n\n");

            Code += QStringLiteral("    // Resolve imports\n");
            Code += QStringLiteral("    auto& ImportDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n");
            Code += QStringLiteral("    if (ImportDir.Size) {\n");
            Code += QStringLiteral("        auto* Import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Base + ImportDir.VirtualAddress);\n");
            Code += QStringLiteral("        for (; Import->Name; ++Import) {\n");
            Code += QStringLiteral("            HMODULE Mod = Data->pLoadLibraryA(reinterpret_cast<char*>(Base + Import->Name));\n");
            Code += QStringLiteral("            auto* Thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(Base + Import->FirstThunk);\n");
            Code += QStringLiteral("            auto* OrigThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(Base + Import->OriginalFirstThunk);\n");
            Code += QStringLiteral("            for (; OrigThunk->u1.AddressOfData; ++Thunk, ++OrigThunk) {\n");
            Code += QStringLiteral("                if (IMAGE_SNAP_BY_ORDINAL(OrigThunk->u1.Ordinal)) {\n");
            Code += QStringLiteral("                    Thunk->u1.Function = reinterpret_cast<ULONG_PTR>(Data->pGetProcAddress(Mod, reinterpret_cast<char*>(OrigThunk->u1.Ordinal & 0xFFFF)));\n");
            Code += QStringLiteral("                } else {\n");
            Code += QStringLiteral("                    auto* Name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(Base + OrigThunk->u1.AddressOfData);\n");
            Code += QStringLiteral("                    Thunk->u1.Function = reinterpret_cast<ULONG_PTR>(Data->pGetProcAddress(Mod, Name->Name));\n");
            Code += QStringLiteral("                }\n            }\n        }\n    }\n\n");

            Code += QStringLiteral("    // Call TLS callbacks\n");
            Code += QStringLiteral("    auto& TlsDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];\n");
            Code += QStringLiteral("    if (TlsDir.Size) {\n");
            Code += QStringLiteral("        auto* Tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(Base + TlsDir.VirtualAddress);\n");
            Code += QStringLiteral("        auto** Callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(Tls->AddressOfCallBacks);\n");
            Code += QStringLiteral("        if (Callbacks) {\n");
            Code += QStringLiteral("            for (; *Callbacks; ++Callbacks)\n");
            Code += QStringLiteral("                (*Callbacks)(Base, DLL_PROCESS_ATTACH, nullptr);\n        }\n    }\n\n");

            Code += QStringLiteral("    // Call entry point\n");
            Code += QStringLiteral("    if (Opt->AddressOfEntryPoint) {\n");
            Code += QStringLiteral("        typedef BOOL(WINAPI* DllEntry)(HINSTANCE, DWORD, LPVOID);\n");
            Code += QStringLiteral("        auto Entry = reinterpret_cast<DllEntry>(Base + Opt->AddressOfEntryPoint);\n");
            Code += QStringLiteral("        Entry(reinterpret_cast<HINSTANCE>(Base), DLL_PROCESS_ATTACH, nullptr);\n    }\n}\n\n");

            Code += QStringLiteral("bool ManualMap(DWORD Pid, const char* DllPath) {\n");
            Code += QStringLiteral("    std::ifstream File(DllPath, std::ios::binary | std::ios::ate);\n");
            Code += QStringLiteral("    if (!File.is_open()) return false;\n");
            Code += QStringLiteral("    size_t FileSize = File.tellg();\n    File.seekg(0);\n");
            Code += QStringLiteral("    std::vector<BYTE> RawDll(FileSize);\n");
            Code += QStringLiteral("    File.read(reinterpret_cast<char*>(RawDll.data()), FileSize);\n    File.close();\n\n");
            Code += QStringLiteral("    auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(RawDll.data());\n");
            Code += QStringLiteral("    auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(RawDll.data() + Dos->e_lfanew);\n\n");
            Code += QStringLiteral("    HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);\n");
            Code += QStringLiteral("    if (!Process) return false;\n\n");
            Code += QStringLiteral("    BYTE* RemoteImage = reinterpret_cast<BYTE*>(VirtualAllocEx(Process, nullptr, Nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));\n");
            Code += QStringLiteral("    if (!RemoteImage) { CloseHandle(Process); return false; }\n\n");

            Code += QStringLiteral("    // Copy headers\n");
            Code += QStringLiteral("    WriteProcessMemory(Process, RemoteImage, RawDll.data(), Nt->OptionalHeader.SizeOfHeaders, nullptr);\n\n");
            Code += QStringLiteral("    // Copy sections\n");
            Code += QStringLiteral("    auto* Section = IMAGE_FIRST_SECTION(Nt);\n");
            Code += QStringLiteral("    for (WORD I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {\n");
            Code += QStringLiteral("        if (Section[I].SizeOfRawData)\n");
            Code += QStringLiteral("            WriteProcessMemory(Process, RemoteImage + Section[I].VirtualAddress, RawDll.data() + Section[I].PointerToRawData, Section[I].SizeOfRawData, nullptr);\n    }\n\n");

            Code += QStringLiteral("    // Write shellcode and ManualMapData\n");
            Code += QStringLiteral("    ManualMapData Data;\n");
            Code += QStringLiteral("    Data.pLoadLibraryA = LoadLibraryA;\n");
            Code += QStringLiteral("    Data.pGetProcAddress = GetProcAddress;\n");
            Code += QStringLiteral("    Data.ImageBase = RemoteImage;\n\n");
            Code += QStringLiteral("    BYTE* RemoteData = reinterpret_cast<BYTE*>(VirtualAllocEx(Process, nullptr, sizeof(Data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));\n");
            Code += QStringLiteral("    WriteProcessMemory(Process, RemoteData, &Data, sizeof(Data), nullptr);\n\n");
            Code += QStringLiteral("    BYTE* RemoteShellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(Process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));\n");
            Code += QStringLiteral("    WriteProcessMemory(Process, RemoteShellcode, &ShellcodeEntry, 4096, nullptr);\n\n");
            Code += QStringLiteral("    HANDLE Thread = CreateRemoteThread(Process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(RemoteShellcode), RemoteData, 0, nullptr);\n");
            Code += QStringLiteral("    WaitForSingleObject(Thread, INFINITE);\n\n");
            Code += QStringLiteral("    CloseHandle(Thread);\n    CloseHandle(Process);\n");
            Code += QStringLiteral("    printf(\"Manual map complete\\n\");\n");
            Code += QStringLiteral("    return true;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Manual mapping loader: copy sections, fix relocations, resolve imports, call TLS + entry");
            return Result;
        });

    RegisterTool(QStringLiteral("generate_process_hollow"),
        QStringLiteral("Generate process hollowing code."),
        Schema::Build({
            {QStringLiteral("host_process"), Schema::String(QStringLiteral("Path to host process (e.g. svchost.exe)"))},
            {QStringLiteral("payload_var"), Schema::String(QStringLiteral("Name of variable holding payload PE bytes"))}
        }, {QStringLiteral("host_process")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString HostProcess = A.value(QStringLiteral("host_process")).toString();
            QString PayloadVar = A.value(QStringLiteral("payload_var")).toString(QStringLiteral("PayloadData"));

            QString Code;
            Code += QStringLiteral("#include <Windows.h>\n#include <cstdio>\n\n");
            Code += QStringLiteral("typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);\n\n");
            Code += QStringLiteral("bool ProcessHollow(const char* HostPath, const BYTE* Payload, size_t PayloadSize) {\n");
            Code += QStringLiteral("    STARTUPINFOA Si = {};\n    Si.cb = sizeof(Si);\n");
            Code += QStringLiteral("    PROCESS_INFORMATION Pi = {};\n\n");
            Code += QStringLiteral("    if (!CreateProcessA(HostPath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &Si, &Pi)) {\n");
            Code += QStringLiteral("        printf(\"CreateProcess failed: %lu\\n\", GetLastError());\n        return false;\n    }\n\n");
            Code += QStringLiteral("    auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Payload);\n");
            Code += QStringLiteral("    auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(Payload + Dos->e_lfanew);\n\n");

            Code += QStringLiteral("    auto NtUnmap = reinterpret_cast<pNtUnmapViewOfSection>(GetProcAddress(GetModuleHandleA(\"ntdll.dll\"), \"NtUnmapViewOfSection\"));\n\n");

            Code += QStringLiteral("    CONTEXT Ctx;\n    Ctx.ContextFlags = CONTEXT_FULL;\n");
            Code += QStringLiteral("    GetThreadContext(Pi.hThread, &Ctx);\n\n");

            Code += QStringLiteral("    DWORD64 ImageBase = 0;\n");
            Code += QStringLiteral("    ReadProcessMemory(Pi.hProcess, reinterpret_cast<PVOID>(Ctx.Rdx + 0x10), &ImageBase, sizeof(ImageBase), nullptr);\n\n");

            Code += QStringLiteral("    NtUnmap(Pi.hProcess, reinterpret_cast<PVOID>(ImageBase));\n\n");

            Code += QStringLiteral("    PVOID RemoteBase = VirtualAllocEx(Pi.hProcess, reinterpret_cast<PVOID>(Nt->OptionalHeader.ImageBase),\n");
            Code += QStringLiteral("        Nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n");
            Code += QStringLiteral("    if (!RemoteBase) {\n");
            Code += QStringLiteral("        RemoteBase = VirtualAllocEx(Pi.hProcess, nullptr, Nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n    }\n\n");

            Code += QStringLiteral("    // Write headers\n");
            Code += QStringLiteral("    WriteProcessMemory(Pi.hProcess, RemoteBase, Payload, Nt->OptionalHeader.SizeOfHeaders, nullptr);\n\n");
            Code += QStringLiteral("    // Write sections\n");
            Code += QStringLiteral("    auto* Section = IMAGE_FIRST_SECTION(Nt);\n");
            Code += QStringLiteral("    for (WORD I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {\n");
            Code += QStringLiteral("        if (Section[I].SizeOfRawData)\n");
            Code += QStringLiteral("            WriteProcessMemory(Pi.hProcess, reinterpret_cast<BYTE*>(RemoteBase) + Section[I].VirtualAddress,\n");
            Code += QStringLiteral("                Payload + Section[I].PointerToRawData, Section[I].SizeOfRawData, nullptr);\n    }\n\n");

            Code += QStringLiteral("    // Update PEB ImageBase\n");
            Code += QStringLiteral("    DWORD64 NewBase = reinterpret_cast<DWORD64>(RemoteBase);\n");
            Code += QStringLiteral("    WriteProcessMemory(Pi.hProcess, reinterpret_cast<PVOID>(Ctx.Rdx + 0x10), &NewBase, sizeof(NewBase), nullptr);\n\n");

            Code += QStringLiteral("    // Update entry point\n");
            Code += QStringLiteral("    Ctx.Rcx = reinterpret_cast<DWORD64>(RemoteBase) + Nt->OptionalHeader.AddressOfEntryPoint;\n");
            Code += QStringLiteral("    SetThreadContext(Pi.hThread, &Ctx);\n\n");

            Code += QStringLiteral("    ResumeThread(Pi.hThread);\n");
            Code += QStringLiteral("    printf(\"Process hollowed successfully. PID: %lu\\n\", Pi.dwProcessId);\n\n");
            Code += QStringLiteral("    CloseHandle(Pi.hThread);\n    CloseHandle(Pi.hProcess);\n");
            Code += QStringLiteral("    return true;\n}\n");

            QJsonObject Result;
            Result[QStringLiteral("code")] = Code;
            Result[QStringLiteral("language")] = QStringLiteral("cpp");
            Result[QStringLiteral("description")] = QStringLiteral("Process hollowing: CREATE_SUSPENDED, NtUnmapViewOfSection, write PE, update PEB, resume");
            return Result;
        });
}

}
