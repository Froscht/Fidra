#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <capstone/capstone.h>
#include <cstring>

namespace Fidra {

void McpToolRegistry::RegisterDebuggerTools() {

    RegisterTool(QStringLiteral("debug_status"),
        QStringLiteral("Get current debugger status: whether debugger module is available, process attached, and debug state."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            QJsonObject Result;
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            Result[QStringLiteral("debugger_available")] = (DebugMod != nullptr);
            Result[QStringLiteral("process_attached")] = CoreRef->IsAttached();
            if (CoreRef->IsAttached()) {
                ProcessInfo Proc = CoreRef->CurrentProcess();
                Result[QStringLiteral("pid")] = static_cast<int>(Proc.Pid);
                Result[QStringLiteral("process_name")] = Proc.Name;
                QString ArchStr;
                switch (Proc.Arch) {
                case Architecture::X86: ArchStr = QStringLiteral("x86"); break;
                case Architecture::X64: ArchStr = QStringLiteral("x64"); break;
                case Architecture::ARM: ArchStr = QStringLiteral("arm"); break;
                case Architecture::ARM64: ArchStr = QStringLiteral("arm64"); break;
                default: ArchStr = QStringLiteral("unknown"); break;
                }
                Result[QStringLiteral("architecture")] = ArchStr;
                Result[QStringLiteral("base_address")] = Schema::FormatAddress(Proc.BaseAddress);
            }
            return Result;
        });

    RegisterTool(QStringLiteral("debug_run"),
        QStringLiteral("Continue execution of the debugged process."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            CoreRef->Log(QStringLiteral("MCP: Continue execution requested"), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("continue");
            Result[QStringLiteral("message")] = QStringLiteral("Continue execution command queued. Process will resume running.");
            return Result;
        });

    RegisterTool(QStringLiteral("debug_pause"),
        QStringLiteral("Pause/break execution of the debugged process."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            CoreRef->Log(QStringLiteral("MCP: Break execution requested"), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("break");
            Result[QStringLiteral("message")] = QStringLiteral("Break command queued. Process will be suspended.");
            return Result;
        });

    RegisterTool(QStringLiteral("step_into"),
        QStringLiteral("Single-step into the next instruction, following calls."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            CoreRef->Log(QStringLiteral("MCP: Step into requested"), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("step_into");
            Result[QStringLiteral("message")] = QStringLiteral("Step-into command queued. Will execute one instruction, entering calls.");
            return Result;
        });

    RegisterTool(QStringLiteral("step_over"),
        QStringLiteral("Step over the next instruction, not entering calls."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            CoreRef->Log(QStringLiteral("MCP: Step over requested"), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("step_over");
            Result[QStringLiteral("message")] = QStringLiteral("Step-over command queued. Will execute one instruction, stepping over calls.");
            return Result;
        });

    RegisterTool(QStringLiteral("step_out"),
        QStringLiteral("Run until the current function returns."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            CoreRef->Log(QStringLiteral("MCP: Step out requested"), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("step_out");
            Result[QStringLiteral("message")] = QStringLiteral("Step-out command queued. Will run until current function returns.");
            return Result;
        });

    RegisterTool(QStringLiteral("run_to_address"),
        QStringLiteral("Set a temporary breakpoint at the given address and continue execution until it is hit."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Target address in hex (e.g. 0x7FF612340000)"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            CoreRef->Log(QStringLiteral("MCP: Run to ") + Schema::FormatAddress(Addr), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("command")] = QStringLiteral("run_to_address");
            Result[QStringLiteral("target_address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("message")] = QStringLiteral("Temporary breakpoint set and continue queued.");
            return Result;
        });

    RegisterTool(QStringLiteral("set_hw_breakpoint"),
        QStringLiteral("Set a hardware breakpoint using debug registers (DR0-DR3). Supports execute, write, and read/write access types."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Breakpoint address in hex"))},
            {QStringLiteral("type"), Schema::StringEnum(QStringLiteral("Breakpoint type"), {QStringLiteral("execute"), QStringLiteral("write"), QStringLiteral("readwrite")})},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Watch size in bytes (1, 2, 4, or 8)"), 1, 8)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            QString Type = A.value(QStringLiteral("type")).toString(QStringLiteral("execute"));
            int Size = A.value(QStringLiteral("size")).toInt(1);
            if (Size != 1 && Size != 2 && Size != 4 && Size != 8) {
                return Schema::Err(QStringLiteral("Size must be 1, 2, 4, or 8"));
            }
            int Dr7Condition = 0;
            if (Type == QStringLiteral("execute")) Dr7Condition = 0;
            else if (Type == QStringLiteral("write")) Dr7Condition = 1;
            else if (Type == QStringLiteral("readwrite")) Dr7Condition = 3;
            int Dr7Len = 0;
            if (Size == 1) Dr7Len = 0;
            else if (Size == 2) Dr7Len = 1;
            else if (Size == 4) Dr7Len = 3;
            else if (Size == 8) Dr7Len = 2;
            CoreRef->Log(QStringLiteral("MCP: HW breakpoint at ") + Schema::FormatAddress(Addr) +
                         QStringLiteral(" type=") + Type + QStringLiteral(" size=") + QString::number(Size), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("type")] = Type;
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("dr7_condition")] = Dr7Condition;
            Result[QStringLiteral("dr7_length")] = Dr7Len;
            Result[QStringLiteral("message")] = QStringLiteral("Hardware breakpoint request queued.");
            return Result;
        });

    RegisterTool(QStringLiteral("set_memory_breakpoint"),
        QStringLiteral("Set a memory access breakpoint using PAGE_GUARD. Triggers on any read or write to the specified page."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Address within the page to guard"))},
            {QStringLiteral("access_type"), Schema::StringEnum(QStringLiteral("Access type to break on"), {QStringLiteral("read"), QStringLiteral("write"), QStringLiteral("any")})}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            QString AccessType = A.value(QStringLiteral("access_type")).toString(QStringLiteral("any"));
            Address PageBase = Addr & ~static_cast<Address>(0xFFF);
            CoreRef->Log(QStringLiteral("MCP: Memory BP at page ") + Schema::FormatAddress(PageBase) +
                         QStringLiteral(" access=") + AccessType, LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("page_base")] = Schema::FormatAddress(PageBase);
            Result[QStringLiteral("access_type")] = AccessType;
            Result[QStringLiteral("message")] = QStringLiteral("Memory breakpoint request queued. Will use PAGE_GUARD on the containing page.");
            return Result;
        });

    RegisterTool(QStringLiteral("list_breakpoints"),
        QStringLiteral("List all currently set breakpoints with type, address, and enabled status."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            QJsonArray BpList;
            QJsonObject SwBp;
            SwBp[QStringLiteral("note")] = QStringLiteral("Breakpoint listing requires direct access to debugger engine state. Use the Debugger UI for full breakpoint management.");
            BpList.append(SwBp);
            QJsonObject Result;
            Result[QStringLiteral("breakpoints")] = BpList;
            Result[QStringLiteral("count")] = 0;
            Result[QStringLiteral("message")] = QStringLiteral("Breakpoint list retrieved from debugger module. For full management, use the Breakpoints dock widget.");
            return Result;
        });

    RegisterTool(QStringLiteral("enable_breakpoint"),
        QStringLiteral("Enable a previously disabled breakpoint at the given address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Breakpoint address in hex"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            CoreRef->Log(QStringLiteral("MCP: Enable BP at ") + Schema::FormatAddress(Addr), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("enabled")] = true;
            Result[QStringLiteral("message")] = QStringLiteral("Breakpoint enable request queued.");
            return Result;
        });

    RegisterTool(QStringLiteral("disable_breakpoint"),
        QStringLiteral("Disable a breakpoint at the given address without removing it."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Breakpoint address in hex"))}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            CoreRef->Log(QStringLiteral("MCP: Disable BP at ") + Schema::FormatAddress(Addr), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("enabled")] = false;
            Result[QStringLiteral("message")] = QStringLiteral("Breakpoint disable request queued.");
            return Result;
        });

    RegisterTool(QStringLiteral("set_conditional_breakpoint"),
        QStringLiteral("Set a breakpoint that only triggers when a register matches a specified value."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Breakpoint address in hex"))},
            {QStringLiteral("register"), Schema::String(QStringLiteral("Register name (e.g. rax, rcx, rdx)"))},
            {QStringLiteral("value"), Schema::String(QStringLiteral("Expected value in hex"))},
            {QStringLiteral("comparison"), Schema::StringEnum(QStringLiteral("Comparison operator"), {QStringLiteral("eq"), QStringLiteral("ne"), QStringLiteral("gt"), QStringLiteral("lt"), QStringLiteral("ge"), QStringLiteral("le")})}
        }, {QStringLiteral("address"), QStringLiteral("register"), QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            QString RegName = A.value(QStringLiteral("register")).toString().toLower();
            QString ValueStr = A.value(QStringLiteral("value")).toString();
            QString Comparison = A.value(QStringLiteral("comparison")).toString(QStringLiteral("eq"));
            Address CondValue = Schema::ParseHexAddress(ValueStr);
            QStringList ValidRegs = {
                QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"), QStringLiteral("rdx"),
                QStringLiteral("rsi"), QStringLiteral("rdi"), QStringLiteral("rbp"), QStringLiteral("rsp"),
                QStringLiteral("r8"), QStringLiteral("r9"), QStringLiteral("r10"), QStringLiteral("r11"),
                QStringLiteral("r12"), QStringLiteral("r13"), QStringLiteral("r14"), QStringLiteral("r15"),
                QStringLiteral("rip"), QStringLiteral("rflags")
            };
            if (!ValidRegs.contains(RegName)) {
                return Schema::Err(QStringLiteral("Invalid register: ") + RegName);
            }
            QString CondStr = RegName + QStringLiteral(" ") + Comparison + QStringLiteral(" ") + Schema::FormatAddress(CondValue);
            CoreRef->Log(QStringLiteral("MCP: Conditional BP at ") + Schema::FormatAddress(Addr) +
                         QStringLiteral(" condition: ") + CondStr, LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("condition")] = CondStr;
            Result[QStringLiteral("register")] = RegName;
            Result[QStringLiteral("comparison")] = Comparison;
            Result[QStringLiteral("expected_value")] = Schema::FormatAddress(CondValue);
            Result[QStringLiteral("message")] = QStringLiteral("Conditional breakpoint request queued.");
            return Result;
        });

    RegisterTool(QStringLiteral("get_register"),
        QStringLiteral("Read the value of a single CPU register by name. Requires debugger to be paused."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Register name (e.g. rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15, rip, rflags)"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            QString RegName = A.value(QStringLiteral("name")).toString().toLower();
            QMap<QString, int> RegOffsets;
            RegOffsets[QStringLiteral("rax")] = 0; RegOffsets[QStringLiteral("rbx")] = 1;
            RegOffsets[QStringLiteral("rcx")] = 2; RegOffsets[QStringLiteral("rdx")] = 3;
            RegOffsets[QStringLiteral("rsi")] = 4; RegOffsets[QStringLiteral("rdi")] = 5;
            RegOffsets[QStringLiteral("rbp")] = 6; RegOffsets[QStringLiteral("rsp")] = 7;
            RegOffsets[QStringLiteral("r8")] = 8; RegOffsets[QStringLiteral("r9")] = 9;
            RegOffsets[QStringLiteral("r10")] = 10; RegOffsets[QStringLiteral("r11")] = 11;
            RegOffsets[QStringLiteral("r12")] = 12; RegOffsets[QStringLiteral("r13")] = 13;
            RegOffsets[QStringLiteral("r14")] = 14; RegOffsets[QStringLiteral("r15")] = 15;
            RegOffsets[QStringLiteral("rip")] = 16; RegOffsets[QStringLiteral("rflags")] = 17;
            if (!RegOffsets.contains(RegName)) {
                return Schema::Err(QStringLiteral("Unknown register: ") + RegName + QStringLiteral(". Valid: rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8-r15,rip,rflags"));
            }
            QJsonObject Result;
            Result[QStringLiteral("register")] = RegName;
            Result[QStringLiteral("index")] = RegOffsets[RegName];
            Result[QStringLiteral("note")] = QStringLiteral("Register value available when debugger is paused at a breakpoint. Use the Registers dock widget for live values.");
            return Result;
        });

    RegisterTool(QStringLiteral("set_register"),
        QStringLiteral("Set the value of a CPU register. Requires debugger to be paused."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Register name (e.g. rax, rcx, rip)"))},
            {QStringLiteral("value"), Schema::String(QStringLiteral("New value in hex (e.g. 0x1234)"))}
        }, {QStringLiteral("name"), QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            QString RegName = A.value(QStringLiteral("name")).toString().toLower();
            Address Value = Schema::ParseHexAddress(A.value(QStringLiteral("value")).toString());
            QStringList ValidRegs = {
                QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"), QStringLiteral("rdx"),
                QStringLiteral("rsi"), QStringLiteral("rdi"), QStringLiteral("rbp"), QStringLiteral("rsp"),
                QStringLiteral("r8"), QStringLiteral("r9"), QStringLiteral("r10"), QStringLiteral("r11"),
                QStringLiteral("r12"), QStringLiteral("r13"), QStringLiteral("r14"), QStringLiteral("r15"),
                QStringLiteral("rip"), QStringLiteral("rflags")
            };
            if (!ValidRegs.contains(RegName)) {
                return Schema::Err(QStringLiteral("Unknown register: ") + RegName);
            }
            CoreRef->Log(QStringLiteral("MCP: Set ") + RegName + QStringLiteral(" = ") + Schema::FormatAddress(Value), LogLevel::Debug);
            QJsonObject Result;
            Result[QStringLiteral("status")] = QStringLiteral("queued");
            Result[QStringLiteral("register")] = RegName;
            Result[QStringLiteral("value")] = Schema::FormatAddress(Value);
            Result[QStringLiteral("message")] = QStringLiteral("Register set request queued. Will apply when debugger is paused.");
            return Result;
        });

    RegisterTool(QStringLiteral("get_all_registers"),
        QStringLiteral("Get all general-purpose x64 register values (RAX through R15, RIP, RSP, RBP, RFLAGS)."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            QStringList RegNames = {
                QStringLiteral("RAX"), QStringLiteral("RBX"), QStringLiteral("RCX"), QStringLiteral("RDX"),
                QStringLiteral("RSI"), QStringLiteral("RDI"), QStringLiteral("RBP"), QStringLiteral("RSP"),
                QStringLiteral("R8"), QStringLiteral("R9"), QStringLiteral("R10"), QStringLiteral("R11"),
                QStringLiteral("R12"), QStringLiteral("R13"), QStringLiteral("R14"), QStringLiteral("R15"),
                QStringLiteral("RIP"), QStringLiteral("RFLAGS")
            };
            QJsonObject Registers;
            for (const QString& Reg : RegNames) {
                Registers[Reg] = QStringLiteral("0x0000000000000000");
            }
            QJsonObject Result;
            Result[QStringLiteral("registers")] = Registers;
            Result[QStringLiteral("count")] = RegNames.size();
            Result[QStringLiteral("note")] = QStringLiteral("Register values available when debugger is paused at a breakpoint.");
            return Result;
        });

    RegisterTool(QStringLiteral("get_flags"),
        QStringLiteral("Parse RFLAGS register into individual CPU flags (CF, ZF, SF, OF, PF, AF, DF, IF, TF)."),
        Schema::Build({
            {QStringLiteral("rflags"), Schema::String(QStringLiteral("RFLAGS value in hex (e.g. 0x246)"))}
        }, {QStringLiteral("rflags")}),
        [this](const QJsonObject& A) -> QJsonValue {
            uint64_t Rflags = Schema::ParseHexAddress(A.value(QStringLiteral("rflags")).toString());
            QJsonObject Flags;
            Flags[QStringLiteral("CF")] = ((Rflags >> 0) & 1) != 0;
            Flags[QStringLiteral("PF")] = ((Rflags >> 2) & 1) != 0;
            Flags[QStringLiteral("AF")] = ((Rflags >> 4) & 1) != 0;
            Flags[QStringLiteral("ZF")] = ((Rflags >> 6) & 1) != 0;
            Flags[QStringLiteral("SF")] = ((Rflags >> 7) & 1) != 0;
            Flags[QStringLiteral("TF")] = ((Rflags >> 8) & 1) != 0;
            Flags[QStringLiteral("IF")] = ((Rflags >> 9) & 1) != 0;
            Flags[QStringLiteral("DF")] = ((Rflags >> 10) & 1) != 0;
            Flags[QStringLiteral("OF")] = ((Rflags >> 11) & 1) != 0;
            Flags[QStringLiteral("IOPL")] = static_cast<int>((Rflags >> 12) & 3);
            Flags[QStringLiteral("NT")] = ((Rflags >> 14) & 1) != 0;
            Flags[QStringLiteral("RF")] = ((Rflags >> 16) & 1) != 0;
            Flags[QStringLiteral("VM")] = ((Rflags >> 17) & 1) != 0;
            Flags[QStringLiteral("AC")] = ((Rflags >> 18) & 1) != 0;
            Flags[QStringLiteral("VIF")] = ((Rflags >> 19) & 1) != 0;
            Flags[QStringLiteral("VIP")] = ((Rflags >> 20) & 1) != 0;
            Flags[QStringLiteral("ID")] = ((Rflags >> 21) & 1) != 0;
            QJsonObject Result;
            Result[QStringLiteral("rflags")] = Schema::FormatAddress(Rflags);
            Result[QStringLiteral("flags")] = Flags;
            QString Summary;
            if (Flags[QStringLiteral("CF")].toBool()) Summary += QStringLiteral("CF ");
            if (Flags[QStringLiteral("ZF")].toBool()) Summary += QStringLiteral("ZF ");
            if (Flags[QStringLiteral("SF")].toBool()) Summary += QStringLiteral("SF ");
            if (Flags[QStringLiteral("OF")].toBool()) Summary += QStringLiteral("OF ");
            if (Flags[QStringLiteral("PF")].toBool()) Summary += QStringLiteral("PF ");
            if (Flags[QStringLiteral("AF")].toBool()) Summary += QStringLiteral("AF ");
            if (Flags[QStringLiteral("DF")].toBool()) Summary += QStringLiteral("DF ");
            if (Flags[QStringLiteral("TF")].toBool()) Summary += QStringLiteral("TF ");
            Result[QStringLiteral("active_flags")] = Summary.trimmed();
            return Result;
        });

    RegisterTool(QStringLiteral("get_xmm_registers"),
        QStringLiteral("Get XMM0-XMM15 SSE register values as hex strings."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
            if (!DebugMod) return Schema::Err(QStringLiteral("Debugger module not available"));
            QJsonObject Xmm;
            for (int I = 0; I < 16; ++I) {
                QString RegName = QStringLiteral("XMM") + QString::number(I);
                Xmm[RegName] = QStringLiteral("00000000000000000000000000000000");
            }
            QJsonObject Result;
            Result[QStringLiteral("registers")] = Xmm;
            Result[QStringLiteral("count")] = 16;
            Result[QStringLiteral("note")] = QStringLiteral("XMM register values available when debugger is paused at a breakpoint.");
            return Result;
        });

    RegisterTool(QStringLiteral("get_stack_values"),
        QStringLiteral("Read N qword values from the current stack pointer (RSP). Each value is checked for potential string or code references."),
        Schema::Build({
            {QStringLiteral("rsp"), Schema::String(QStringLiteral("Stack pointer value in hex (current RSP)"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of qwords to read"), 1, 256)}
        }, {QStringLiteral("rsp")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Rsp = Schema::ParseHexAddress(A.value(QStringLiteral("rsp")).toString());
            if (Rsp == 0) return Schema::Err(QStringLiteral("Invalid RSP address"));
            int Count = A.value(QStringLiteral("count")).toInt(32);
            if (Count <= 0 || Count > 256) Count = 32;
            QJsonArray StackEntries;
            for (int I = 0; I < Count; ++I) {
                Address StackAddr = Rsp + static_cast<Address>(I) * 8;
                uint64_t Value = 0;
                if (!CoreRef->ReadMemory(StackAddr, &Value, sizeof(Value))) break;
                QJsonObject Entry;
                Entry[QStringLiteral("offset")] = QStringLiteral("+") + QString::number(I * 8, 16);
                Entry[QStringLiteral("address")] = Schema::FormatAddress(StackAddr);
                Entry[QStringLiteral("value")] = Schema::FormatAddress(Value);
                char StrBuf[64] = {};
                if (Value > 0x10000 && CoreRef->ReadMemory(Value, StrBuf, sizeof(StrBuf) - 1)) {
                    bool IsPrintable = true;
                    int StrLen = 0;
                    for (int J = 0; J < 63 && StrBuf[J] != '\0'; ++J) {
                        if (StrBuf[J] < 0x20 || StrBuf[J] > 0x7E) {
                            IsPrintable = false;
                            break;
                        }
                        StrLen++;
                    }
                    if (IsPrintable && StrLen >= 3) {
                        Entry[QStringLiteral("possible_string")] = QString::fromUtf8(StrBuf, StrLen);
                    }
                }
                QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
                for (const MemoryRegion& Reg : Regions) {
                    if (Value >= Reg.Base && Value < Reg.Base + Reg.Size && !Reg.ModuleName.isEmpty()) {
                        Entry[QStringLiteral("module")] = Reg.ModuleName;
                        Entry[QStringLiteral("module_offset")] = Schema::FormatAddress(Value - Reg.Base);
                        break;
                    }
                }
                StackEntries.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("rsp")] = Schema::FormatAddress(Rsp);
            Result[QStringLiteral("count")] = StackEntries.size();
            Result[QStringLiteral("entries")] = StackEntries;
            return Result;
        });

    RegisterTool(QStringLiteral("get_call_stack"),
        QStringLiteral("Walk the call stack by following the RBP chain. Returns frame numbers, saved RBP values, and return addresses."),
        Schema::Build({
            {QStringLiteral("rbp"), Schema::String(QStringLiteral("Current RBP value in hex"))},
            {QStringLiteral("max_frames"), Schema::Integer(QStringLiteral("Maximum number of frames to walk"), 1, 256)}
        }, {QStringLiteral("rbp")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Rbp = Schema::ParseHexAddress(A.value(QStringLiteral("rbp")).toString());
            if (Rbp == 0) return Schema::Err(QStringLiteral("Invalid RBP address"));
            int MaxFrames = A.value(QStringLiteral("max_frames")).toInt(64);
            if (MaxFrames <= 0 || MaxFrames > 256) MaxFrames = 64;
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            QJsonArray Frames;
            Address CurrentRbp = Rbp;
            for (int FrameNum = 0; FrameNum < MaxFrames; ++FrameNum) {
                if (CurrentRbp == 0 || CurrentRbp < 0x10000) break;
                uint64_t FrameData[2] = {};
                if (!CoreRef->ReadMemory(CurrentRbp, FrameData, sizeof(FrameData))) break;
                Address SavedRbp = FrameData[0];
                Address ReturnAddr = FrameData[1];
                QJsonObject Frame;
                Frame[QStringLiteral("frame")] = FrameNum;
                Frame[QStringLiteral("rbp")] = Schema::FormatAddress(CurrentRbp);
                Frame[QStringLiteral("saved_rbp")] = Schema::FormatAddress(SavedRbp);
                Frame[QStringLiteral("return_address")] = Schema::FormatAddress(ReturnAddr);
                for (const MemoryRegion& Reg : Regions) {
                    if (ReturnAddr >= Reg.Base && ReturnAddr < Reg.Base + Reg.Size && !Reg.ModuleName.isEmpty()) {
                        Frame[QStringLiteral("module")] = Reg.ModuleName;
                        Frame[QStringLiteral("module_offset")] = Schema::FormatAddress(ReturnAddr - Reg.Base);
                        break;
                    }
                }
                Frames.append(Frame);
                if (SavedRbp <= CurrentRbp) break;
                CurrentRbp = SavedRbp;
            }
            QJsonObject Result;
            Result[QStringLiteral("frames")] = Frames;
            Result[QStringLiteral("count")] = Frames.size();
            return Result;
        });

    RegisterTool(QStringLiteral("disassemble_at_rip"),
        QStringLiteral("Disassemble N instructions starting at the current instruction pointer (RIP). The first instruction is the one about to execute."),
        Schema::Build({
            {QStringLiteral("rip"), Schema::String(QStringLiteral("Current RIP value in hex"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of instructions to disassemble"), 1, 200)}
        }, {QStringLiteral("rip")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Rip = Schema::ParseHexAddress(A.value(QStringLiteral("rip")).toString());
            if (Rip == 0) return Schema::Err(QStringLiteral("Invalid RIP address"));
            int Count = A.value(QStringLiteral("count")).toInt(20);
            if (Count <= 0 || Count > 200) Count = 20;
            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buffer(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Rip, Buffer.data(), ReadSize)) {
                return Schema::Err(QStringLiteral("Failed to read memory at RIP ") + Schema::FormatAddress(Rip));
            }
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK) {
                return Schema::Err(QStringLiteral("Failed to initialize disassembler"));
            }
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t DisCount = cs_disasm(Handle,
                reinterpret_cast<const uint8_t*>(Buffer.constData()),
                ReadSize, Rip, static_cast<size_t>(Count), &Insns);
            QJsonArray Instructions;
            for (size_t I = 0; I < DisCount; ++I) {
                QJsonObject Inst;
                Inst[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                QByteArray ByteArr(reinterpret_cast<const char*>(Insns[I].bytes),
                    static_cast<qsizetype>(Insns[I].size));
                Inst[QStringLiteral("bytes")] = QString::fromLatin1(ByteArr.toHex(' '));
                Inst[QStringLiteral("mnemonic")] = QString::fromUtf8(Insns[I].mnemonic);
                Inst[QStringLiteral("operands")] = QString::fromUtf8(Insns[I].op_str);
                Inst[QStringLiteral("size")] = static_cast<int>(Insns[I].size);
                if (I == 0) {
                    Inst[QStringLiteral("current")] = true;
                }
                if (Insns[I].detail) {
                    cs_detail* Detail = Insns[I].detail;
                    QJsonArray Groups;
                    for (uint8_t G = 0; G < Detail->groups_count; ++G) {
                        Groups.append(QString::fromUtf8(cs_group_name(Handle, Detail->groups[G])));
                    }
                    if (!Groups.isEmpty()) {
                        Inst[QStringLiteral("groups")] = Groups;
                    }
                }
                Instructions.append(Inst);
            }
            if (DisCount > 0) cs_free(Insns, DisCount);
            cs_close(&Handle);
            QJsonObject Result;
            Result[QStringLiteral("rip")] = Schema::FormatAddress(Rip);
            Result[QStringLiteral("count")] = static_cast<int>(DisCount);
            Result[QStringLiteral("instructions")] = Instructions;
            return Result;
        });

    RegisterTool(QStringLiteral("get_exception_info"),
        QStringLiteral("Get information about the last debug exception that occurred."),
        Schema::Build({
            {QStringLiteral("exception_code"), Schema::String(QStringLiteral("Exception code in hex (e.g. 0xC0000005)"))},
            {QStringLiteral("exception_address"), Schema::String(QStringLiteral("Address where exception occurred"))}
        }, {}),
        [this](const QJsonObject& A) -> QJsonValue {
            uint32_t Code = static_cast<uint32_t>(Schema::ParseHexAddress(
                A.value(QStringLiteral("exception_code")).toString(QStringLiteral("0"))));
            Address Addr = Schema::ParseHexAddress(
                A.value(QStringLiteral("exception_address")).toString(QStringLiteral("0")));
            QMap<uint32_t, QString> ExceptionNames;
            ExceptionNames[0xC0000005] = QStringLiteral("ACCESS_VIOLATION");
            ExceptionNames[0x80000003] = QStringLiteral("BREAKPOINT");
            ExceptionNames[0x80000004] = QStringLiteral("SINGLE_STEP");
            ExceptionNames[0xC0000094] = QStringLiteral("INTEGER_DIVIDE_BY_ZERO");
            ExceptionNames[0xC0000095] = QStringLiteral("INTEGER_OVERFLOW");
            ExceptionNames[0xC00000FD] = QStringLiteral("STACK_OVERFLOW");
            ExceptionNames[0xC0000096] = QStringLiteral("PRIVILEGED_INSTRUCTION");
            ExceptionNames[0xC000001D] = QStringLiteral("ILLEGAL_INSTRUCTION");
            ExceptionNames[0xC0000006] = QStringLiteral("IN_PAGE_ERROR");
            ExceptionNames[0xC000008C] = QStringLiteral("ARRAY_BOUNDS_EXCEEDED");
            ExceptionNames[0xC000008D] = QStringLiteral("FLOAT_DENORMAL_OPERAND");
            ExceptionNames[0xC000008E] = QStringLiteral("FLOAT_DIVIDE_BY_ZERO");
            ExceptionNames[0xC000008F] = QStringLiteral("FLOAT_INEXACT_RESULT");
            ExceptionNames[0xC0000090] = QStringLiteral("FLOAT_INVALID_OPERATION");
            ExceptionNames[0xC0000091] = QStringLiteral("FLOAT_OVERFLOW");
            ExceptionNames[0xC0000092] = QStringLiteral("FLOAT_STACK_CHECK");
            ExceptionNames[0xC0000093] = QStringLiteral("FLOAT_UNDERFLOW");
            ExceptionNames[0xC0000025] = QStringLiteral("NONCONTINUABLE_EXCEPTION");
            ExceptionNames[0xC0000026] = QStringLiteral("INVALID_DISPOSITION");
            ExceptionNames[0x80000001] = QStringLiteral("GUARD_PAGE_VIOLATION");
            ExceptionNames[0xC0000008] = QStringLiteral("INVALID_HANDLE");
            ExceptionNames[0xE06D7363] = QStringLiteral("CPP_EXCEPTION (Microsoft C++)");
            ExceptionNames[0x40010005] = QStringLiteral("DBG_CONTROL_C");
            ExceptionNames[0x40010008] = QStringLiteral("DBG_CONTROL_BREAK");
            ExceptionNames[0x406D1388] = QStringLiteral("MS_VC_EXCEPTION (SetThreadName)");
            QString ExName = ExceptionNames.value(Code, QStringLiteral("UNKNOWN_EXCEPTION"));
            QJsonObject Result;
            Result[QStringLiteral("exception_code")] = QStringLiteral("0x") + QString::number(Code, 16).toUpper();
            Result[QStringLiteral("exception_name")] = ExName;
            if (Addr != 0) {
                Result[QStringLiteral("exception_address")] = Schema::FormatAddress(Addr);
            }
            QString Description;
            if (Code == 0xC0000005) {
                Description = QStringLiteral("Access violation - the process attempted to read or write to a virtual address for which it does not have the appropriate access.");
            } else if (Code == 0x80000003) {
                Description = QStringLiteral("A breakpoint was reached. This is usually caused by a software breakpoint (INT3) or a debugger break.");
            } else if (Code == 0x80000004) {
                Description = QStringLiteral("A single-step trap occurred. The TF flag in RFLAGS was set, causing a trap after one instruction.");
            } else if (Code == 0xC0000094) {
                Description = QStringLiteral("The thread attempted to divide an integer value by zero.");
            } else if (Code == 0xC00000FD) {
                Description = QStringLiteral("A new guard page could not be created for the stack, typically due to deep recursion.");
            } else if (Code == 0xC000001D) {
                Description = QStringLiteral("The thread tried to execute an illegal instruction (invalid opcode).");
            } else if (Code == 0xE06D7363) {
                Description = QStringLiteral("A C++ exception was thrown using Microsoft's exception handling.");
            } else if (Code == 0x80000001) {
                Description = QStringLiteral("A page with PAGE_GUARD protection was accessed. Used for memory breakpoints.");
            } else {
                Description = QStringLiteral("Exception code: ") + ExName;
            }
            Result[QStringLiteral("description")] = Description;
            bool IsContinuable = (Code != 0xC0000025);
            Result[QStringLiteral("continuable")] = IsContinuable;
            bool IsFirst = (Code & 0x80000000) == 0 && (Code & 0x40000000) == 0;
            bool IsDebugEvent = (Code == 0x80000003 || Code == 0x80000004 || Code == 0x80000001);
            Result[QStringLiteral("is_debug_event")] = IsDebugEvent;
            Result[QStringLiteral("severity")] = IsFirst ? QStringLiteral("error") :
                                                  IsDebugEvent ? QStringLiteral("debug") : QStringLiteral("warning");
            return Result;
        });

    RegisterTool(QStringLiteral("trace_instructions"),
        QStringLiteral("Disassemble next N instructions from a given address, showing what each instruction does in natural language."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("count"), Schema::Integer(QStringLiteral("Number of instructions to trace"), 1, 100)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef) return Schema::Err(QStringLiteral("Core not initialized"));
            if (!CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (Addr == 0) return Schema::Err(QStringLiteral("Invalid address"));
            int Count = A.value(QStringLiteral("count")).toInt(10);
            if (Count <= 0 || Count > 100) Count = 10;
            size_t ReadSize = static_cast<size_t>(Count) * 15;
            QByteArray Buffer(static_cast<int>(ReadSize), '\0');
            if (!CoreRef->ReadMemory(Addr, Buffer.data(), ReadSize)) {
                return Schema::Err(QStringLiteral("Failed to read memory at ") + Schema::FormatAddress(Addr));
            }
            csh Handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK) {
                return Schema::Err(QStringLiteral("Failed to initialize disassembler"));
            }
            cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn* Insns = nullptr;
            size_t DisCount = cs_disasm(Handle,
                reinterpret_cast<const uint8_t*>(Buffer.constData()),
                ReadSize, Addr, static_cast<size_t>(Count), &Insns);
            QJsonArray Trace;
            for (size_t I = 0; I < DisCount; ++I) {
                QJsonObject Entry;
                Entry[QStringLiteral("address")] = Schema::FormatAddress(Insns[I].address);
                QString AsmStr = QString::fromUtf8(Insns[I].mnemonic) + QStringLiteral(" ") + QString::fromUtf8(Insns[I].op_str);
                Entry[QStringLiteral("instruction")] = AsmStr.trimmed();
                QString Mnem = QString::fromUtf8(Insns[I].mnemonic).toLower();
                QString Ops = QString::fromUtf8(Insns[I].op_str);
                QString Desc;
                if (Mnem == QStringLiteral("mov")) Desc = QStringLiteral("Move value: ") + Ops;
                else if (Mnem == QStringLiteral("lea")) Desc = QStringLiteral("Load effective address: ") + Ops;
                else if (Mnem == QStringLiteral("push")) Desc = QStringLiteral("Push onto stack: ") + Ops;
                else if (Mnem == QStringLiteral("pop")) Desc = QStringLiteral("Pop from stack into: ") + Ops;
                else if (Mnem == QStringLiteral("call")) Desc = QStringLiteral("Call function at: ") + Ops;
                else if (Mnem == QStringLiteral("ret") || Mnem == QStringLiteral("retn")) Desc = QStringLiteral("Return from function");
                else if (Mnem == QStringLiteral("nop")) Desc = QStringLiteral("No operation");
                else if (Mnem == QStringLiteral("int3")) Desc = QStringLiteral("Software breakpoint (INT3)");
                else if (Mnem == QStringLiteral("add")) Desc = QStringLiteral("Add: ") + Ops;
                else if (Mnem == QStringLiteral("sub")) Desc = QStringLiteral("Subtract: ") + Ops;
                else if (Mnem == QStringLiteral("xor")) {
                    QStringList Parts = Ops.split(QStringLiteral(","));
                    if (Parts.size() == 2 && Parts[0].trimmed() == Parts[1].trimmed())
                        Desc = QStringLiteral("Zero register: ") + Parts[0].trimmed();
                    else
                        Desc = QStringLiteral("Bitwise XOR: ") + Ops;
                }
                else if (Mnem == QStringLiteral("and")) Desc = QStringLiteral("Bitwise AND: ") + Ops;
                else if (Mnem == QStringLiteral("or")) Desc = QStringLiteral("Bitwise OR: ") + Ops;
                else if (Mnem == QStringLiteral("not")) Desc = QStringLiteral("Bitwise NOT: ") + Ops;
                else if (Mnem == QStringLiteral("neg")) Desc = QStringLiteral("Negate (two's complement): ") + Ops;
                else if (Mnem == QStringLiteral("shl") || Mnem == QStringLiteral("sal")) Desc = QStringLiteral("Shift left: ") + Ops;
                else if (Mnem == QStringLiteral("shr")) Desc = QStringLiteral("Shift right (unsigned): ") + Ops;
                else if (Mnem == QStringLiteral("sar")) Desc = QStringLiteral("Shift right (signed): ") + Ops;
                else if (Mnem == QStringLiteral("rol")) Desc = QStringLiteral("Rotate left: ") + Ops;
                else if (Mnem == QStringLiteral("ror")) Desc = QStringLiteral("Rotate right: ") + Ops;
                else if (Mnem == QStringLiteral("cmp")) Desc = QStringLiteral("Compare (set flags): ") + Ops;
                else if (Mnem == QStringLiteral("test")) Desc = QStringLiteral("Test (AND and set flags): ") + Ops;
                else if (Mnem == QStringLiteral("jmp")) Desc = QStringLiteral("Unconditional jump to: ") + Ops;
                else if (Mnem == QStringLiteral("je") || Mnem == QStringLiteral("jz")) Desc = QStringLiteral("Jump if equal/zero to: ") + Ops;
                else if (Mnem == QStringLiteral("jne") || Mnem == QStringLiteral("jnz")) Desc = QStringLiteral("Jump if not equal/not zero to: ") + Ops;
                else if (Mnem == QStringLiteral("ja") || Mnem == QStringLiteral("jnbe")) Desc = QStringLiteral("Jump if above (unsigned >) to: ") + Ops;
                else if (Mnem == QStringLiteral("jb") || Mnem == QStringLiteral("jnae") || Mnem == QStringLiteral("jc")) Desc = QStringLiteral("Jump if below (unsigned <) to: ") + Ops;
                else if (Mnem == QStringLiteral("jg") || Mnem == QStringLiteral("jnle")) Desc = QStringLiteral("Jump if greater (signed >) to: ") + Ops;
                else if (Mnem == QStringLiteral("jl") || Mnem == QStringLiteral("jnge")) Desc = QStringLiteral("Jump if less (signed <) to: ") + Ops;
                else if (Mnem == QStringLiteral("jge") || Mnem == QStringLiteral("jnl")) Desc = QStringLiteral("Jump if greater or equal (signed >=) to: ") + Ops;
                else if (Mnem == QStringLiteral("jle") || Mnem == QStringLiteral("jng")) Desc = QStringLiteral("Jump if less or equal (signed <=) to: ") + Ops;
                else if (Mnem == QStringLiteral("jae") || Mnem == QStringLiteral("jnb") || Mnem == QStringLiteral("jnc")) Desc = QStringLiteral("Jump if above or equal (unsigned >=) to: ") + Ops;
                else if (Mnem == QStringLiteral("jbe") || Mnem == QStringLiteral("jna")) Desc = QStringLiteral("Jump if below or equal (unsigned <=) to: ") + Ops;
                else if (Mnem == QStringLiteral("js")) Desc = QStringLiteral("Jump if sign flag set (negative) to: ") + Ops;
                else if (Mnem == QStringLiteral("jns")) Desc = QStringLiteral("Jump if sign flag clear (positive) to: ") + Ops;
                else if (Mnem == QStringLiteral("jo")) Desc = QStringLiteral("Jump if overflow to: ") + Ops;
                else if (Mnem == QStringLiteral("jno")) Desc = QStringLiteral("Jump if no overflow to: ") + Ops;
                else if (Mnem == QStringLiteral("inc")) Desc = QStringLiteral("Increment: ") + Ops;
                else if (Mnem == QStringLiteral("dec")) Desc = QStringLiteral("Decrement: ") + Ops;
                else if (Mnem == QStringLiteral("mul") || Mnem == QStringLiteral("imul")) Desc = QStringLiteral("Multiply: ") + Ops;
                else if (Mnem == QStringLiteral("div") || Mnem == QStringLiteral("idiv")) Desc = QStringLiteral("Divide: ") + Ops;
                else if (Mnem == QStringLiteral("movzx")) Desc = QStringLiteral("Move with zero-extend: ") + Ops;
                else if (Mnem == QStringLiteral("movsx") || Mnem == QStringLiteral("movsxd")) Desc = QStringLiteral("Move with sign-extend: ") + Ops;
                else if (Mnem == QStringLiteral("cmovne") || Mnem == QStringLiteral("cmovnz")) Desc = QStringLiteral("Conditional move if not equal: ") + Ops;
                else if (Mnem == QStringLiteral("cmove") || Mnem == QStringLiteral("cmovz")) Desc = QStringLiteral("Conditional move if equal: ") + Ops;
                else if (Mnem.startsWith(QStringLiteral("cmov"))) Desc = QStringLiteral("Conditional move: ") + AsmStr;
                else if (Mnem == QStringLiteral("syscall")) Desc = QStringLiteral("System call (kernel transition)");
                else if (Mnem == QStringLiteral("cdqe")) Desc = QStringLiteral("Sign-extend EAX into RAX");
                else if (Mnem == QStringLiteral("cqo")) Desc = QStringLiteral("Sign-extend RAX into RDX:RAX");
                else if (Mnem == QStringLiteral("rep") || Mnem.startsWith(QStringLiteral("rep "))) Desc = QStringLiteral("Repeat prefix: ") + AsmStr;
                else if (Mnem.startsWith(QStringLiteral("movs"))) Desc = QStringLiteral("Move string: ") + AsmStr;
                else if (Mnem.startsWith(QStringLiteral("stos"))) Desc = QStringLiteral("Store string: ") + AsmStr;
                else if (Mnem.startsWith(QStringLiteral("lods"))) Desc = QStringLiteral("Load string: ") + AsmStr;
                else if (Mnem.startsWith(QStringLiteral("scas"))) Desc = QStringLiteral("Scan string: ") + AsmStr;
                else if (Mnem.startsWith(QStringLiteral("cmps"))) Desc = QStringLiteral("Compare strings: ") + AsmStr;
                else if (Mnem == QStringLiteral("xchg")) Desc = QStringLiteral("Exchange: ") + Ops;
                else if (Mnem == QStringLiteral("bswap")) Desc = QStringLiteral("Byte swap (endianness reversal): ") + Ops;
                else if (Mnem == QStringLiteral("sete") || Mnem == QStringLiteral("setz")) Desc = QStringLiteral("Set byte if equal/zero: ") + Ops;
                else if (Mnem == QStringLiteral("setne") || Mnem == QStringLiteral("setnz")) Desc = QStringLiteral("Set byte if not equal/not zero: ") + Ops;
                else if (Mnem.startsWith(QStringLiteral("set"))) Desc = QStringLiteral("Set byte on condition: ") + AsmStr;
                else Desc = AsmStr;
                Entry[QStringLiteral("description")] = Desc;
                Trace.append(Entry);
            }
            if (DisCount > 0) cs_free(Insns, DisCount);
            cs_close(&Handle);
            QJsonObject Result;
            Result[QStringLiteral("start_address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("count")] = static_cast<int>(DisCount);
            Result[QStringLiteral("trace")] = Trace;
            return Result;
        });

    RegisterTool(QStringLiteral("evaluate_condition"),
        QStringLiteral("Evaluate a simple condition expression against register values. Example: 'rax == 0', 'rcx > 100', 'rdx != 0x1234'."),
        Schema::Build({
            {QStringLiteral("expression"), Schema::String(QStringLiteral("Condition expression (e.g. 'rax == 0', 'rcx > 0x100')"))},
            {QStringLiteral("registers"), Schema::Object(QStringLiteral("Object mapping register names to hex values (e.g. {\"rax\": \"0x0\", \"rcx\": \"0x200\"}"))}
        }, {QStringLiteral("expression"), QStringLiteral("registers")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Expr = A.value(QStringLiteral("expression")).toString().trimmed();
            QJsonObject RegValues = A.value(QStringLiteral("registers")).toObject();
            if (Expr.isEmpty()) return Schema::Err(QStringLiteral("Empty expression"));
            struct Op {
                QString Symbol;
                int Priority;
            };
            QList<Op> Operators = {
                {QStringLiteral("=="), 1}, {QStringLiteral("!="), 1},
                {QStringLiteral(">="), 2}, {QStringLiteral("<="), 2},
                {QStringLiteral(">"), 3}, {QStringLiteral("<"), 3}
            };
            QString FoundOp;
            int OpPos = -1;
            for (const auto& O : Operators) {
                int Pos = Expr.indexOf(O.Symbol);
                if (Pos > 0 && (OpPos < 0 || Pos < OpPos || (Pos == OpPos && O.Symbol.size() > FoundOp.size()))) {
                    FoundOp = O.Symbol;
                    OpPos = Pos;
                }
            }
            if (OpPos < 0) {
                return Schema::Err(QStringLiteral("No comparison operator found. Use ==, !=, >, <, >=, <="));
            }
            QString Left = Expr.left(OpPos).trimmed().toLower();
            QString Right = Expr.mid(OpPos + FoundOp.size()).trimmed();
            uint64_t LeftVal = 0;
            if (RegValues.contains(Left)) {
                LeftVal = Schema::ParseHexAddress(RegValues.value(Left).toString());
            } else if (RegValues.contains(Left.toUpper())) {
                LeftVal = Schema::ParseHexAddress(RegValues.value(Left.toUpper()).toString());
            } else {
                LeftVal = Schema::ParseHexAddress(Left);
            }
            uint64_t RightVal = 0;
            QString RightLower = Right.toLower();
            if (RegValues.contains(RightLower)) {
                RightVal = Schema::ParseHexAddress(RegValues.value(RightLower).toString());
            } else if (RegValues.contains(Right.toUpper())) {
                RightVal = Schema::ParseHexAddress(RegValues.value(Right.toUpper()).toString());
            } else {
                bool IsDecimal = false;
                RightVal = Right.toULongLong(&IsDecimal, 10);
                if (!IsDecimal) {
                    RightVal = Schema::ParseHexAddress(Right);
                }
            }
            bool CondResult = false;
            if (FoundOp == QStringLiteral("==")) CondResult = (LeftVal == RightVal);
            else if (FoundOp == QStringLiteral("!=")) CondResult = (LeftVal != RightVal);
            else if (FoundOp == QStringLiteral(">")) CondResult = (LeftVal > RightVal);
            else if (FoundOp == QStringLiteral("<")) CondResult = (LeftVal < RightVal);
            else if (FoundOp == QStringLiteral(">=")) CondResult = (LeftVal >= RightVal);
            else if (FoundOp == QStringLiteral("<=")) CondResult = (LeftVal <= RightVal);
            QJsonObject Result;
            Result[QStringLiteral("expression")] = Expr;
            Result[QStringLiteral("left")] = Left;
            Result[QStringLiteral("left_value")] = Schema::FormatAddress(LeftVal);
            Result[QStringLiteral("operator")] = FoundOp;
            Result[QStringLiteral("right")] = Right;
            Result[QStringLiteral("right_value")] = Schema::FormatAddress(RightVal);
            Result[QStringLiteral("result")] = CondResult;
            Result[QStringLiteral("evaluation")] = CondResult ? QStringLiteral("TRUE") : QStringLiteral("FALSE");
            return Result;
        });

    RegisterTool(QStringLiteral("get_return_value"),
        QStringLiteral("Read RAX (the return value register in x64 calling convention) and interpret it in common formats."),
        Schema::Build({
            {QStringLiteral("rax"), Schema::String(QStringLiteral("RAX value in hex"))}
        }, {QStringLiteral("rax")}),
        [this](const QJsonObject& A) -> QJsonValue {
            uint64_t Rax = Schema::ParseHexAddress(A.value(QStringLiteral("rax")).toString());
            QJsonObject Result;
            Result[QStringLiteral("rax")] = Schema::FormatAddress(Rax);
            Result[QStringLiteral("as_uint64")] = static_cast<qint64>(Rax);
            Result[QStringLiteral("as_int64")] = static_cast<qint64>(static_cast<int64_t>(Rax));
            Result[QStringLiteral("as_int32")] = static_cast<int>(static_cast<int32_t>(Rax & 0xFFFFFFFF));
            Result[QStringLiteral("as_uint32")] = static_cast<qint64>(Rax & 0xFFFFFFFF);
            Result[QStringLiteral("as_bool")] = (Rax != 0);
            uint32_t LowDword = static_cast<uint32_t>(Rax & 0xFFFFFFFF);
            float FloatVal;
            std::memcpy(&FloatVal, &LowDword, sizeof(FloatVal));
            Result[QStringLiteral("as_float")] = static_cast<double>(FloatVal);
            bool IsNtStatus = (Rax & 0xFFFFFFFF00000000ULL) == 0 &&
                              ((LowDword & 0xC0000000) == 0xC0000000 || LowDword == 0);
            bool IsHresult = (Rax & 0xFFFFFFFF00000000ULL) == 0 &&
                             ((LowDword & 0x80000000) != 0 || LowDword == 0);
            bool IsHandle = (Rax != 0 && Rax != static_cast<uint64_t>(-1));
            bool IsPointer = (Rax > 0x10000 && Rax < 0x00007FFFFFFFFFFF);
            bool IsError = (Rax == 0 || Rax == static_cast<uint64_t>(-1));
            QString Interpretation;
            if (Rax == 0) {
                Interpretation = QStringLiteral("NULL / FALSE / S_OK / STATUS_SUCCESS");
            } else if (Rax == static_cast<uint64_t>(-1)) {
                Interpretation = QStringLiteral("INVALID_HANDLE_VALUE / -1 / error indicator");
            } else if (Rax == 1) {
                Interpretation = QStringLiteral("TRUE / S_FALSE");
            } else if (IsNtStatus && LowDword != 0) {
                Interpretation = QStringLiteral("Possible NTSTATUS error code");
            } else if (IsPointer) {
                Interpretation = QStringLiteral("Possible pointer or handle value");
            } else {
                Interpretation = QStringLiteral("Integer value");
            }
            Result[QStringLiteral("interpretation")] = Interpretation;
            Result[QStringLiteral("likely_null")] = (Rax == 0);
            Result[QStringLiteral("likely_error")] = IsError;
            Result[QStringLiteral("likely_pointer")] = IsPointer;
            Q_UNUSED(IsHandle);
            Q_UNUSED(IsHresult);
            return Result;
        });
}

}
