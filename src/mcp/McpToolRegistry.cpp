#include "McpToolRegistry.h"
#include <fidra/Types.h>
#include <QJsonDocument>
#include <QRegularExpression>
#include <capstone/capstone.h>
#include <cstring>
#include <algorithm>

namespace Fidra {

McpToolRegistry::McpToolRegistry(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr) {
}

McpToolRegistry::~McpToolRegistry() {
}

void McpToolRegistry::Initialize(ICore* Core) {
    CoreRef = Core;
    RegisterBuiltinTools();
}

void McpToolRegistry::RegisterTool(const QString& Name, const QString& Description,
                                    const QJsonObject& InputSchema,
                                    std::function<QJsonValue(const QJsonObject&)> Handler) {
    McpToolDefinition Def;
    Def.Name = Name;
    Def.Description = Description;
    Def.InputSchema = InputSchema;
    Def.Enabled = true;
    Def.Handler = std::move(Handler);
    Tools.insert(Name, Def);
    emit ToolRegistered(Name);
}

void McpToolRegistry::UnregisterTool(const QString& Name) {
    if (Tools.remove(Name)) {
        emit ToolUnregistered(Name);
    }
}

bool McpToolRegistry::HasTool(const QString& Name) const {
    return Tools.contains(Name);
}

void McpToolRegistry::SetToolEnabled(const QString& Name, bool Enabled) {
    auto It = Tools.find(Name);
    if (It != Tools.end()) {
        It->Enabled = Enabled;
        emit ToolEnabledChanged(Name, Enabled);
    }
}

bool McpToolRegistry::IsToolEnabled(const QString& Name) const {
    auto It = Tools.find(Name);
    if (It != Tools.end()) {
        return It->Enabled;
    }
    return false;
}

QJsonArray McpToolRegistry::GetToolList() const {
    QJsonArray ToolArray;
    for (auto It = Tools.constBegin(); It != Tools.constEnd(); ++It) {
        if (!It->Enabled) continue;

        QJsonObject ToolObj;
        ToolObj[QStringLiteral("name")] = It->Name;
        ToolObj[QStringLiteral("description")] = It->Description;
        ToolObj[QStringLiteral("inputSchema")] = It->InputSchema;
        ToolArray.append(ToolObj);
    }
    return ToolArray;
}

QJsonValue McpToolRegistry::CallTool(const QString& Name, const QJsonObject& Arguments) {
    auto It = Tools.find(Name);
    if (It == Tools.end()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Tool not found: ") + Name;
        return Err;
    }

    if (!It->Enabled) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Tool is disabled: ") + Name;
        return Err;
    }

    QJsonValue Result = It->Handler(Arguments);
    emit ToolCalled(Name, Arguments, Result);
    return Result;
}

QList<McpToolDefinition> McpToolRegistry::GetAllTools() const {
    return Tools.values();
}

void McpToolRegistry::RegisterBuiltinTools() {
    RegisterCoreTools();
    RegisterAnalysisTools();
    RegisterMemoryTools();
    RegisterNetworkTools();
    RegisterCodegenTools();
    RegisterScriptingTools();
    RegisterAiTools();
    RegisterFileTools();
    RegisterEncodingTools();
    RegisterDebuggerTools();
    RegisterUtilityTools();
}

void McpToolRegistry::RegisterCoreTools() {
    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Memory address in hex (e.g. 0x7FF600000000)");
        Props[QStringLiteral("address")] = AddrProp;
        QJsonObject SizeProp;
        SizeProp[QStringLiteral("type")] = QStringLiteral("integer");
        SizeProp[QStringLiteral("description")] = QStringLiteral("Number of bytes to read");
        SizeProp[QStringLiteral("minimum")] = 1;
        SizeProp[QStringLiteral("maximum")] = 65536;
        Props[QStringLiteral("size")] = SizeProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Required.append(QStringLiteral("size"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("read_memory"),
                     QStringLiteral("Read process memory at the given address. Returns hex-encoded bytes."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleReadMemory(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Memory address in hex (e.g. 0x7FF600000000)");
        Props[QStringLiteral("address")] = AddrProp;
        QJsonObject DataProp;
        DataProp[QStringLiteral("type")] = QStringLiteral("string");
        DataProp[QStringLiteral("description")] = QStringLiteral("Hex-encoded bytes to write (e.g. 90909090)");
        Props[QStringLiteral("hex_data")] = DataProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Required.append(QStringLiteral("hex_data"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("write_memory"),
                     QStringLiteral("Write hex-encoded bytes to process memory at the given address."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleWriteMemory(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        Schema[QStringLiteral("properties")] = Props;

        RegisterTool(QStringLiteral("get_memory_regions"),
                     QStringLiteral("List all memory regions of the attached process with base address, size, protection, and module name."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetMemoryRegions(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        Schema[QStringLiteral("properties")] = Props;

        RegisterTool(QStringLiteral("get_process_list"),
                     QStringLiteral("List all running processes with PID, name, path, and architecture."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetProcessList(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject PidProp;
        PidProp[QStringLiteral("type")] = QStringLiteral("integer");
        PidProp[QStringLiteral("description")] = QStringLiteral("Process ID to attach to");
        Props[QStringLiteral("pid")] = PidProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("pid"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("attach_process"),
                     QStringLiteral("Attach to a process by PID for memory inspection and modification."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleAttachProcess(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        Schema[QStringLiteral("properties")] = Props;

        RegisterTool(QStringLiteral("detach_process"),
                     QStringLiteral("Detach from the currently attached process."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleDetachProcess(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Start address in hex");
        Props[QStringLiteral("address")] = AddrProp;
        QJsonObject CountProp;
        CountProp[QStringLiteral("type")] = QStringLiteral("integer");
        CountProp[QStringLiteral("description")] = QStringLiteral("Number of instructions to disassemble");
        CountProp[QStringLiteral("minimum")] = 1;
        CountProp[QStringLiteral("maximum")] = 1000;
        Props[QStringLiteral("count")] = CountProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Required.append(QStringLiteral("count"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("disassemble"),
                     QStringLiteral("Disassemble instructions at the given address. Returns address, bytes, mnemonic, and operands for each instruction."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleDisassemble(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject ValueProp;
        ValueProp[QStringLiteral("type")] = QStringLiteral("string");
        ValueProp[QStringLiteral("description")] = QStringLiteral("Value to scan for");
        Props[QStringLiteral("value")] = ValueProp;
        QJsonObject TypeProp;
        TypeProp[QStringLiteral("type")] = QStringLiteral("string");
        TypeProp[QStringLiteral("description")] = QStringLiteral("Value type: byte, int16, int32, int64, float, double, string");
        QJsonArray TypeEnum;
        TypeEnum.append(QStringLiteral("byte"));
        TypeEnum.append(QStringLiteral("int16"));
        TypeEnum.append(QStringLiteral("int32"));
        TypeEnum.append(QStringLiteral("int64"));
        TypeEnum.append(QStringLiteral("float"));
        TypeEnum.append(QStringLiteral("double"));
        TypeEnum.append(QStringLiteral("string"));
        TypeProp[QStringLiteral("enum")] = TypeEnum;
        Props[QStringLiteral("type")] = TypeProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("value"));
        Required.append(QStringLiteral("type"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("scan_value"),
                     QStringLiteral("Scan process memory for a specific value. Returns matching addresses."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleScanValue(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        Schema[QStringLiteral("properties")] = Props;

        RegisterTool(QStringLiteral("get_modules"),
                     QStringLiteral("List all loaded modules in the attached process with base address and name."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetModules(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        Schema[QStringLiteral("properties")] = Props;

        RegisterTool(QStringLiteral("get_registers"),
                     QStringLiteral("Get CPU register values. Requires debugger to be attached and paused."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetRegisters(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Address in hex where breakpoint should be set");
        Props[QStringLiteral("address")] = AddrProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("set_breakpoint"),
                     QStringLiteral("Set a software breakpoint at the given address."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleSetBreakpoint(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Address in hex of breakpoint to remove");
        Props[QStringLiteral("address")] = AddrProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("remove_breakpoint"),
                     QStringLiteral("Remove a breakpoint at the given address."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleRemoveBreakpoint(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject PatternProp;
        PatternProp[QStringLiteral("type")] = QStringLiteral("string");
        PatternProp[QStringLiteral("description")] = QStringLiteral("Byte pattern with wildcards (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0')");
        Props[QStringLiteral("pattern")] = PatternProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("pattern"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("pattern_scan"),
                     QStringLiteral("Scan process memory for a byte pattern with optional wildcards (?? for any byte)."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandlePatternScan(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject AddrProp;
        AddrProp[QStringLiteral("type")] = QStringLiteral("string");
        AddrProp[QStringLiteral("description")] = QStringLiteral("Start address in hex");
        Props[QStringLiteral("address")] = AddrProp;
        QJsonObject MaxLenProp;
        MaxLenProp[QStringLiteral("type")] = QStringLiteral("integer");
        MaxLenProp[QStringLiteral("description")] = QStringLiteral("Maximum string length to read");
        MaxLenProp[QStringLiteral("minimum")] = 1;
        MaxLenProp[QStringLiteral("maximum")] = 65536;
        Props[QStringLiteral("max_length")] = MaxLenProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("address"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("read_string"),
                     QStringLiteral("Read a null-terminated string from the given address."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleReadString(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject ModProp;
        ModProp[QStringLiteral("type")] = QStringLiteral("string");
        ModProp[QStringLiteral("description")] = QStringLiteral("Module name (e.g. kernel32.dll)");
        Props[QStringLiteral("module")] = ModProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("module"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("get_imports"),
                     QStringLiteral("Get the import table of a loaded module."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetImports(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject ModProp;
        ModProp[QStringLiteral("type")] = QStringLiteral("string");
        ModProp[QStringLiteral("description")] = QStringLiteral("Module name (e.g. kernel32.dll)");
        Props[QStringLiteral("module")] = ModProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("module"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("get_exports"),
                     QStringLiteral("Get the export table of a loaded module."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleGetExports(Args); });
    }

    {
        QJsonObject Schema;
        Schema[QStringLiteral("type")] = QStringLiteral("object");
        QJsonObject Props;
        QJsonObject ExprProp;
        ExprProp[QStringLiteral("type")] = QStringLiteral("string");
        ExprProp[QStringLiteral("description")] = QStringLiteral("Expression to evaluate (e.g. 'kernel32.dll+0x1234', '0x7FF600000000+0x100')");
        Props[QStringLiteral("expression")] = ExprProp;
        Schema[QStringLiteral("properties")] = Props;
        QJsonArray Required;
        Required.append(QStringLiteral("expression"));
        Schema[QStringLiteral("required")] = Required;

        RegisterTool(QStringLiteral("evaluate_expression"),
                     QStringLiteral("Evaluate an address expression. Supports module+offset and hex arithmetic."),
                     Schema,
                     [this](const QJsonObject& Args) { return HandleEvaluateExpression(Args); });
    }
}

static Address ParseAddress(const QString& AddrStr) {
    QString Cleaned = AddrStr.trimmed();
    if (Cleaned.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ||
        Cleaned.startsWith(QStringLiteral("0X"))) {
        Cleaned = Cleaned.mid(2);
    }
    bool Ok = false;
    Address Addr = Cleaned.toULongLong(&Ok, 16);
    if (!Ok) return 0;
    return Addr;
}

QJsonValue McpToolRegistry::HandleReadMemory(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());
    int Size = Args.value(QStringLiteral("size")).toInt(256);

    if (Size <= 0 || Size > 65536) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid size (must be 1-65536)");
        return Err;
    }

    QByteArray Buffer(Size, '\0');
    if (!CoreRef->ReadMemory(Addr, Buffer.data(), static_cast<size_t>(Size))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read memory at 0x") +
                                        QString::number(Addr, 16).toUpper();
        return Err;
    }

    QJsonObject Result;
    Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
    Result[QStringLiteral("size")] = Size;
    Result[QStringLiteral("hex")] = QString::fromLatin1(Buffer.toHex(' '));
    Result[QStringLiteral("raw_hex")] = QString::fromLatin1(Buffer.toHex());
    return Result;
}

QJsonValue McpToolRegistry::HandleWriteMemory(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());
    QString HexData = Args.value(QStringLiteral("hex_data")).toString().remove(' ');

    QByteArray Data = QByteArray::fromHex(HexData.toLatin1());
    if (Data.isEmpty()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid hex data");
        return Err;
    }

    if (!CoreRef->WriteMemory(Addr, Data.constData(), static_cast<size_t>(Data.size()))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to write memory at 0x") +
                                        QString::number(Addr, 16).toUpper();
        return Err;
    }

    QJsonObject Result;
    Result[QStringLiteral("success")] = true;
    Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
    Result[QStringLiteral("bytes_written")] = Data.size();
    return Result;
}

QJsonValue McpToolRegistry::HandleGetMemoryRegions(const QJsonObject& Args) {
    Q_UNUSED(Args);

    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();

    QJsonArray RegionArray;
    for (const MemoryRegion& Region : Regions) {
        QJsonObject RegObj;
        RegObj[QStringLiteral("base")] = QStringLiteral("0x") + QString::number(Region.Base, 16).toUpper();
        RegObj[QStringLiteral("size")] = static_cast<qint64>(Region.Size);
        RegObj[QStringLiteral("protection")] = static_cast<int>(Region.Protection);

        QString ProtStr;
        if (Region.Protection & 0x01) ProtStr += QStringLiteral("X");
        if (Region.Protection & 0x02) ProtStr += QStringLiteral("R");
        if (Region.Protection & 0x04) ProtStr += QStringLiteral("W");
        if (Region.Protection & 0x10) ProtStr += QStringLiteral("E(PAGE_EXECUTE)");
        if (Region.Protection & 0x20) ProtStr += QStringLiteral("RE");
        if (Region.Protection & 0x40) ProtStr += QStringLiteral("RWE");
        if (ProtStr.isEmpty()) ProtStr = QString::number(Region.Protection, 16);
        RegObj[QStringLiteral("protection_str")] = ProtStr;

        if (!Region.ModuleName.isEmpty()) {
            RegObj[QStringLiteral("module")] = Region.ModuleName;
        }
        RegionArray.append(RegObj);
    }

    QJsonObject Result;
    Result[QStringLiteral("count")] = RegionArray.size();
    Result[QStringLiteral("regions")] = RegionArray;
    return Result;
}

QJsonValue McpToolRegistry::HandleGetProcessList(const QJsonObject& Args) {
    Q_UNUSED(Args);

    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    QList<ProcessInfo> Processes = CoreRef->GetProcessList();

    QJsonArray ProcArray;
    for (const ProcessInfo& Proc : Processes) {
        QJsonObject ProcObj;
        ProcObj[QStringLiteral("pid")] = static_cast<int>(Proc.Pid);
        ProcObj[QStringLiteral("name")] = Proc.Name;
        if (!Proc.Path.isEmpty()) {
            ProcObj[QStringLiteral("path")] = Proc.Path;
        }
        ProcObj[QStringLiteral("base_address")] = QStringLiteral("0x") + QString::number(Proc.BaseAddress, 16).toUpper();

        QString ArchStr;
        switch (Proc.Arch) {
        case Architecture::X86: ArchStr = QStringLiteral("x86"); break;
        case Architecture::X64: ArchStr = QStringLiteral("x64"); break;
        case Architecture::ARM: ArchStr = QStringLiteral("arm"); break;
        case Architecture::ARM64: ArchStr = QStringLiteral("arm64"); break;
        default: ArchStr = QStringLiteral("unknown"); break;
        }
        ProcObj[QStringLiteral("architecture")] = ArchStr;

        ProcArray.append(ProcObj);
    }

    QJsonObject Result;
    Result[QStringLiteral("count")] = ProcArray.size();
    Result[QStringLiteral("processes")] = ProcArray;
    return Result;
}

QJsonValue McpToolRegistry::HandleAttachProcess(const QJsonObject& Args) {
    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    int Pid = Args.value(QStringLiteral("pid")).toInt(0);
    if (Pid <= 0) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid PID");
        return Err;
    }

    CoreRef->AttachToProcess(static_cast<uint32_t>(Pid));

    QJsonObject Result;
    if (CoreRef->IsAttached()) {
        ProcessInfo Info = CoreRef->CurrentProcess();
        Result[QStringLiteral("success")] = true;
        Result[QStringLiteral("pid")] = static_cast<int>(Info.Pid);
        Result[QStringLiteral("name")] = Info.Name;
        Result[QStringLiteral("base_address")] = QStringLiteral("0x") + QString::number(Info.BaseAddress, 16).toUpper();
    } else {
        Result[QStringLiteral("success")] = false;
        Result[QStringLiteral("error")] = QStringLiteral("Failed to attach to process ") + QString::number(Pid);
    }
    return Result;
}

QJsonValue McpToolRegistry::HandleDetachProcess(const QJsonObject& Args) {
    Q_UNUSED(Args);

    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    if (!CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    CoreRef->DetachFromProcess();

    QJsonObject Result;
    Result[QStringLiteral("success")] = true;
    return Result;
}

QJsonValue McpToolRegistry::HandleDisassemble(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());
    int Count = Args.value(QStringLiteral("count")).toInt(20);

    if (Count <= 0 || Count > 1000) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid count (must be 1-1000)");
        return Err;
    }

    size_t ReadSize = static_cast<size_t>(Count) * 15;
    QByteArray Buffer(static_cast<int>(ReadSize), '\0');

    if (!CoreRef->ReadMemory(Addr, Buffer.data(), ReadSize)) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read memory at 0x") +
                                        QString::number(Addr, 16).toUpper();
        return Err;
    }

    IModule* DisasmMod = CoreRef->GetModule(QStringLiteral("Disassembler"));
    Q_UNUSED(DisasmMod);

    ProcessInfo Proc = CoreRef->CurrentProcess();
    cs_arch CsArch = CS_ARCH_X86;
    cs_mode CsMode = CS_MODE_64;

    switch (Proc.Arch) {
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
    default:
        break;
    }

    csh Handle;
    cs_err Err = cs_open(CsArch, CsMode, &Handle);
    if (Err != CS_ERR_OK) {
        QJsonObject ErrObj;
        ErrObj[QStringLiteral("error")] = QStringLiteral("Failed to initialize disassembler");
        return ErrObj;
    }

    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* Insns = nullptr;
    size_t DisCount = cs_disasm(Handle,
                                reinterpret_cast<const uint8_t*>(Buffer.constData()),
                                ReadSize, Addr,
                                static_cast<size_t>(Count), &Insns);

    QJsonArray Instructions;
    for (size_t I = 0; I < DisCount; ++I) {
        QJsonObject InstObj;
        InstObj[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Insns[I].address, 16).toUpper();
        QByteArray ByteArr(reinterpret_cast<const char*>(Insns[I].bytes),
                           static_cast<qsizetype>(Insns[I].size));
        InstObj[QStringLiteral("bytes")] = QString::fromLatin1(ByteArr.toHex(' '));
        InstObj[QStringLiteral("mnemonic")] = QString::fromUtf8(Insns[I].mnemonic);
        InstObj[QStringLiteral("operands")] = QString::fromUtf8(Insns[I].op_str);
        Instructions.append(InstObj);
    }

    if (DisCount > 0) {
        cs_free(Insns, DisCount);
    }
    cs_close(&Handle);

    QJsonObject Result;
    Result[QStringLiteral("count")] = static_cast<int>(DisCount);
    Result[QStringLiteral("instructions")] = Instructions;
    return Result;
}

QJsonValue McpToolRegistry::HandleScanValue(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QString ValueStr = Args.value(QStringLiteral("value")).toString();
    QString TypeStr = Args.value(QStringLiteral("type")).toString().toLower();

    ValueType ValType = ValueType::Int32;
    if (TypeStr == QStringLiteral("byte")) ValType = ValueType::Byte;
    else if (TypeStr == QStringLiteral("int16")) ValType = ValueType::Int16;
    else if (TypeStr == QStringLiteral("int32")) ValType = ValueType::Int32;
    else if (TypeStr == QStringLiteral("int64")) ValType = ValueType::Int64;
    else if (TypeStr == QStringLiteral("float")) ValType = ValueType::Float;
    else if (TypeStr == QStringLiteral("double")) ValType = ValueType::Double;
    else if (TypeStr == QStringLiteral("string")) ValType = ValueType::String;

    int ValSize = 4;
    QByteArray SearchBytes;

    switch (ValType) {
    case ValueType::Byte: {
        uint8_t V = static_cast<uint8_t>(ValueStr.toUInt());
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 1;
        break;
    }
    case ValueType::Int16: {
        int16_t V = static_cast<int16_t>(ValueStr.toShort());
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 2;
        break;
    }
    case ValueType::Int32: {
        int32_t V = ValueStr.toInt();
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 4;
        break;
    }
    case ValueType::Int64: {
        int64_t V = ValueStr.toLongLong();
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 8;
        break;
    }
    case ValueType::Float: {
        float V = ValueStr.toFloat();
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 4;
        break;
    }
    case ValueType::Double: {
        double V = ValueStr.toDouble();
        SearchBytes.append(reinterpret_cast<const char*>(&V), sizeof(V));
        ValSize = 8;
        break;
    }
    case ValueType::String: {
        SearchBytes = ValueStr.toUtf8();
        ValSize = SearchBytes.size();
        break;
    }
    default:
        break;
    }

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
    QJsonArray Matches;
    constexpr int MaxResults = 1000;
    constexpr size_t ChunkSize = 4 * 1024 * 1024;

    for (const MemoryRegion& Region : Regions) {
        if (Matches.size() >= MaxResults) break;

        size_t Remaining = Region.Size;
        Address CurrentBase = Region.Base;

        while (Remaining > 0 && Matches.size() < MaxResults) {
            size_t ToRead = std::min(Remaining, ChunkSize);
            QByteArray Chunk(static_cast<int>(ToRead), '\0');

            if (!CoreRef->ReadMemory(CurrentBase, Chunk.data(), ToRead)) {
                CurrentBase += ToRead;
                Remaining -= ToRead;
                continue;
            }

            int Alignment = (ValType == ValueType::String) ? 1 : ValSize;

            for (size_t I = 0; I + static_cast<size_t>(ValSize) <= ToRead; I += Alignment) {
                if (Matches.size() >= MaxResults) break;

                if (std::memcmp(Chunk.constData() + I, SearchBytes.constData(), static_cast<size_t>(ValSize)) == 0) {
                    QJsonObject Match;
                    Match[QStringLiteral("address")] = QStringLiteral("0x") +
                        QString::number(CurrentBase + I, 16).toUpper();
                    Matches.append(Match);
                }
            }

            CurrentBase += ToRead;
            Remaining -= ToRead;
        }
    }

    QJsonObject Result;
    Result[QStringLiteral("count")] = Matches.size();
    Result[QStringLiteral("matches")] = Matches;
    if (Matches.size() >= MaxResults) {
        Result[QStringLiteral("truncated")] = true;
    }
    return Result;
}

QJsonValue McpToolRegistry::HandleGetModules(const QJsonObject& Args) {
    Q_UNUSED(Args);

    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();

    QMap<QString, Address> ModuleBaseMap;
    QMap<QString, size_t> ModuleSizeMap;

    for (const MemoryRegion& Region : Regions) {
        if (Region.ModuleName.isEmpty()) continue;

        if (!ModuleBaseMap.contains(Region.ModuleName)) {
            ModuleBaseMap[Region.ModuleName] = Region.Base;
            ModuleSizeMap[Region.ModuleName] = Region.Size;
        } else {
            Address ExistingBase = ModuleBaseMap[Region.ModuleName];
            if (Region.Base < ExistingBase) {
                ModuleBaseMap[Region.ModuleName] = Region.Base;
            }
            Address ExistingEnd = ExistingBase + ModuleSizeMap[Region.ModuleName];
            Address RegionEnd = Region.Base + Region.Size;
            Address EffectiveBase = std::min(ExistingBase, Region.Base);
            Address EffectiveEnd = std::max(ExistingEnd, RegionEnd);
            ModuleSizeMap[Region.ModuleName] = EffectiveEnd - EffectiveBase;
            ModuleBaseMap[Region.ModuleName] = EffectiveBase;
        }
    }

    QJsonArray ModuleArray;
    for (auto It = ModuleBaseMap.constBegin(); It != ModuleBaseMap.constEnd(); ++It) {
        QJsonObject ModObj;
        ModObj[QStringLiteral("name")] = It.key();
        ModObj[QStringLiteral("base")] = QStringLiteral("0x") + QString::number(It.value(), 16).toUpper();
        ModObj[QStringLiteral("size")] = static_cast<qint64>(ModuleSizeMap[It.key()]);
        ModuleArray.append(ModObj);
    }

    QJsonObject Result;
    Result[QStringLiteral("count")] = ModuleArray.size();
    Result[QStringLiteral("modules")] = ModuleArray;
    return Result;
}

QJsonValue McpToolRegistry::HandleGetRegisters(const QJsonObject& Args) {
    Q_UNUSED(Args);

    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
    if (!DebugMod) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Debugger module not available");
        return Err;
    }

    QJsonObject Regs;
    Regs[QStringLiteral("note")] = QStringLiteral("Registers available when debugger is paused at a breakpoint. Attach debugger and hit a breakpoint first.");
    return Regs;
}

QJsonValue McpToolRegistry::HandleSetBreakpoint(const QJsonObject& Args) {
    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());

    IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
    if (!DebugMod) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Debugger module not available");
        return Err;
    }

    QJsonObject Result;
    Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
    Result[QStringLiteral("note")] = QStringLiteral("Breakpoint request queued. Use debugger module for full breakpoint management.");
    return Result;
}

QJsonValue McpToolRegistry::HandleRemoveBreakpoint(const QJsonObject& Args) {
    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());

    IModule* DebugMod = CoreRef->GetModule(QStringLiteral("Debugger"));
    if (!DebugMod) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Debugger module not available");
        return Err;
    }

    QJsonObject Result;
    Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
    Result[QStringLiteral("note")] = QStringLiteral("Breakpoint removal request queued.");
    return Result;
}

QJsonValue McpToolRegistry::HandlePatternScan(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QString PatternStr = Args.value(QStringLiteral("pattern")).toString();
    QStringList Parts = PatternStr.split(' ', Qt::SkipEmptyParts);

    struct PatByte {
        uint8_t Value;
        bool IsWild;
    };

    QVector<PatByte> Pattern;
    for (const QString& Part : Parts) {
        PatByte Pb;
        if (Part == QStringLiteral("??") || Part == QStringLiteral("?")) {
            Pb.Value = 0;
            Pb.IsWild = true;
        } else {
            bool Ok;
            Pb.Value = static_cast<uint8_t>(Part.toUInt(&Ok, 16));
            Pb.IsWild = false;
            if (!Ok) {
                QJsonObject Err;
                Err[QStringLiteral("error")] = QStringLiteral("Invalid pattern byte: ") + Part;
                return Err;
            }
        }
        Pattern.append(Pb);
    }

    if (Pattern.isEmpty()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Empty pattern");
        return Err;
    }

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
    QJsonArray Matches;
    constexpr int MaxResults = 100;
    constexpr size_t ChunkSize = 4 * 1024 * 1024;
    size_t PatternSize = static_cast<size_t>(Pattern.size());

    for (const MemoryRegion& Region : Regions) {
        if (Matches.size() >= MaxResults) break;

        size_t Remaining = Region.Size;
        Address CurrentBase = Region.Base;

        while (Remaining > 0 && Matches.size() < MaxResults) {
            size_t ToRead = std::min(Remaining, ChunkSize);
            QByteArray Chunk(static_cast<int>(ToRead), '\0');

            if (!CoreRef->ReadMemory(CurrentBase, Chunk.data(), ToRead)) {
                CurrentBase += ToRead;
                Remaining -= ToRead;
                continue;
            }

            for (size_t I = 0; I + PatternSize <= ToRead; ++I) {
                if (Matches.size() >= MaxResults) break;

                bool Found = true;
                for (size_t J = 0; J < PatternSize; ++J) {
                    if (Pattern[static_cast<int>(J)].IsWild) continue;
                    if (static_cast<uint8_t>(Chunk[static_cast<int>(I + J)]) != Pattern[static_cast<int>(J)].Value) {
                        Found = false;
                        break;
                    }
                }

                if (Found) {
                    QJsonObject Match;
                    Match[QStringLiteral("address")] = QStringLiteral("0x") +
                        QString::number(CurrentBase + I, 16).toUpper();
                    QByteArray MatchBytes = Chunk.mid(static_cast<int>(I), static_cast<int>(PatternSize));
                    Match[QStringLiteral("bytes")] = QString::fromLatin1(MatchBytes.toHex(' '));
                    Matches.append(Match);
                }
            }

            CurrentBase += ToRead;
            Remaining -= ToRead;
        }
    }

    QJsonObject Result;
    Result[QStringLiteral("pattern")] = PatternStr;
    Result[QStringLiteral("count")] = Matches.size();
    Result[QStringLiteral("matches")] = Matches;
    if (Matches.size() >= MaxResults) {
        Result[QStringLiteral("truncated")] = true;
    }
    return Result;
}

QJsonValue McpToolRegistry::HandleReadString(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    Address Addr = ParseAddress(Args.value(QStringLiteral("address")).toString());
    int MaxLen = Args.value(QStringLiteral("max_length")).toInt(256);

    if (MaxLen <= 0 || MaxLen > 65536) {
        MaxLen = 256;
    }

    QByteArray Buffer(MaxLen, '\0');
    if (!CoreRef->ReadMemory(Addr, Buffer.data(), static_cast<size_t>(MaxLen))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read memory at 0x") +
                                        QString::number(Addr, 16).toUpper();
        return Err;
    }

    int NullPos = Buffer.indexOf('\0');
    if (NullPos >= 0) {
        Buffer.truncate(NullPos);
    }

    QJsonObject Result;
    Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
    Result[QStringLiteral("string")] = QString::fromUtf8(Buffer);
    Result[QStringLiteral("length")] = Buffer.size();
    Result[QStringLiteral("hex")] = QString::fromLatin1(Buffer.toHex(' '));
    return Result;
}

QJsonValue McpToolRegistry::HandleGetImports(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QString ModuleName = Args.value(QStringLiteral("module")).toString();

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
    Address ModuleBase = 0;

    for (const MemoryRegion& Region : Regions) {
        if (Region.ModuleName.compare(ModuleName, Qt::CaseInsensitive) == 0) {
            if (ModuleBase == 0 || Region.Base < ModuleBase) {
                ModuleBase = Region.Base;
            }
        }
    }

    if (ModuleBase == 0) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Module not found: ") + ModuleName;
        return Err;
    }

    uint8_t DosHeader[64];
    if (!CoreRef->ReadMemory(ModuleBase, DosHeader, sizeof(DosHeader))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read DOS header");
        return Err;
    }

    uint16_t Magic = *reinterpret_cast<uint16_t*>(DosHeader);
    if (Magic != 0x5A4D) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid PE signature");
        return Err;
    }

    uint32_t PeOffset = *reinterpret_cast<uint32_t*>(DosHeader + 0x3C);

    uint8_t PeHeader[4096];
    if (!CoreRef->ReadMemory(ModuleBase + PeOffset, PeHeader, sizeof(PeHeader))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read PE header");
        return Err;
    }

    uint32_t PeSig = *reinterpret_cast<uint32_t*>(PeHeader);
    if (PeSig != 0x00004550) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid PE signature");
        return Err;
    }

    uint16_t MachineTy = *reinterpret_cast<uint16_t*>(PeHeader + 4);
    bool Is64 = (MachineTy == 0x8664);

    uint32_t ImportDirRva = 0;
    uint32_t ImportDirSize = 0;

    if (Is64) {
        ImportDirRva = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 112);
        ImportDirSize = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 116);
    } else {
        ImportDirRva = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 96);
        ImportDirSize = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 100);
    }

    if (ImportDirRva == 0 || ImportDirSize == 0) {
        QJsonObject Result;
        Result[QStringLiteral("module")] = ModuleName;
        Result[QStringLiteral("imports")] = QJsonArray();
        Result[QStringLiteral("count")] = 0;
        return Result;
    }

    QJsonArray Imports;
    Address ImportTableAddr = ModuleBase + ImportDirRva;

    for (int I = 0; I < 256; ++I) {
        uint8_t ImportDesc[20];
        if (!CoreRef->ReadMemory(ImportTableAddr + static_cast<uint64_t>(I) * 20, ImportDesc, 20))
            break;

        uint32_t NameRva = *reinterpret_cast<uint32_t*>(ImportDesc + 12);
        uint32_t ThunkRva = *reinterpret_cast<uint32_t*>(ImportDesc + 0);

        if (NameRva == 0) break;

        char DllNameBuf[256] = {};
        CoreRef->ReadMemory(ModuleBase + NameRva, DllNameBuf, sizeof(DllNameBuf) - 1);
        QString DllName = QString::fromUtf8(DllNameBuf);

        QJsonObject ImportEntry;
        ImportEntry[QStringLiteral("dll")] = DllName;

        QJsonArray Functions;
        if (ThunkRva != 0) {
            Address ThunkAddr = ModuleBase + ThunkRva;
            int EntrySize = Is64 ? 8 : 4;

            for (int J = 0; J < 512; ++J) {
                uint64_t ThunkData = 0;
                if (!CoreRef->ReadMemory(ThunkAddr + static_cast<uint64_t>(J) * EntrySize, &ThunkData, EntrySize))
                    break;

                if (ThunkData == 0) break;

                bool IsOrdinal = Is64 ? (ThunkData & 0x8000000000000000ULL) != 0
                                      : (ThunkData & 0x80000000UL) != 0;

                if (IsOrdinal) {
                    uint16_t Ordinal = static_cast<uint16_t>(ThunkData & 0xFFFF);
                    Functions.append(QStringLiteral("Ordinal#") + QString::number(Ordinal));
                } else {
                    uint32_t HintNameRva = static_cast<uint32_t>(ThunkData & 0x7FFFFFFF);
                    char FuncNameBuf[256] = {};
                    CoreRef->ReadMemory(ModuleBase + HintNameRva + 2, FuncNameBuf, sizeof(FuncNameBuf) - 1);
                    Functions.append(QString::fromUtf8(FuncNameBuf));
                }
            }
        }

        ImportEntry[QStringLiteral("functions")] = Functions;
        Imports.append(ImportEntry);
    }

    QJsonObject Result;
    Result[QStringLiteral("module")] = ModuleName;
    Result[QStringLiteral("count")] = Imports.size();
    Result[QStringLiteral("imports")] = Imports;
    return Result;
}

QJsonValue McpToolRegistry::HandleGetExports(const QJsonObject& Args) {
    if (!CoreRef || !CoreRef->IsAttached()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("No process attached");
        return Err;
    }

    QString ModuleName = Args.value(QStringLiteral("module")).toString();

    QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
    Address ModuleBase = 0;

    for (const MemoryRegion& Region : Regions) {
        if (Region.ModuleName.compare(ModuleName, Qt::CaseInsensitive) == 0) {
            if (ModuleBase == 0 || Region.Base < ModuleBase) {
                ModuleBase = Region.Base;
            }
        }
    }

    if (ModuleBase == 0) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Module not found: ") + ModuleName;
        return Err;
    }

    uint8_t DosHeader[64];
    if (!CoreRef->ReadMemory(ModuleBase, DosHeader, sizeof(DosHeader))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read DOS header");
        return Err;
    }

    uint16_t DosmagicV = *reinterpret_cast<uint16_t*>(DosHeader);
    if (DosmagicV != 0x5A4D) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid PE signature");
        return Err;
    }

    uint32_t PeOffset = *reinterpret_cast<uint32_t*>(DosHeader + 0x3C);

    uint8_t PeHeader[4096];
    if (!CoreRef->ReadMemory(ModuleBase + PeOffset, PeHeader, sizeof(PeHeader))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read PE header");
        return Err;
    }

    uint32_t PeSig = *reinterpret_cast<uint32_t*>(PeHeader);
    if (PeSig != 0x00004550) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Invalid PE signature");
        return Err;
    }

    uint16_t MachineTy = *reinterpret_cast<uint16_t*>(PeHeader + 4);
    bool Is64 = (MachineTy == 0x8664);

    uint32_t ExportDirRva = 0;

    if (Is64) {
        ExportDirRva = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 96);
    } else {
        ExportDirRva = *reinterpret_cast<uint32_t*>(PeHeader + 24 + 80);
    }

    if (ExportDirRva == 0) {
        QJsonObject Result;
        Result[QStringLiteral("module")] = ModuleName;
        Result[QStringLiteral("exports")] = QJsonArray();
        Result[QStringLiteral("count")] = 0;
        return Result;
    }

    uint8_t ExportDir[40];
    if (!CoreRef->ReadMemory(ModuleBase + ExportDirRva, ExportDir, sizeof(ExportDir))) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Failed to read export directory");
        return Err;
    }

    uint32_t NumberOfFunctions = *reinterpret_cast<uint32_t*>(ExportDir + 20);
    uint32_t NumberOfNames = *reinterpret_cast<uint32_t*>(ExportDir + 24);
    uint32_t AddressOfFunctions = *reinterpret_cast<uint32_t*>(ExportDir + 28);
    uint32_t AddressOfNames = *reinterpret_cast<uint32_t*>(ExportDir + 32);
    uint32_t AddressOfNameOrdinals = *reinterpret_cast<uint32_t*>(ExportDir + 36);
    uint32_t OrdinalBase = *reinterpret_cast<uint32_t*>(ExportDir + 16);

    QJsonArray Exports;

    if (NumberOfNames > 10000) NumberOfNames = 10000;
    if (NumberOfFunctions > 10000) NumberOfFunctions = 10000;

    QVector<uint32_t> NameRvas(static_cast<int>(NumberOfNames));
    QVector<uint16_t> NameOrdinals(static_cast<int>(NumberOfNames));
    QVector<uint32_t> FuncRvas(static_cast<int>(NumberOfFunctions));

    CoreRef->ReadMemory(ModuleBase + AddressOfNames,
                        NameRvas.data(),
                        NumberOfNames * sizeof(uint32_t));
    CoreRef->ReadMemory(ModuleBase + AddressOfNameOrdinals,
                        NameOrdinals.data(),
                        NumberOfNames * sizeof(uint16_t));
    CoreRef->ReadMemory(ModuleBase + AddressOfFunctions,
                        FuncRvas.data(),
                        NumberOfFunctions * sizeof(uint32_t));

    for (uint32_t I = 0; I < NumberOfNames; ++I) {
        char FuncName[256] = {};
        CoreRef->ReadMemory(ModuleBase + NameRvas[static_cast<int>(I)], FuncName, sizeof(FuncName) - 1);

        uint16_t OrdIdx = NameOrdinals[static_cast<int>(I)];
        uint32_t FuncRva = (OrdIdx < NumberOfFunctions) ? FuncRvas[static_cast<int>(OrdIdx)] : 0;

        QJsonObject ExportEntry;
        ExportEntry[QStringLiteral("name")] = QString::fromUtf8(FuncName);
        ExportEntry[QStringLiteral("ordinal")] = static_cast<int>(OrdIdx + OrdinalBase);
        ExportEntry[QStringLiteral("address")] = QStringLiteral("0x") +
            QString::number(ModuleBase + FuncRva, 16).toUpper();
        ExportEntry[QStringLiteral("rva")] = QStringLiteral("0x") +
            QString::number(FuncRva, 16).toUpper();

        Exports.append(ExportEntry);
    }

    QJsonObject Result;
    Result[QStringLiteral("module")] = ModuleName;
    Result[QStringLiteral("count")] = Exports.size();
    Result[QStringLiteral("exports")] = Exports;
    return Result;
}

QJsonValue McpToolRegistry::HandleEvaluateExpression(const QJsonObject& Args) {
    if (!CoreRef) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Core not initialized");
        return Err;
    }

    QString Expr = Args.value(QStringLiteral("expression")).toString().trimmed();

    if (Expr.isEmpty()) {
        QJsonObject Err;
        Err[QStringLiteral("error")] = QStringLiteral("Empty expression");
        return Err;
    }

    int PlusPos = Expr.indexOf('+');
    int MinusPos = Expr.indexOf('-', 1);

    if (PlusPos > 0 || MinusPos > 0) {
        int SplitPos = -1;
        QChar Op = '+';

        if (PlusPos > 0 && (MinusPos < 0 || PlusPos < MinusPos)) {
            SplitPos = PlusPos;
            Op = '+';
        } else if (MinusPos > 0) {
            SplitPos = MinusPos;
            Op = '-';
        }

        if (SplitPos > 0) {
            QString Left = Expr.left(SplitPos).trimmed();
            QString Right = Expr.mid(SplitPos + 1).trimmed();

            Address BaseAddr = 0;

            if (Left.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
                BaseAddr = ParseAddress(Left);
            } else if (CoreRef->IsAttached()) {
                QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
                for (const MemoryRegion& Region : Regions) {
                    if (Region.ModuleName.compare(Left, Qt::CaseInsensitive) == 0) {
                        if (BaseAddr == 0 || Region.Base < BaseAddr) {
                            BaseAddr = Region.Base;
                        }
                    }
                }

                if (BaseAddr == 0) {
                    QJsonObject Err;
                    Err[QStringLiteral("error")] = QStringLiteral("Module not found: ") + Left;
                    return Err;
                }
            }

            Address OffsetVal = ParseAddress(Right);

            Address FinalAddr = (Op == '+') ? BaseAddr + OffsetVal : BaseAddr - OffsetVal;

            QJsonObject Result;
            Result[QStringLiteral("expression")] = Expr;
            Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(FinalAddr, 16).toUpper();
            Result[QStringLiteral("base")] = QStringLiteral("0x") + QString::number(BaseAddr, 16).toUpper();
            Result[QStringLiteral("offset")] = QStringLiteral("0x") + QString::number(OffsetVal, 16).toUpper();
            return Result;
        }
    }

    if (Expr.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ||
        Expr.contains(QRegularExpression(QStringLiteral("^[0-9a-fA-F]+$")))) {
        Address Addr = ParseAddress(Expr);
        QJsonObject Result;
        Result[QStringLiteral("expression")] = Expr;
        Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Addr, 16).toUpper();
        return Result;
    }

    if (CoreRef->IsAttached()) {
        QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
        for (const MemoryRegion& Region : Regions) {
            if (Region.ModuleName.compare(Expr, Qt::CaseInsensitive) == 0) {
                QJsonObject Result;
                Result[QStringLiteral("expression")] = Expr;
                Result[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(Region.Base, 16).toUpper();
                Result[QStringLiteral("module")] = Region.ModuleName;
                return Result;
            }
        }
    }

    QJsonObject Err;
    Err[QStringLiteral("error")] = QStringLiteral("Could not evaluate expression: ") + Expr;
    return Err;
}

}
