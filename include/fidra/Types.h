#pragma once

#include <cstdint>
#include <cstddef>
#include <QString>
#include <QList>
#include <QMap>
#include <QVariant>

namespace Fidra {

using Address = uint64_t;
using Offset = int64_t;

enum class Architecture {
    X86,
    X64,
    ARM,
    ARM64,
    Unknown
};

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

enum class ScanType {
    Exact,
    GreaterThan,
    LessThan,
    Between,
    Unknown,
    Changed,
    Unchanged
};

enum class ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    String,
    ByteArray,
    Pointer
};

struct MemoryRegion {
    Address Base;
    size_t Size;
    uint32_t Protection;
    QString ModuleName;
};

struct ProcessInfo {
    uint32_t Pid;
    QString Name;
    QString Path;
    Address BaseAddress;
    Architecture Arch;
};

struct Breakpoint {
    Address Location;
    bool Enabled;
    bool IsHardware;
    uint32_t HitCount;
    QString Condition;
};

struct DisasmInstruction {
    Address Location;
    QByteArray Bytes;
    QString Mnemonic;
    QString Operands;
    QString Comment;
};

struct NetworkPacket {
    uint64_t Timestamp;
    QString Protocol;
    QString SourceAddress;
    uint16_t SourcePort;
    QString DestAddress;
    uint16_t DestPort;
    QByteArray Data;
    bool Outgoing;
};

struct HttpRequest {
    QString Method;
    QString Url;
    QMap<QString, QString> Headers;
    QByteArray Body;
    int StatusCode;
    QByteArray ResponseBody;
    QMap<QString, QString> ResponseHeaders;
    qint64 ElapsedMs;
};

}
