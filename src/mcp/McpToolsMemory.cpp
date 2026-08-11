#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QIODevice>
#include <QDataStream>
#include <cstring>
#include <algorithm>

namespace Fidra {

void McpToolRegistry::RegisterMemoryTools() {

    RegisterTool(QStringLiteral("read_memory_typed"),
        QStringLiteral("Read memory as a typed value (int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, pointer)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("type"), Schema::StringEnum(QStringLiteral("Value type"),
                {QStringLiteral("int8"), QStringLiteral("uint8"), QStringLiteral("int16"), QStringLiteral("uint16"),
                 QStringLiteral("int32"), QStringLiteral("uint32"), QStringLiteral("int64"), QStringLiteral("uint64"),
                 QStringLiteral("float"), QStringLiteral("double"), QStringLiteral("pointer")})}
        }, {QStringLiteral("address"), QStringLiteral("type")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Type = A.value(QStringLiteral("type")).toString().toLower();
            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("type")] = Type;
            if (Type == QStringLiteral("int8")) {
                int8_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<int>(V);
            } else if (Type == QStringLiteral("uint8")) {
                uint8_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<int>(V);
            } else if (Type == QStringLiteral("int16")) {
                int16_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<int>(V);
            } else if (Type == QStringLiteral("uint16")) {
                uint16_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<int>(V);
            } else if (Type == QStringLiteral("int32")) {
                int32_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = V;
            } else if (Type == QStringLiteral("uint32")) {
                uint32_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<qint64>(V);
            } else if (Type == QStringLiteral("int64")) {
                int64_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<qint64>(V);
            } else if (Type == QStringLiteral("uint64")) {
                uint64_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = QString::number(V);
                Result[QStringLiteral("hex")] = Schema::FormatAddress(V);
            } else if (Type == QStringLiteral("float")) {
                float V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = static_cast<double>(V);
            } else if (Type == QStringLiteral("double")) {
                double V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                Result[QStringLiteral("value")] = V;
            } else if (Type == QStringLiteral("pointer")) {
                bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
                if (Is64) {
                    uint64_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                    Result[QStringLiteral("value")] = Schema::FormatAddress(V);
                } else {
                    uint32_t V = 0; CoreRef->ReadMemory(Addr, &V, sizeof(V));
                    Result[QStringLiteral("value")] = Schema::FormatAddress(static_cast<Address>(V));
                }
            } else {
                return Schema::Err(QStringLiteral("Unknown type: ") + Type);
            }
            return Result;
        });

    RegisterTool(QStringLiteral("write_memory_typed"),
        QStringLiteral("Write a typed value to memory."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("type"), Schema::StringEnum(QStringLiteral("Value type"),
                {QStringLiteral("int8"), QStringLiteral("uint8"), QStringLiteral("int16"), QStringLiteral("uint16"),
                 QStringLiteral("int32"), QStringLiteral("uint32"), QStringLiteral("int64"), QStringLiteral("uint64"),
                 QStringLiteral("float"), QStringLiteral("double"), QStringLiteral("pointer")})},
            {QStringLiteral("value"), Schema::String(QStringLiteral("Value to write (as string)"))}
        }, {QStringLiteral("address"), QStringLiteral("type"), QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Type = A.value(QStringLiteral("type")).toString().toLower();
            QString ValStr = A.value(QStringLiteral("value")).toString();
            bool Written = false;
            if (Type == QStringLiteral("int8")) {
                int8_t V = static_cast<int8_t>(ValStr.toInt());
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("uint8")) {
                uint8_t V = static_cast<uint8_t>(ValStr.toUInt());
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("int16")) {
                int16_t V = static_cast<int16_t>(ValStr.toShort());
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("uint16")) {
                uint16_t V = static_cast<uint16_t>(ValStr.toUShort());
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("int32")) {
                int32_t V = ValStr.toInt();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("uint32")) {
                uint32_t V = ValStr.toUInt();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("int64")) {
                int64_t V = ValStr.toLongLong();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("uint64")) {
                uint64_t V = ValStr.toULongLong();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("float")) {
                float V = ValStr.toFloat();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("double")) {
                double V = ValStr.toDouble();
                Written = CoreRef->WriteMemory(Addr, &V, sizeof(V));
            } else if (Type == QStringLiteral("pointer")) {
                uint64_t V = Schema::ParseHexAddress(ValStr);
                bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
                if (Is64) {
                    Written = CoreRef->WriteMemory(Addr, &V, sizeof(uint64_t));
                } else {
                    uint32_t V32 = static_cast<uint32_t>(V);
                    Written = CoreRef->WriteMemory(Addr, &V32, sizeof(uint32_t));
                }
            } else {
                return Schema::Err(QStringLiteral("Unknown type: ") + Type);
            }
            if (!Written) return Schema::Err(QStringLiteral("Failed to write memory"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("type")] = Type;
            return Result;
        });

    auto MakeReadTool = [this](const QString& Name, const QString& Desc, int Size, bool IsSigned, bool IsFloat) {
        RegisterTool(Name, Desc,
            Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))}},
                          {QStringLiteral("address")}),
            [this, Size, IsSigned, IsFloat](const QJsonObject& A) -> QJsonValue {
                if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
                Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
                uint8_t Buf[8] = {};
                if (!CoreRef->ReadMemory(Addr, Buf, static_cast<size_t>(Size)))
                    return Schema::Err(QStringLiteral("Failed to read memory at ") + Schema::FormatAddress(Addr));
                QJsonObject Result;
                Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                QByteArray Raw(reinterpret_cast<const char*>(Buf), Size);
                Result[QStringLiteral("hex")] = QString::fromLatin1(Raw.toHex(' '));
                if (IsFloat && Size == 4) {
                    float V; std::memcpy(&V, Buf, 4);
                    Result[QStringLiteral("value")] = static_cast<double>(V);
                } else if (IsFloat && Size == 8) {
                    double V; std::memcpy(&V, Buf, 8);
                    Result[QStringLiteral("value")] = V;
                } else if (IsSigned) {
                    if (Size == 1) { int8_t V; std::memcpy(&V, Buf, 1); Result[QStringLiteral("value")] = static_cast<int>(V); }
                    else if (Size == 2) { int16_t V; std::memcpy(&V, Buf, 2); Result[QStringLiteral("value")] = static_cast<int>(V); }
                    else if (Size == 4) { int32_t V; std::memcpy(&V, Buf, 4); Result[QStringLiteral("value")] = V; }
                    else if (Size == 8) { int64_t V; std::memcpy(&V, Buf, 8); Result[QStringLiteral("value")] = static_cast<qint64>(V); }
                } else {
                    if (Size == 1) { uint8_t V; std::memcpy(&V, Buf, 1); Result[QStringLiteral("value")] = static_cast<int>(V); }
                    else if (Size == 2) { uint16_t V; std::memcpy(&V, Buf, 2); Result[QStringLiteral("value")] = static_cast<int>(V); }
                    else if (Size == 4) { uint32_t V; std::memcpy(&V, Buf, 4); Result[QStringLiteral("value")] = static_cast<qint64>(V); }
                    else if (Size == 8) { uint64_t V; std::memcpy(&V, Buf, 8); Result[QStringLiteral("value")] = QString::number(V); Result[QStringLiteral("value_hex")] = Schema::FormatAddress(V); }
                }
                return Result;
            });
    };

    MakeReadTool(QStringLiteral("read_int8"), QStringLiteral("Read a signed 8-bit integer at address."), 1, true, false);
    MakeReadTool(QStringLiteral("read_uint8"), QStringLiteral("Read an unsigned 8-bit integer at address."), 1, false, false);
    MakeReadTool(QStringLiteral("read_int16"), QStringLiteral("Read a signed 16-bit integer at address."), 2, true, false);
    MakeReadTool(QStringLiteral("read_uint16"), QStringLiteral("Read an unsigned 16-bit integer at address."), 2, false, false);
    MakeReadTool(QStringLiteral("read_int32"), QStringLiteral("Read a signed 32-bit integer at address."), 4, true, false);
    MakeReadTool(QStringLiteral("read_uint32"), QStringLiteral("Read an unsigned 32-bit integer at address."), 4, false, false);
    MakeReadTool(QStringLiteral("read_int64"), QStringLiteral("Read a signed 64-bit integer at address."), 8, true, false);
    MakeReadTool(QStringLiteral("read_uint64"), QStringLiteral("Read an unsigned 64-bit integer at address."), 8, false, false);
    MakeReadTool(QStringLiteral("read_float"), QStringLiteral("Read a 32-bit float at address."), 4, false, true);
    MakeReadTool(QStringLiteral("read_double"), QStringLiteral("Read a 64-bit double at address."), 8, false, true);

    RegisterTool(QStringLiteral("read_pointer"),
        QStringLiteral("Read a pointer-sized value (4 bytes on x86, 8 bytes on x64) at address."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            if (Is64) {
                uint64_t V = 0;
                if (!CoreRef->ReadMemory(Addr, &V, 8))
                    return Schema::Err(QStringLiteral("Failed to read memory"));
                Result[QStringLiteral("value")] = Schema::FormatAddress(V);
                Result[QStringLiteral("size")] = 8;
            } else {
                uint32_t V = 0;
                if (!CoreRef->ReadMemory(Addr, &V, 4))
                    return Schema::Err(QStringLiteral("Failed to read memory"));
                Result[QStringLiteral("value")] = Schema::FormatAddress(static_cast<Address>(V));
                Result[QStringLiteral("size")] = 4;
            }
            return Result;
        });

    auto MakeWriteTool = [this](const QString& Name, const QString& Desc, int Size, bool IsFloat) {
        RegisterTool(Name, Desc,
            Schema::Build({
                {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
                {QStringLiteral("value"), Schema::String(QStringLiteral("Value to write"))}
            }, {QStringLiteral("address"), QStringLiteral("value")}),
            [this, Size, IsFloat, Name](const QJsonObject& A) -> QJsonValue {
                if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
                Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
                QString ValStr = A.value(QStringLiteral("value")).toString();
                uint8_t Buf[8] = {};
                if (IsFloat && Size == 4) {
                    float V = ValStr.toFloat(); std::memcpy(Buf, &V, 4);
                } else if (IsFloat && Size == 8) {
                    double V = ValStr.toDouble(); std::memcpy(Buf, &V, 8);
                } else if (Size == 4) {
                    if (Name.contains(QStringLiteral("uint"))) { uint32_t V = ValStr.toUInt(); std::memcpy(Buf, &V, 4); }
                    else { int32_t V = ValStr.toInt(); std::memcpy(Buf, &V, 4); }
                } else if (Size == 8) {
                    if (Name.contains(QStringLiteral("uint")) || Name.contains(QStringLiteral("pointer"))) { uint64_t V = ValStr.toULongLong(); std::memcpy(Buf, &V, 8); }
                    else { int64_t V = ValStr.toLongLong(); std::memcpy(Buf, &V, 8); }
                }
                if (!CoreRef->WriteMemory(Addr, Buf, static_cast<size_t>(Size)))
                    return Schema::Err(QStringLiteral("Failed to write memory"));
                QJsonObject Result;
                Result[QStringLiteral("success")] = true;
                Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                return Result;
            });
    };

    MakeWriteTool(QStringLiteral("write_int32"), QStringLiteral("Write a signed 32-bit integer to memory."), 4, false);
    MakeWriteTool(QStringLiteral("write_uint32"), QStringLiteral("Write an unsigned 32-bit integer to memory."), 4, false);
    MakeWriteTool(QStringLiteral("write_int64"), QStringLiteral("Write a signed 64-bit integer to memory."), 8, false);
    MakeWriteTool(QStringLiteral("write_uint64"), QStringLiteral("Write an unsigned 64-bit integer to memory."), 8, false);
    MakeWriteTool(QStringLiteral("write_float"), QStringLiteral("Write a 32-bit float to memory."), 4, true);
    MakeWriteTool(QStringLiteral("write_double"), QStringLiteral("Write a 64-bit double to memory."), 8, true);
    MakeWriteTool(QStringLiteral("write_pointer"), QStringLiteral("Write a pointer-sized value to memory."), 8, false);

    RegisterTool(QStringLiteral("read_unicode_string"),
        QStringLiteral("Read a null-terminated UTF-16LE (wide) string from the given address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("max_length"), Schema::Integer(QStringLiteral("Maximum characters to read"), 1, 65536)}
        }, {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int MaxLen = A.value(QStringLiteral("max_length")).toInt(256);
            QByteArray Buf(MaxLen * 2, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Buf.size())))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            const char16_t* WidePtr = reinterpret_cast<const char16_t*>(Buf.constData());
            int Len = 0;
            for (int I = 0; I < MaxLen; ++I) {
                if (WidePtr[I] == 0) break;
                Len = I + 1;
            }
            QString Str = QString::fromUtf16(WidePtr, Len);
            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("string")] = Str;
            Result[QStringLiteral("length")] = Len;
            return Result;
        });

    RegisterTool(QStringLiteral("write_string"),
        QStringLiteral("Write an ASCII string to memory (with null terminator)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("string"), Schema::String(QStringLiteral("String to write"))}
        }, {QStringLiteral("address"), QStringLiteral("string")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Data = A.value(QStringLiteral("string")).toString().toUtf8();
            Data.append('\0');
            if (!CoreRef->WriteMemory(Addr, Data.constData(), static_cast<size_t>(Data.size())))
                return Schema::Err(QStringLiteral("Failed to write string"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("bytes_written")] = Data.size();
            return Result;
        });

    RegisterTool(QStringLiteral("write_unicode_string"),
        QStringLiteral("Write a UTF-16LE (wide) string to memory (with null terminator)."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("string"), Schema::String(QStringLiteral("String to write"))}
        }, {QStringLiteral("address"), QStringLiteral("string")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QString Str = A.value(QStringLiteral("string")).toString();
            QByteArray Data(reinterpret_cast<const char*>(Str.utf16()), (Str.size() + 1) * 2);
            if (!CoreRef->WriteMemory(Addr, Data.constData(), static_cast<size_t>(Data.size())))
                return Schema::Err(QStringLiteral("Failed to write unicode string"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("bytes_written")] = Data.size();
            return Result;
        });

    RegisterTool(QStringLiteral("find_pointer_chain"),
        QStringLiteral("Resolve a multi-level pointer chain. Reads pointer at base, adds offset, reads next pointer, etc."),
        Schema::Build({
            {QStringLiteral("base_address"), Schema::String(QStringLiteral("Base address in hex"))},
            {QStringLiteral("offsets"), Schema::Array(QStringLiteral("Array of hex offset strings to follow"),
                Schema::String(QStringLiteral("Offset in hex")))}
        }, {QStringLiteral("base_address"), QStringLiteral("offsets")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address CurrentAddr = Schema::ParseHexAddress(A.value(QStringLiteral("base_address")).toString());
            QJsonArray Offsets = A.value(QStringLiteral("offsets")).toArray();
            bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
            int PtrSize = Is64 ? 8 : 4;
            QJsonArray Chain;
            QJsonObject FirstEntry;
            FirstEntry[QStringLiteral("level")] = 0;
            FirstEntry[QStringLiteral("address")] = Schema::FormatAddress(CurrentAddr);
            Chain.append(FirstEntry);
            for (int I = 0; I < Offsets.size(); ++I) {
                uint64_t PtrVal = 0;
                if (!CoreRef->ReadMemory(CurrentAddr, &PtrVal, static_cast<size_t>(PtrSize)))
                    return Schema::Err(QStringLiteral("Failed to read pointer at ") + Schema::FormatAddress(CurrentAddr));
                if (!Is64) PtrVal &= 0xFFFFFFFF;
                Address Offset = Schema::ParseHexAddress(Offsets[I].toString());
                CurrentAddr = PtrVal + Offset;
                QJsonObject Entry;
                Entry[QStringLiteral("level")] = I + 1;
                Entry[QStringLiteral("dereferenced")] = Schema::FormatAddress(PtrVal);
                Entry[QStringLiteral("offset")] = Schema::FormatAddress(Offset);
                Entry[QStringLiteral("result")] = Schema::FormatAddress(CurrentAddr);
                Chain.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("final_address")] = Schema::FormatAddress(CurrentAddr);
            Result[QStringLiteral("chain")] = Chain;
            return Result;
        });

    RegisterTool(QStringLiteral("memory_compare"),
        QStringLiteral("Compare two memory regions byte-by-byte and return differences."),
        Schema::Build({
            {QStringLiteral("address_a"), Schema::String(QStringLiteral("First address in hex"))},
            {QStringLiteral("address_b"), Schema::String(QStringLiteral("Second address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to compare"), 1, 65536)}
        }, {QStringLiteral("address_a"), QStringLiteral("address_b"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address AddrA = Schema::ParseHexAddress(A.value(QStringLiteral("address_a")).toString());
            Address AddrB = Schema::ParseHexAddress(A.value(QStringLiteral("address_b")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(256);
            QByteArray BufA(Size, '\0'), BufB(Size, '\0');
            if (!CoreRef->ReadMemory(AddrA, BufA.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory at address_a"));
            if (!CoreRef->ReadMemory(AddrB, BufB.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory at address_b"));
            QJsonArray Diffs;
            for (int I = 0; I < Size; ++I) {
                if (BufA[I] != BufB[I]) {
                    QJsonObject Diff;
                    Diff[QStringLiteral("offset")] = I;
                    Diff[QStringLiteral("a")] = QString::number(static_cast<uint8_t>(BufA[I]), 16).rightJustified(2, '0').toUpper();
                    Diff[QStringLiteral("b")] = QString::number(static_cast<uint8_t>(BufB[I]), 16).rightJustified(2, '0').toUpper();
                    Diffs.append(Diff);
                    if (Diffs.size() >= 1000) break;
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("total_bytes")] = Size;
            Result[QStringLiteral("differences")] = Diffs.size();
            Result[QStringLiteral("diff_list")] = Diffs;
            Result[QStringLiteral("match_percent")] = 100.0 * (1.0 - static_cast<double>(Diffs.size()) / Size);
            return Result;
        });

    RegisterTool(QStringLiteral("aob_generate"),
        QStringLiteral("Generate an Array of Bytes (AOB) pattern from memory at an address."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes for pattern"), 1, 256)},
            {QStringLiteral("wildcard_address"), Schema::String(QStringLiteral("Optional second address; differing bytes become wildcards"))}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(32);
            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            QByteArray Buf2;
            bool HasSecond = A.contains(QStringLiteral("wildcard_address")) && !A.value(QStringLiteral("wildcard_address")).toString().isEmpty();
            if (HasSecond) {
                Address Addr2 = Schema::ParseHexAddress(A.value(QStringLiteral("wildcard_address")).toString());
                Buf2.resize(Size, '\0');
                if (!CoreRef->ReadMemory(Addr2, Buf2.data(), static_cast<size_t>(Size)))
                    return Schema::Err(QStringLiteral("Failed to read second address"));
            }
            QString Pattern;
            for (int I = 0; I < Size; ++I) {
                if (I > 0) Pattern += ' ';
                if (HasSecond && Buf[I] != Buf2[I]) {
                    Pattern += QStringLiteral("??");
                } else {
                    Pattern += QString::number(static_cast<uint8_t>(Buf[I]), 16).rightJustified(2, '0').toUpper();
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("pattern")] = Pattern;
            return Result;
        });

    RegisterTool(QStringLiteral("dump_region"),
        QStringLiteral("Read an entire memory region and return it as hex string."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to dump"), 1, 1048576)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);
            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory"));
            QJsonObject Result;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("hex")] = QString::fromLatin1(Buf.toHex());
            return Result;
        });

    RegisterTool(QStringLiteral("find_pattern_in_module"),
        QStringLiteral("Scan for a byte pattern within a specific module only."),
        Schema::Build({
            {QStringLiteral("module"), Schema::String(QStringLiteral("Module name (e.g. ntdll.dll)"))},
            {QStringLiteral("pattern"), Schema::String(QStringLiteral("Byte pattern with ?? wildcards"))}
        }, {QStringLiteral("module"), QStringLiteral("pattern")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString ModName = A.value(QStringLiteral("module")).toString();
            QString PatternStr = A.value(QStringLiteral("pattern")).toString();
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            Address ModBase = 0;
            Address ModEnd = 0;
            for (const MemoryRegion& R : Regions) {
                if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
                    if (ModBase == 0 || R.Base < ModBase) ModBase = R.Base;
                    Address End = R.Base + R.Size;
                    if (End > ModEnd) ModEnd = End;
                }
            }
            if (ModBase == 0) return Schema::Err(QStringLiteral("Module not found: ") + ModName);
            QStringList Parts = PatternStr.split(' ', Qt::SkipEmptyParts);
            struct PatByte { uint8_t Value; bool Wild; };
            QVector<PatByte> Pat;
            for (const QString& P : Parts) {
                PatByte Pb;
                if (P == QStringLiteral("??") || P == QStringLiteral("?")) {
                    Pb.Value = 0; Pb.Wild = true;
                } else {
                    bool Ok; Pb.Value = static_cast<uint8_t>(P.toUInt(&Ok, 16)); Pb.Wild = false;
                    if (!Ok) return Schema::Err(QStringLiteral("Invalid pattern byte: ") + P);
                }
                Pat.append(Pb);
            }
            size_t ModSize = static_cast<size_t>(ModEnd - ModBase);
            constexpr size_t ChunkSize = 4 * 1024 * 1024;
            QJsonArray Matches;
            size_t PatSize = static_cast<size_t>(Pat.size());
            Address Cur = ModBase;
            size_t Remaining = ModSize;
            while (Remaining > 0 && Matches.size() < 100) {
                size_t ToRead = std::min(Remaining, ChunkSize);
                QByteArray Chunk(static_cast<int>(ToRead), '\0');
                if (!CoreRef->ReadMemory(Cur, Chunk.data(), ToRead)) { Cur += ToRead; Remaining -= ToRead; continue; }
                for (size_t I = 0; I + PatSize <= ToRead && Matches.size() < 100; ++I) {
                    bool Found = true;
                    for (size_t J = 0; J < PatSize; ++J) {
                        if (Pat[static_cast<int>(J)].Wild) continue;
                        if (static_cast<uint8_t>(Chunk[static_cast<int>(I + J)]) != Pat[static_cast<int>(J)].Value) { Found = false; break; }
                    }
                    if (Found) {
                        QJsonObject M;
                        M[QStringLiteral("address")] = Schema::FormatAddress(Cur + I);
                        M[QStringLiteral("offset")] = Schema::FormatAddress(Cur + I - ModBase);
                        Matches.append(M);
                    }
                }
                Cur += ToRead; Remaining -= ToRead;
            }
            QJsonObject Result;
            Result[QStringLiteral("module")] = ModName;
            Result[QStringLiteral("base")] = Schema::FormatAddress(ModBase);
            Result[QStringLiteral("count")] = Matches.size();
            Result[QStringLiteral("matches")] = Matches;
            return Result;
        });

    auto MakeScanFilterTool = [this](const QString& Name, const QString& Desc, int Mode) {
        RegisterTool(Name, Desc,
            Schema::Build({
                {QStringLiteral("addresses"), Schema::Array(QStringLiteral("Array of hex address strings to check"))},
                {QStringLiteral("old_values"), Schema::Array(QStringLiteral("Corresponding old values (as hex byte strings)"))},
                {QStringLiteral("value_size"), Schema::Integer(QStringLiteral("Size of each value in bytes"), 1, 8)}
            }, {QStringLiteral("addresses"), QStringLiteral("old_values"), QStringLiteral("value_size")}),
            [this, Mode](const QJsonObject& A) -> QJsonValue {
                if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
                QJsonArray Addrs = A.value(QStringLiteral("addresses")).toArray();
                QJsonArray OldVals = A.value(QStringLiteral("old_values")).toArray();
                int ValSize = A.value(QStringLiteral("value_size")).toInt(4);
                QJsonArray Filtered;
                for (int I = 0; I < Addrs.size() && I < OldVals.size(); ++I) {
                    Address Addr = Schema::ParseHexAddress(Addrs[I].toString());
                    QByteArray OldBytes = QByteArray::fromHex(OldVals[I].toString().toLatin1());
                    QByteArray NewBytes(ValSize, '\0');
                    if (!CoreRef->ReadMemory(Addr, NewBytes.data(), static_cast<size_t>(ValSize))) continue;
                    bool Match = false;
                    if (Mode == 0) Match = (NewBytes != OldBytes);
                    else if (Mode == 1) Match = (NewBytes == OldBytes);
                    else if (Mode == 2 || Mode == 3) {
                        int64_t OldV = 0, NewV = 0;
                        std::memcpy(&OldV, OldBytes.constData(), std::min(static_cast<size_t>(ValSize), sizeof(int64_t)));
                        std::memcpy(&NewV, NewBytes.constData(), std::min(static_cast<size_t>(ValSize), sizeof(int64_t)));
                        if (Mode == 2) Match = (NewV > OldV);
                        else Match = (NewV < OldV);
                    }
                    if (Match) {
                        QJsonObject Entry;
                        Entry[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                        Entry[QStringLiteral("old_hex")] = QString::fromLatin1(OldBytes.toHex());
                        Entry[QStringLiteral("new_hex")] = QString::fromLatin1(NewBytes.toHex());
                        Filtered.append(Entry);
                    }
                }
                QJsonObject Result;
                Result[QStringLiteral("count")] = Filtered.size();
                Result[QStringLiteral("results")] = Filtered;
                return Result;
            });
    };

    MakeScanFilterTool(QStringLiteral("scan_changed"), QStringLiteral("Filter addresses where value has changed from old value."), 0);
    MakeScanFilterTool(QStringLiteral("scan_unchanged"), QStringLiteral("Filter addresses where value has NOT changed from old value."), 1);
    MakeScanFilterTool(QStringLiteral("scan_increased"), QStringLiteral("Filter addresses where value has increased from old value."), 2);
    MakeScanFilterTool(QStringLiteral("scan_decreased"), QStringLiteral("Filter addresses where value has decreased from old value."), 3);

    RegisterTool(QStringLiteral("create_snapshot"),
        QStringLiteral("Create a named memory snapshot of a region for later comparison or restoration."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Snapshot name"))},
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to snapshot"), 1, 16777216)}
        }, {QStringLiteral("name"), QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Name = A.value(QStringLiteral("name")).toString();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(4096);
            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read memory for snapshot"));
            QByteArray Header;
            QDataStream Ds(&Header, QIODevice::WriteOnly);
            Ds << static_cast<quint64>(Addr) << static_cast<qint64>(Size);
            MemorySnapshots[Name] = Header + Buf;
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("name")] = Name;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            return Result;
        });

    RegisterTool(QStringLiteral("restore_snapshot"),
        QStringLiteral("Write a previously created snapshot back to its original memory location."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Snapshot name to restore"))}
        }, {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Name = A.value(QStringLiteral("name")).toString();
            if (!MemorySnapshots.contains(Name))
                return Schema::Err(QStringLiteral("Snapshot not found: ") + Name);
            QByteArray Data = MemorySnapshots[Name];
            QDataStream Ds(&Data, QIODevice::ReadOnly);
            quint64 AddrRaw; qint64 Size;
            Ds >> AddrRaw >> Size;
            Address Addr = static_cast<Address>(AddrRaw);
            int HeaderSize = static_cast<int>(sizeof(Address) + sizeof(qint64));
            QByteArray Content = Data.mid(HeaderSize);
            if (!CoreRef->WriteMemory(Addr, Content.constData(), static_cast<size_t>(Content.size())))
                return Schema::Err(QStringLiteral("Failed to write snapshot back to memory"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("name")] = Name;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = static_cast<int>(Content.size());
            return Result;
        });

    RegisterTool(QStringLiteral("compare_snapshots"),
        QStringLiteral("Compare two named snapshots and return byte-level differences."),
        Schema::Build({
            {QStringLiteral("name_a"), Schema::String(QStringLiteral("First snapshot name"))},
            {QStringLiteral("name_b"), Schema::String(QStringLiteral("Second snapshot name"))}
        }, {QStringLiteral("name_a"), QStringLiteral("name_b")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString NameA = A.value(QStringLiteral("name_a")).toString();
            QString NameB = A.value(QStringLiteral("name_b")).toString();
            if (!MemorySnapshots.contains(NameA)) return Schema::Err(QStringLiteral("Snapshot not found: ") + NameA);
            if (!MemorySnapshots.contains(NameB)) return Schema::Err(QStringLiteral("Snapshot not found: ") + NameB);
            QByteArray DataA = MemorySnapshots[NameA];
            QByteArray DataB = MemorySnapshots[NameB];
            int HeaderSize = static_cast<int>(sizeof(Address) + sizeof(qint64));
            QByteArray ContentA = DataA.mid(HeaderSize);
            QByteArray ContentB = DataB.mid(HeaderSize);
            int CmpSize = std::min(ContentA.size(), ContentB.size());
            QJsonArray Diffs;
            for (int I = 0; I < CmpSize && Diffs.size() < 1000; ++I) {
                if (ContentA[I] != ContentB[I]) {
                    QJsonObject D;
                    D[QStringLiteral("offset")] = I;
                    D[QStringLiteral("a")] = QString::number(static_cast<uint8_t>(ContentA[I]), 16).rightJustified(2, '0').toUpper();
                    D[QStringLiteral("b")] = QString::number(static_cast<uint8_t>(ContentB[I]), 16).rightJustified(2, '0').toUpper();
                    Diffs.append(D);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("size_a")] = ContentA.size();
            Result[QStringLiteral("size_b")] = ContentB.size();
            Result[QStringLiteral("differences")] = Diffs.size();
            Result[QStringLiteral("diff_list")] = Diffs;
            return Result;
        });

    RegisterTool(QStringLiteral("list_snapshots"),
        QStringLiteral("List all stored memory snapshots."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonArray Arr;
            for (auto It = MemorySnapshots.constBegin(); It != MemorySnapshots.constEnd(); ++It) {
                QJsonObject Entry;
                Entry[QStringLiteral("name")] = It.key();
                int HeaderSize = static_cast<int>(sizeof(Address) + sizeof(qint64));
                int ContentSize = It.value().size() - HeaderSize;
                Entry[QStringLiteral("data_size")] = ContentSize;
                QByteArray Copy = It.value();
                QDataStream Ds(&Copy, QIODevice::ReadOnly);
                quint64 AddrRaw; qint64 Sz;
                Ds >> AddrRaw >> Sz;
                Address Addr = static_cast<Address>(AddrRaw);
                Entry[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                Arr.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Arr.size();
            Result[QStringLiteral("snapshots")] = Arr;
            return Result;
        });

    RegisterTool(QStringLiteral("delete_snapshot"),
        QStringLiteral("Delete a named memory snapshot."),
        Schema::Build({{QStringLiteral("name"), Schema::String(QStringLiteral("Snapshot name to delete"))}},
                      {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Name = A.value(QStringLiteral("name")).toString();
            if (!MemorySnapshots.remove(Name))
                return Schema::Err(QStringLiteral("Snapshot not found: ") + Name);
            return Schema::Ok(QStringLiteral("Snapshot deleted: ") + Name);
        });

    RegisterTool(QStringLiteral("patch_bytes"),
        QStringLiteral("Write bytes to memory and store a backup for later undo."),
        Schema::Build({
            {QStringLiteral("name"), Schema::String(QStringLiteral("Patch name for reference"))},
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex bytes to write (e.g. 90909090)"))}
        }, {QStringLiteral("name"), QStringLiteral("address"), QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Name = A.value(QStringLiteral("name")).toString();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray NewBytes = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().remove(' ').toLatin1());
            if (NewBytes.isEmpty()) return Schema::Err(QStringLiteral("Invalid hex data"));
            QByteArray OldBytes(NewBytes.size(), '\0');
            if (!CoreRef->ReadMemory(Addr, OldBytes.data(), static_cast<size_t>(OldBytes.size())))
                return Schema::Err(QStringLiteral("Failed to read original bytes"));
            if (!CoreRef->WriteMemory(Addr, NewBytes.constData(), static_cast<size_t>(NewBytes.size())))
                return Schema::Err(QStringLiteral("Failed to write patch"));
            PatchBackups[Name] = qMakePair(Addr, OldBytes);
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("name")] = Name;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("bytes_patched")] = NewBytes.size();
            Result[QStringLiteral("old_bytes")] = QString::fromLatin1(OldBytes.toHex(' '));
            return Result;
        });

    RegisterTool(QStringLiteral("unpatch_bytes"),
        QStringLiteral("Restore original bytes from a previous patch_bytes operation."),
        Schema::Build({{QStringLiteral("name"), Schema::String(QStringLiteral("Patch name to undo"))}},
                      {QStringLiteral("name")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString Name = A.value(QStringLiteral("name")).toString();
            if (!PatchBackups.contains(Name))
                return Schema::Err(QStringLiteral("Patch not found: ") + Name);
            auto Backup = PatchBackups[Name];
            if (!CoreRef->WriteMemory(Backup.first, Backup.second.constData(), static_cast<size_t>(Backup.second.size())))
                return Schema::Err(QStringLiteral("Failed to restore original bytes"));
            PatchBackups.remove(Name);
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("name")] = Name;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Backup.first);
            Result[QStringLiteral("bytes_restored")] = Backup.second.size();
            return Result;
        });

    RegisterTool(QStringLiteral("list_patches"),
        QStringLiteral("List all active patches that can be undone."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonArray Arr;
            for (auto It = PatchBackups.constBegin(); It != PatchBackups.constEnd(); ++It) {
                QJsonObject Entry;
                Entry[QStringLiteral("name")] = It.key();
                Entry[QStringLiteral("address")] = Schema::FormatAddress(It.value().first);
                Entry[QStringLiteral("size")] = It.value().second.size();
                Entry[QStringLiteral("original_bytes")] = QString::fromLatin1(It.value().second.toHex(' '));
                Arr.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Arr.size();
            Result[QStringLiteral("patches")] = Arr;
            return Result;
        });

    RegisterTool(QStringLiteral("nop_instruction"),
        QStringLiteral("NOP out an instruction at address. Reads instruction length and overwrites with 0x90 bytes. Stores backup."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Instruction address in hex"))},
            {QStringLiteral("length"), Schema::Integer(QStringLiteral("Instruction length in bytes (1-15)"), 1, 15)}
        }, {QStringLiteral("address"), QStringLiteral("length")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Len = A.value(QStringLiteral("length")).toInt(1);
            QByteArray OldBytes(Len, '\0');
            if (!CoreRef->ReadMemory(Addr, OldBytes.data(), static_cast<size_t>(Len)))
                return Schema::Err(QStringLiteral("Failed to read instruction bytes"));
            QByteArray Nops(Len, static_cast<char>(0x90));
            if (!CoreRef->WriteMemory(Addr, Nops.constData(), static_cast<size_t>(Len)))
                return Schema::Err(QStringLiteral("Failed to write NOP bytes"));
            QString PatchName = QStringLiteral("nop_") + Schema::FormatAddress(Addr);
            PatchBackups[PatchName] = qMakePair(Addr, OldBytes);
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("length")] = Len;
            Result[QStringLiteral("original_bytes")] = QString::fromLatin1(OldBytes.toHex(' '));
            Result[QStringLiteral("patch_name")] = PatchName;
            return Result;
        });

    RegisterTool(QStringLiteral("nop_range"),
        QStringLiteral("NOP out a range of N bytes at address with 0x90."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to NOP"), 1, 4096)}
        }, {QStringLiteral("address"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(1);
            QByteArray OldBytes(Size, '\0');
            if (!CoreRef->ReadMemory(Addr, OldBytes.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read original bytes"));
            QByteArray Nops(Size, static_cast<char>(0x90));
            if (!CoreRef->WriteMemory(Addr, Nops.constData(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to NOP range"));
            QString PatchName = QStringLiteral("nop_range_") + Schema::FormatAddress(Addr);
            PatchBackups[PatchName] = qMakePair(Addr, OldBytes);
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("patch_name")] = PatchName;
            return Result;
        });

    RegisterTool(QStringLiteral("freeze_value"),
        QStringLiteral("Register an address+value to be frozen (written repeatedly). Stores intent; use with a freeze timer."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Memory address in hex"))},
            {QStringLiteral("hex_value"), Schema::String(QStringLiteral("Hex bytes to freeze to (e.g. E8030000 for 1000 as int32)"))}
        }, {QStringLiteral("address"), QStringLiteral("hex_value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QByteArray Val = QByteArray::fromHex(A.value(QStringLiteral("hex_value")).toString().remove(' ').toLatin1());
            if (Val.isEmpty()) return Schema::Err(QStringLiteral("Invalid hex value"));
            FrozenValues[Addr] = Val;
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Val.size();
            Result[QStringLiteral("frozen_count")] = FrozenValues.size();
            return Result;
        });

    RegisterTool(QStringLiteral("unfreeze_value"),
        QStringLiteral("Remove a frozen value registration."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Address to unfreeze"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            if (!FrozenValues.remove(Addr))
                return Schema::Err(QStringLiteral("Address not frozen: ") + Schema::FormatAddress(Addr));
            return Schema::Ok(QStringLiteral("Unfrozen: ") + Schema::FormatAddress(Addr));
        });

    RegisterTool(QStringLiteral("list_frozen"),
        QStringLiteral("List all frozen value registrations."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            QJsonArray Arr;
            for (auto It = FrozenValues.constBegin(); It != FrozenValues.constEnd(); ++It) {
                QJsonObject Entry;
                Entry[QStringLiteral("address")] = Schema::FormatAddress(It.key());
                Entry[QStringLiteral("hex_value")] = QString::fromLatin1(It.value().toHex(' '));
                Entry[QStringLiteral("size")] = It.value().size();
                Arr.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Arr.size();
            Result[QStringLiteral("frozen")] = Arr;
            return Result;
        });

    RegisterTool(QStringLiteral("get_page_info"),
        QStringLiteral("Get memory page protection info for a specific address."),
        Schema::Build({{QStringLiteral("address"), Schema::String(QStringLiteral("Address in hex"))}},
                      {QStringLiteral("address")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            for (const MemoryRegion& R : Regions) {
                if (Addr >= R.Base && Addr < R.Base + R.Size) {
                    QJsonObject Result;
                    Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
                    Result[QStringLiteral("region_base")] = Schema::FormatAddress(R.Base);
                    Result[QStringLiteral("region_size")] = static_cast<qint64>(R.Size);
                    Result[QStringLiteral("protection")] = static_cast<int>(R.Protection);
                    if (!R.ModuleName.isEmpty())
                        Result[QStringLiteral("module")] = R.ModuleName;
                    Result[QStringLiteral("offset_in_region")] = Schema::FormatAddress(Addr - R.Base);
                    return Result;
                }
            }
            return Schema::Err(QStringLiteral("Address not found in any memory region"));
        });

    auto MakeMemSearchTool = [this](const QString& Name, const QString& Desc, int Mode) {
        QJsonObject SearchSchema;
        if (Mode == 0 || Mode == 1) {
            SearchSchema = Schema::Build({
                {QStringLiteral("search"), Schema::String(QStringLiteral("String to search for"))},
                {QStringLiteral("max_results"), Schema::Integer(QStringLiteral("Maximum results"), 1, 1000)}
            }, {QStringLiteral("search")});
        } else {
            SearchSchema = Schema::Build({
                {QStringLiteral("hex_bytes"), Schema::String(QStringLiteral("Hex bytes to search for (e.g. 48 8B 05)"))},
                {QStringLiteral("max_results"), Schema::Integer(QStringLiteral("Maximum results"), 1, 1000)}
            }, {QStringLiteral("hex_bytes")});
        }
        RegisterTool(Name, Desc, SearchSchema,
            [this, Mode](const QJsonObject& A) -> QJsonValue {
                if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
                QByteArray SearchBytes;
                if (Mode == 0) {
                    SearchBytes = A.value(QStringLiteral("search")).toString().toUtf8();
                } else if (Mode == 1) {
                    QString Str = A.value(QStringLiteral("search")).toString();
                    SearchBytes = QByteArray(reinterpret_cast<const char*>(Str.utf16()), Str.size() * 2);
                } else {
                    SearchBytes = QByteArray::fromHex(A.value(QStringLiteral("hex_bytes")).toString().remove(' ').toLatin1());
                }
                if (SearchBytes.isEmpty()) return Schema::Err(QStringLiteral("Empty search data"));
                int MaxResults = A.value(QStringLiteral("max_results")).toInt(100);
                QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
                QJsonArray Matches;
                constexpr size_t ChunkSize = 4 * 1024 * 1024;
                for (const MemoryRegion& R : Regions) {
                    if (Matches.size() >= MaxResults) break;
                    size_t Remaining = R.Size;
                    Address Cur = R.Base;
                    while (Remaining > 0 && Matches.size() < MaxResults) {
                        size_t ToRead = std::min(Remaining, ChunkSize);
                        QByteArray Chunk(static_cast<int>(ToRead), '\0');
                        if (!CoreRef->ReadMemory(Cur, Chunk.data(), ToRead)) { Cur += ToRead; Remaining -= ToRead; continue; }
                        int Pos = 0;
                        while (Pos >= 0 && Matches.size() < MaxResults) {
                            Pos = Chunk.indexOf(SearchBytes, Pos);
                            if (Pos >= 0) {
                                QJsonObject M;
                                M[QStringLiteral("address")] = Schema::FormatAddress(Cur + static_cast<size_t>(Pos));
                                if (!R.ModuleName.isEmpty()) M[QStringLiteral("module")] = R.ModuleName;
                                Matches.append(M);
                                Pos++;
                            }
                        }
                        Cur += ToRead; Remaining -= ToRead;
                    }
                }
                QJsonObject Result;
                Result[QStringLiteral("count")] = Matches.size();
                Result[QStringLiteral("matches")] = Matches;
                return Result;
            });
    };

    MakeMemSearchTool(QStringLiteral("memory_search_string"), QStringLiteral("Search all memory for an ASCII string."), 0);
    MakeMemSearchTool(QStringLiteral("memory_search_unicode"), QStringLiteral("Search all memory for a UTF-16LE (wide) string."), 1);
    MakeMemSearchTool(QStringLiteral("memory_search_bytes"), QStringLiteral("Search all memory for a raw hex byte sequence."), 2);

    RegisterTool(QStringLiteral("memory_fill"),
        QStringLiteral("Fill N bytes at address with a single byte value."),
        Schema::Build({
            {QStringLiteral("address"), Schema::String(QStringLiteral("Start address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to fill"), 1, 1048576)},
            {QStringLiteral("byte"), Schema::Integer(QStringLiteral("Byte value (0-255)"), 0, 255)}
        }, {QStringLiteral("address"), QStringLiteral("size"), QStringLiteral("byte")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Addr = Schema::ParseHexAddress(A.value(QStringLiteral("address")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(1);
            int ByteVal = A.value(QStringLiteral("byte")).toInt(0);
            QByteArray Buf(Size, static_cast<char>(ByteVal));
            if (!CoreRef->WriteMemory(Addr, Buf.constData(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to fill memory"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("size")] = Size;
            Result[QStringLiteral("byte")] = ByteVal;
            return Result;
        });

    RegisterTool(QStringLiteral("memory_copy"),
        QStringLiteral("Copy N bytes from source address to destination address within the target process."),
        Schema::Build({
            {QStringLiteral("source"), Schema::String(QStringLiteral("Source address in hex"))},
            {QStringLiteral("destination"), Schema::String(QStringLiteral("Destination address in hex"))},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to copy"), 1, 1048576)}
        }, {QStringLiteral("source"), QStringLiteral("destination"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Src = Schema::ParseHexAddress(A.value(QStringLiteral("source")).toString());
            Address Dst = Schema::ParseHexAddress(A.value(QStringLiteral("destination")).toString());
            int Size = A.value(QStringLiteral("size")).toInt(1);
            QByteArray Buf(Size, '\0');
            if (!CoreRef->ReadMemory(Src, Buf.data(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to read from source"));
            if (!CoreRef->WriteMemory(Dst, Buf.constData(), static_cast<size_t>(Size)))
                return Schema::Err(QStringLiteral("Failed to write to destination"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("source")] = Schema::FormatAddress(Src);
            Result[QStringLiteral("destination")] = Schema::FormatAddress(Dst);
            Result[QStringLiteral("size")] = Size;
            return Result;
        });

    RegisterTool(QStringLiteral("get_memory_stats"),
        QStringLiteral("Get summary statistics about the process memory layout."),
        Schema::Empty(),
        [this](const QJsonObject&) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            qint64 TotalSize = 0;
            qint64 LargestRegion = 0;
            QSet<QString> ModuleNames;
            int ReadableCount = 0;
            int WritableCount = 0;
            int ExecutableCount = 0;
            for (const MemoryRegion& R : Regions) {
                TotalSize += static_cast<qint64>(R.Size);
                if (static_cast<qint64>(R.Size) > LargestRegion)
                    LargestRegion = static_cast<qint64>(R.Size);
                if (!R.ModuleName.isEmpty()) ModuleNames.insert(R.ModuleName);
                uint32_t P = R.Protection;
                if (P & 0x02 || P & 0x04 || P & 0x20 || P & 0x40) ReadableCount++;
                if (P & 0x04 || P & 0x08 || P & 0x40 || P & 0x80) WritableCount++;
                if (P & 0x10 || P & 0x20 || P & 0x40 || P & 0x80) ExecutableCount++;
            }
            QJsonObject Result;
            Result[QStringLiteral("total_regions")] = Regions.size();
            Result[QStringLiteral("total_committed_bytes")] = TotalSize;
            Result[QStringLiteral("total_committed_mb")] = static_cast<double>(TotalSize) / (1024.0 * 1024.0);
            Result[QStringLiteral("largest_region_bytes")] = LargestRegion;
            Result[QStringLiteral("module_count")] = ModuleNames.size();
            Result[QStringLiteral("readable_regions")] = ReadableCount;
            Result[QStringLiteral("writable_regions")] = WritableCount;
            Result[QStringLiteral("executable_regions")] = ExecutableCount;
            return Result;
        });

    RegisterTool(QStringLiteral("find_module_base"),
        QStringLiteral("Find the base address of a module by name."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name (e.g. kernel32.dll)"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString ModName = A.value(QStringLiteral("module")).toString();
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            Address Base = 0;
            for (const MemoryRegion& R : Regions) {
                if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
                    if (Base == 0 || R.Base < Base) Base = R.Base;
                }
            }
            if (Base == 0) return Schema::Err(QStringLiteral("Module not found: ") + ModName);
            QJsonObject Result;
            Result[QStringLiteral("module")] = ModName;
            Result[QStringLiteral("base")] = Schema::FormatAddress(Base);
            return Result;
        });

    RegisterTool(QStringLiteral("get_module_size"),
        QStringLiteral("Get the total mapped size of a module."),
        Schema::Build({{QStringLiteral("module"), Schema::String(QStringLiteral("Module name"))}},
                      {QStringLiteral("module")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            QString ModName = A.value(QStringLiteral("module")).toString();
            QList<MemoryRegion> Regions = CoreRef->GetMemoryRegions();
            Address MinBase = UINT64_MAX;
            Address MaxEnd = 0;
            bool Found = false;
            for (const MemoryRegion& R : Regions) {
                if (R.ModuleName.compare(ModName, Qt::CaseInsensitive) == 0) {
                    Found = true;
                    if (R.Base < MinBase) MinBase = R.Base;
                    Address End = R.Base + R.Size;
                    if (End > MaxEnd) MaxEnd = End;
                }
            }
            if (!Found) return Schema::Err(QStringLiteral("Module not found: ") + ModName);
            QJsonObject Result;
            Result[QStringLiteral("module")] = ModName;
            Result[QStringLiteral("base")] = Schema::FormatAddress(MinBase);
            Result[QStringLiteral("size")] = static_cast<qint64>(MaxEnd - MinBase);
            Result[QStringLiteral("end")] = Schema::FormatAddress(MaxEnd);
            return Result;
        });

    RegisterTool(QStringLiteral("read_struct_fields"),
        QStringLiteral("Read multiple typed fields from a base address. Each field specifies offset, type, and name."),
        Schema::Build({
            {QStringLiteral("base_address"), Schema::String(QStringLiteral("Base address in hex"))},
            {QStringLiteral("fields"), Schema::Array(QStringLiteral("Array of field descriptors: {offset: hex, type: int8/uint8/.../float/double/pointer, name: string}"))}
        }, {QStringLiteral("base_address"), QStringLiteral("fields")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = Schema::ParseHexAddress(A.value(QStringLiteral("base_address")).toString());
            QJsonArray Fields = A.value(QStringLiteral("fields")).toArray();
            bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
            QJsonObject Values;
            for (int I = 0; I < Fields.size(); ++I) {
                QJsonObject Field = Fields[I].toObject();
                Address Offset = Schema::ParseHexAddress(Field.value(QStringLiteral("offset")).toString());
                QString Type = Field.value(QStringLiteral("type")).toString().toLower();
                QString Name = Field.value(QStringLiteral("name")).toString();
                if (Name.isEmpty()) Name = QStringLiteral("field_") + QString::number(I);
                Address Addr = Base + Offset;
                if (Type == QStringLiteral("int8")) { int8_t V = 0; CoreRef->ReadMemory(Addr, &V, 1); Values[Name] = static_cast<int>(V); }
                else if (Type == QStringLiteral("uint8")) { uint8_t V = 0; CoreRef->ReadMemory(Addr, &V, 1); Values[Name] = static_cast<int>(V); }
                else if (Type == QStringLiteral("int16")) { int16_t V = 0; CoreRef->ReadMemory(Addr, &V, 2); Values[Name] = static_cast<int>(V); }
                else if (Type == QStringLiteral("uint16")) { uint16_t V = 0; CoreRef->ReadMemory(Addr, &V, 2); Values[Name] = static_cast<int>(V); }
                else if (Type == QStringLiteral("int32")) { int32_t V = 0; CoreRef->ReadMemory(Addr, &V, 4); Values[Name] = V; }
                else if (Type == QStringLiteral("uint32")) { uint32_t V = 0; CoreRef->ReadMemory(Addr, &V, 4); Values[Name] = static_cast<qint64>(V); }
                else if (Type == QStringLiteral("int64")) { int64_t V = 0; CoreRef->ReadMemory(Addr, &V, 8); Values[Name] = static_cast<qint64>(V); }
                else if (Type == QStringLiteral("uint64")) { uint64_t V = 0; CoreRef->ReadMemory(Addr, &V, 8); Values[Name] = QString::number(V); }
                else if (Type == QStringLiteral("float")) { float V = 0; CoreRef->ReadMemory(Addr, &V, 4); Values[Name] = static_cast<double>(V); }
                else if (Type == QStringLiteral("double")) { double V = 0; CoreRef->ReadMemory(Addr, &V, 8); Values[Name] = V; }
                else if (Type == QStringLiteral("pointer")) {
                    if (Is64) { uint64_t V = 0; CoreRef->ReadMemory(Addr, &V, 8); Values[Name] = Schema::FormatAddress(V); }
                    else { uint32_t V = 0; CoreRef->ReadMemory(Addr, &V, 4); Values[Name] = Schema::FormatAddress(static_cast<Address>(V)); }
                }
                else { Values[Name] = QStringLiteral("unknown type: ") + Type; }
            }
            QJsonObject Result;
            Result[QStringLiteral("base_address")] = Schema::FormatAddress(Base);
            Result[QStringLiteral("values")] = Values;
            return Result;
        });

    RegisterTool(QStringLiteral("write_struct_field"),
        QStringLiteral("Write a typed value at base_address + offset."),
        Schema::Build({
            {QStringLiteral("base_address"), Schema::String(QStringLiteral("Base address in hex"))},
            {QStringLiteral("offset"), Schema::String(QStringLiteral("Field offset in hex"))},
            {QStringLiteral("type"), Schema::StringEnum(QStringLiteral("Value type"),
                {QStringLiteral("int8"), QStringLiteral("uint8"), QStringLiteral("int16"), QStringLiteral("uint16"),
                 QStringLiteral("int32"), QStringLiteral("uint32"), QStringLiteral("int64"), QStringLiteral("uint64"),
                 QStringLiteral("float"), QStringLiteral("double"), QStringLiteral("pointer")})},
            {QStringLiteral("value"), Schema::String(QStringLiteral("Value to write"))}
        }, {QStringLiteral("base_address"), QStringLiteral("offset"), QStringLiteral("type"), QStringLiteral("value")}),
        [this](const QJsonObject& A) -> QJsonValue {
            if (!CoreRef || !CoreRef->IsAttached()) return Schema::NotAttached();
            Address Base = Schema::ParseHexAddress(A.value(QStringLiteral("base_address")).toString());
            Address Offset = Schema::ParseHexAddress(A.value(QStringLiteral("offset")).toString());
            Address Addr = Base + Offset;
            QString Type = A.value(QStringLiteral("type")).toString().toLower();
            QString ValStr = A.value(QStringLiteral("value")).toString();
            bool Written = false;
            if (Type == QStringLiteral("int8")) { int8_t V = static_cast<int8_t>(ValStr.toInt()); Written = CoreRef->WriteMemory(Addr, &V, 1); }
            else if (Type == QStringLiteral("uint8")) { uint8_t V = static_cast<uint8_t>(ValStr.toUInt()); Written = CoreRef->WriteMemory(Addr, &V, 1); }
            else if (Type == QStringLiteral("int16")) { int16_t V = static_cast<int16_t>(ValStr.toShort()); Written = CoreRef->WriteMemory(Addr, &V, 2); }
            else if (Type == QStringLiteral("uint16")) { uint16_t V = static_cast<uint16_t>(ValStr.toUShort()); Written = CoreRef->WriteMemory(Addr, &V, 2); }
            else if (Type == QStringLiteral("int32")) { int32_t V = ValStr.toInt(); Written = CoreRef->WriteMemory(Addr, &V, 4); }
            else if (Type == QStringLiteral("uint32")) { uint32_t V = ValStr.toUInt(); Written = CoreRef->WriteMemory(Addr, &V, 4); }
            else if (Type == QStringLiteral("int64")) { int64_t V = ValStr.toLongLong(); Written = CoreRef->WriteMemory(Addr, &V, 8); }
            else if (Type == QStringLiteral("uint64")) { uint64_t V = ValStr.toULongLong(); Written = CoreRef->WriteMemory(Addr, &V, 8); }
            else if (Type == QStringLiteral("float")) { float V = ValStr.toFloat(); Written = CoreRef->WriteMemory(Addr, &V, 4); }
            else if (Type == QStringLiteral("double")) { double V = ValStr.toDouble(); Written = CoreRef->WriteMemory(Addr, &V, 8); }
            else if (Type == QStringLiteral("pointer")) {
                bool Is64 = CoreRef->CurrentProcess().Arch != Architecture::X86;
                uint64_t V = Schema::ParseHexAddress(ValStr);
                if (Is64) Written = CoreRef->WriteMemory(Addr, &V, 8);
                else { uint32_t V32 = static_cast<uint32_t>(V); Written = CoreRef->WriteMemory(Addr, &V32, 4); }
            }
            if (!Written) return Schema::Err(QStringLiteral("Failed to write field"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("address")] = Schema::FormatAddress(Addr);
            Result[QStringLiteral("base")] = Schema::FormatAddress(Base);
            Result[QStringLiteral("offset")] = Schema::FormatAddress(Offset);
            return Result;
        });
}

}
