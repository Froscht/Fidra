#include "McpToolRegistry.h"
#include "McpSchemaBuilder.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonDocument>
#include <cstring>
#include <cmath>

namespace Fidra {

static double CalcEntropy(const char* Data, int Size) {
    if (Size <= 0) return 0.0;
    int Freq[256] = {};
    for (int I = 0; I < Size; ++I)
        Freq[static_cast<uint8_t>(Data[I])]++;
    double Entropy = 0.0;
    for (int I = 0; I < 256; ++I) {
        if (Freq[I] == 0) continue;
        double P = static_cast<double>(Freq[I]) / static_cast<double>(Size);
        Entropy -= P * std::log2(P);
    }
    return Entropy;
}

void McpToolRegistry::RegisterFileTools() {

    RegisterTool(QStringLiteral("open_binary_file"),
        QStringLiteral("Open a binary file and return basic info: size, first 64 bytes, detected file type."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the binary file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("size")] = Data.size();
            int PreviewSize = std::min(64, static_cast<int>(Data.size()));
            Result[QStringLiteral("first_bytes")] = QString::fromLatin1(Data.left(PreviewSize).toHex(' '));
            QString FileType = QStringLiteral("Unknown");
            if (Data.size() >= 2 && static_cast<uint8_t>(Data[0]) == 0x4D && static_cast<uint8_t>(Data[1]) == 0x5A)
                FileType = QStringLiteral("PE (MZ)");
            else if (Data.size() >= 4 && static_cast<uint8_t>(Data[0]) == 0x7F && Data[1] == 'E' && Data[2] == 'L' && Data[3] == 'F')
                FileType = QStringLiteral("ELF");
            else if (Data.size() >= 4 && static_cast<uint8_t>(Data[0]) == 0xCA && static_cast<uint8_t>(Data[1]) == 0xFE && static_cast<uint8_t>(Data[2]) == 0xBA && static_cast<uint8_t>(Data[3]) == 0xBE)
                FileType = QStringLiteral("Mach-O / Java Class");
            else if (Data.size() >= 4 && static_cast<uint8_t>(Data[0]) == 0xCE && static_cast<uint8_t>(Data[1]) == 0xFA && static_cast<uint8_t>(Data[2]) == 0xED && static_cast<uint8_t>(Data[3]) == 0xFE)
                FileType = QStringLiteral("Mach-O (32-bit)");
            else if (Data.size() >= 4 && static_cast<uint8_t>(Data[0]) == 0xCF && static_cast<uint8_t>(Data[1]) == 0xFA && static_cast<uint8_t>(Data[2]) == 0xED && static_cast<uint8_t>(Data[3]) == 0xFE)
                FileType = QStringLiteral("Mach-O (64-bit)");
            else if (Data.size() >= 2 && Data[0] == 'P' && Data[1] == 'K')
                FileType = QStringLiteral("ZIP / PKZIP");
            else if (Data.size() >= 2 && static_cast<uint8_t>(Data[0]) == 0x1F && static_cast<uint8_t>(Data[1]) == 0x8B)
                FileType = QStringLiteral("GZIP");
            else if (Data.size() >= 8 && static_cast<uint8_t>(Data[0]) == 0x89 && Data[1] == 'P' && Data[2] == 'N' && Data[3] == 'G')
                FileType = QStringLiteral("PNG");
            else if (Data.size() >= 2 && static_cast<uint8_t>(Data[0]) == 0xFF && static_cast<uint8_t>(Data[1]) == 0xD8)
                FileType = QStringLiteral("JPEG");
            else if (Data.size() >= 4 && Data[0] == '%' && Data[1] == 'P' && Data[2] == 'D' && Data[3] == 'F')
                FileType = QStringLiteral("PDF");
            else if (Data.size() >= 4 && Data[0] == 'R' && Data[1] == 'a' && Data[2] == 'r' && Data[3] == '!')
                FileType = QStringLiteral("RAR");
            else if (Data.size() >= 6 && Data[0] == '7' && Data[1] == 'z' && static_cast<uint8_t>(Data[2]) == 0xBC && static_cast<uint8_t>(Data[3]) == 0xAF)
                FileType = QStringLiteral("7z");
            Result[QStringLiteral("type")] = FileType;
            Result[QStringLiteral("entropy")] = CalcEntropy(Data.constData(), Data.size());
            return Result;
        });

    RegisterTool(QStringLiteral("get_file_info"),
        QStringLiteral("Get file metadata: path, size, permissions, created/modified dates, extension."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFileInfo Info(Path);
            if (!Info.exists())
                return Schema::Err(QStringLiteral("File does not exist: ") + Path);
            QJsonObject Result;
            Result[QStringLiteral("path")] = Info.absoluteFilePath();
            Result[QStringLiteral("name")] = Info.fileName();
            Result[QStringLiteral("extension")] = Info.suffix();
            Result[QStringLiteral("size")] = Info.size();
            Result[QStringLiteral("is_readable")] = Info.isReadable();
            Result[QStringLiteral("is_writable")] = Info.isWritable();
            Result[QStringLiteral("is_executable")] = Info.isExecutable();
            Result[QStringLiteral("is_symlink")] = Info.isSymLink();
            Result[QStringLiteral("created")] = Info.birthTime().toString(Qt::ISODate);
            Result[QStringLiteral("modified")] = Info.lastModified().toString(Qt::ISODate);
            Result[QStringLiteral("accessed")] = Info.lastRead().toString(Qt::ISODate);
            Result[QStringLiteral("owner")] = Info.owner();
            Result[QStringLiteral("group")] = Info.group();
            Result[QStringLiteral("permissions")] = QString::number(static_cast<int>(Info.permissions()), 16);
            return Result;
        });

    RegisterTool(QStringLiteral("calculate_file_hash"),
        QStringLiteral("Calculate MD5, SHA1, and SHA256 hashes of a file."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("size")] = Data.size();
            Result[QStringLiteral("md5")] = QString::fromLatin1(QCryptographicHash::hash(Data, QCryptographicHash::Md5).toHex());
            Result[QStringLiteral("sha1")] = QString::fromLatin1(QCryptographicHash::hash(Data, QCryptographicHash::Sha1).toHex());
            Result[QStringLiteral("sha256")] = QString::fromLatin1(QCryptographicHash::hash(Data, QCryptographicHash::Sha256).toHex());
            return Result;
        });

    RegisterTool(QStringLiteral("calculate_hash"),
        QStringLiteral("Calculate hash of arbitrary hex data. Supports md5, sha1, sha256, sha512."),
        Schema::Build({
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex-encoded data to hash"))},
            {QStringLiteral("algorithm"), Schema::StringEnum(QStringLiteral("Hash algorithm"), {QStringLiteral("md5"), QStringLiteral("sha1"), QStringLiteral("sha256"), QStringLiteral("sha512")})}
        }, {QStringLiteral("hex_data"), QStringLiteral("algorithm")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QByteArray Data = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().toLatin1());
            if (Data.isEmpty())
                return Schema::Err(QStringLiteral("Invalid hex data"));
            QString Algo = A.value(QStringLiteral("algorithm")).toString().toLower();
            QCryptographicHash::Algorithm HashAlgo = QCryptographicHash::Sha256;
            if (Algo == QStringLiteral("md5")) HashAlgo = QCryptographicHash::Md5;
            else if (Algo == QStringLiteral("sha1")) HashAlgo = QCryptographicHash::Sha1;
            else if (Algo == QStringLiteral("sha256")) HashAlgo = QCryptographicHash::Sha256;
            else if (Algo == QStringLiteral("sha512")) HashAlgo = QCryptographicHash::Sha512;
            QJsonObject Result;
            Result[QStringLiteral("algorithm")] = Algo;
            Result[QStringLiteral("input_size")] = Data.size();
            Result[QStringLiteral("hash")] = QString::fromLatin1(QCryptographicHash::hash(Data, HashAlgo).toHex());
            return Result;
        });

    RegisterTool(QStringLiteral("check_pe_signature"),
        QStringLiteral("Check if a file is a valid PE by verifying MZ and PE signatures."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.read(4096);
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            if (Data.size() < 64) {
                Result[QStringLiteral("valid_pe")] = false;
                Result[QStringLiteral("reason")] = QStringLiteral("File too small for PE");
                return Result;
            }
            uint16_t DosMagic = *reinterpret_cast<const uint16_t*>(Data.constData());
            Result[QStringLiteral("dos_magic")] = (DosMagic == 0x5A4D) ? QStringLiteral("MZ (valid)") : QStringLiteral("Invalid");
            if (DosMagic != 0x5A4D) {
                Result[QStringLiteral("valid_pe")] = false;
                return Result;
            }
            uint32_t PeOffset = *reinterpret_cast<const uint32_t*>(Data.constData() + 0x3C);
            Result[QStringLiteral("pe_offset")] = QStringLiteral("0x") + QString::number(PeOffset, 16).toUpper();
            if (static_cast<int>(PeOffset + 4) > Data.size()) {
                Result[QStringLiteral("valid_pe")] = false;
                Result[QStringLiteral("reason")] = QStringLiteral("PE offset out of range");
                return Result;
            }
            uint32_t PeSig = *reinterpret_cast<const uint32_t*>(Data.constData() + PeOffset);
            Result[QStringLiteral("pe_signature")] = (PeSig == 0x00004550) ? QStringLiteral("PE\\0\\0 (valid)") : QStringLiteral("Invalid");
            Result[QStringLiteral("valid_pe")] = (PeSig == 0x00004550);
            if (PeSig == 0x00004550) {
                uint16_t Machine = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 4);
                if (Machine == 0x8664) Result[QStringLiteral("machine")] = QStringLiteral("x64");
                else if (Machine == 0x014C) Result[QStringLiteral("machine")] = QStringLiteral("x86");
                else if (Machine == 0xAA64) Result[QStringLiteral("machine")] = QStringLiteral("ARM64");
                else Result[QStringLiteral("machine")] = QStringLiteral("0x") + QString::number(Machine, 16);
            }
            return Result;
        });

    RegisterTool(QStringLiteral("extract_strings_from_file"),
        QStringLiteral("Extract printable ASCII strings from a file with minimum length."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("min_length"), Schema::Integer(QStringLiteral("Minimum string length (default 4)"), 1, 1000)}
        }, {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            int MinLen = A.value(QStringLiteral("min_length")).toInt(4);
            QJsonArray Strings;
            QString Current;
            int StartOffset = 0;
            constexpr int MaxStrings = 5000;
            for (int I = 0; I < Data.size() && Strings.size() < MaxStrings; ++I) {
                char C = Data[I];
                if (C >= 0x20 && C <= 0x7E) {
                    if (Current.isEmpty()) StartOffset = I;
                    Current += QChar(C);
                } else {
                    if (Current.size() >= MinLen) {
                        QJsonObject Entry;
                        Entry[QStringLiteral("offset")] = StartOffset;
                        Entry[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(StartOffset, 16).toUpper();
                        Entry[QStringLiteral("string")] = Current;
                        Entry[QStringLiteral("length")] = Current.size();
                        Strings.append(Entry);
                    }
                    Current.clear();
                }
            }
            if (Current.size() >= MinLen && Strings.size() < MaxStrings) {
                QJsonObject Entry;
                Entry[QStringLiteral("offset")] = StartOffset;
                Entry[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(StartOffset, 16).toUpper();
                Entry[QStringLiteral("string")] = Current;
                Entry[QStringLiteral("length")] = Current.size();
                Strings.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Strings.size();
            Result[QStringLiteral("strings")] = Strings;
            if (Strings.size() >= MaxStrings)
                Result[QStringLiteral("truncated")] = true;
            return Result;
        });

    RegisterTool(QStringLiteral("extract_unicode_strings_from_file"),
        QStringLiteral("Extract UTF-16LE strings from a file with minimum length."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("min_length"), Schema::Integer(QStringLiteral("Minimum string length in characters (default 4)"), 1, 1000)}
        }, {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            int MinLen = A.value(QStringLiteral("min_length")).toInt(4);
            QJsonArray Strings;
            QString Current;
            int StartOffset = 0;
            constexpr int MaxStrings = 5000;
            for (int I = 0; I + 1 < Data.size() && Strings.size() < MaxStrings; I += 2) {
                uint16_t Wc = static_cast<uint8_t>(Data[I]) | (static_cast<uint8_t>(Data[I + 1]) << 8);
                if (Wc >= 0x20 && Wc <= 0x7E) {
                    if (Current.isEmpty()) StartOffset = I;
                    Current += QChar(Wc);
                } else {
                    if (Current.size() >= MinLen) {
                        QJsonObject Entry;
                        Entry[QStringLiteral("offset")] = StartOffset;
                        Entry[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(StartOffset, 16).toUpper();
                        Entry[QStringLiteral("string")] = Current;
                        Entry[QStringLiteral("length")] = Current.size();
                        Strings.append(Entry);
                    }
                    Current.clear();
                }
            }
            if (Current.size() >= MinLen && Strings.size() < MaxStrings) {
                QJsonObject Entry;
                Entry[QStringLiteral("offset")] = StartOffset;
                Entry[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(StartOffset, 16).toUpper();
                Entry[QStringLiteral("string")] = Current;
                Entry[QStringLiteral("length")] = Current.size();
                Strings.append(Entry);
            }
            QJsonObject Result;
            Result[QStringLiteral("count")] = Strings.size();
            Result[QStringLiteral("strings")] = Strings;
            if (Strings.size() >= MaxStrings)
                Result[QStringLiteral("truncated")] = true;
            return Result;
        });

    RegisterTool(QStringLiteral("patch_file"),
        QStringLiteral("Patch a file by writing hex bytes at a given offset."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("offset"), Schema::Integer(QStringLiteral("Byte offset to write at"), 0)},
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex-encoded bytes to write"))}
        }, {QStringLiteral("path"), QStringLiteral("offset"), QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            int Offset = A.value(QStringLiteral("offset")).toInt();
            QByteArray PatchData = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().toLatin1());
            if (PatchData.isEmpty())
                return Schema::Err(QStringLiteral("Invalid hex data"));
            QFile File(Path);
            if (!File.open(QIODevice::ReadWrite))
                return Schema::Err(QStringLiteral("Cannot open file for writing: ") + File.errorString());
            if (Offset + PatchData.size() > File.size()) {
                File.close();
                return Schema::Err(QStringLiteral("Patch extends beyond file end"));
            }
            File.seek(Offset);
            QByteArray OriginalBytes = File.read(PatchData.size());
            File.seek(Offset);
            File.write(PatchData);
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("offset")] = Offset;
            Result[QStringLiteral("bytes_written")] = PatchData.size();
            Result[QStringLiteral("original_bytes")] = QString::fromLatin1(OriginalBytes.toHex(' '));
            Result[QStringLiteral("new_bytes")] = QString::fromLatin1(PatchData.toHex(' '));
            return Result;
        });

    RegisterTool(QStringLiteral("create_file_backup"),
        QStringLiteral("Create a backup copy of a file (appends .bak extension)."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file to back up"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QString BackupPath = Path + QStringLiteral(".bak");
            if (QFile::exists(BackupPath))
                QFile::remove(BackupPath);
            if (!QFile::copy(Path, BackupPath))
                return Schema::Err(QStringLiteral("Failed to create backup"));
            QJsonObject Result;
            Result[QStringLiteral("success")] = true;
            Result[QStringLiteral("original")] = Path;
            Result[QStringLiteral("backup")] = BackupPath;
            Result[QStringLiteral("size")] = QFileInfo(BackupPath).size();
            return Result;
        });

    RegisterTool(QStringLiteral("compare_files"),
        QStringLiteral("Compare two files byte by byte and return differences."),
        Schema::Build({
            {QStringLiteral("path1"), Schema::String(QStringLiteral("Path to first file"))},
            {QStringLiteral("path2"), Schema::String(QStringLiteral("Path to second file"))},
            {QStringLiteral("max_diffs"), Schema::Integer(QStringLiteral("Maximum number of differences to return (default 100)"), 1, 10000)}
        }, {QStringLiteral("path1"), QStringLiteral("path2")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path1 = A.value(QStringLiteral("path1")).toString();
            QString Path2 = A.value(QStringLiteral("path2")).toString();
            int MaxDiffs = A.value(QStringLiteral("max_diffs")).toInt(100);
            QFile File1(Path1);
            QFile File2(Path2);
            if (!File1.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file1: ") + File1.errorString());
            if (!File2.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file2: ") + File2.errorString());
            QByteArray Data1 = File1.readAll();
            QByteArray Data2 = File2.readAll();
            File1.close();
            File2.close();
            QJsonArray Diffs;
            int CompareLen = std::min(static_cast<int>(Data1.size()), static_cast<int>(Data2.size()));
            for (int I = 0; I < CompareLen && Diffs.size() < MaxDiffs; ++I) {
                if (Data1[I] != Data2[I]) {
                    QJsonObject Diff;
                    Diff[QStringLiteral("offset")] = I;
                    Diff[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(I, 16).toUpper();
                    Diff[QStringLiteral("file1")] = QString::number(static_cast<uint8_t>(Data1[I]), 16).rightJustified(2, '0').toUpper();
                    Diff[QStringLiteral("file2")] = QString::number(static_cast<uint8_t>(Data2[I]), 16).rightJustified(2, '0').toUpper();
                    Diffs.append(Diff);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("file1_size")] = Data1.size();
            Result[QStringLiteral("file2_size")] = Data2.size();
            Result[QStringLiteral("identical")] = (Data1 == Data2);
            Result[QStringLiteral("differences_found")] = Diffs.size();
            Result[QStringLiteral("differences")] = Diffs;
            if (Data1.size() != Data2.size())
                Result[QStringLiteral("size_mismatch")] = true;
            if (Diffs.size() >= MaxDiffs)
                Result[QStringLiteral("truncated")] = true;
            return Result;
        });

    RegisterTool(QStringLiteral("get_file_entropy"),
        QStringLiteral("Calculate Shannon entropy of an entire file (0-8 scale)."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("size")] = Data.size();
            Result[QStringLiteral("entropy")] = CalcEntropy(Data.constData(), Data.size());
            QString Assessment;
            double E = CalcEntropy(Data.constData(), Data.size());
            if (E < 1.0) Assessment = QStringLiteral("Very low (mostly uniform data)");
            else if (E < 3.0) Assessment = QStringLiteral("Low (text or structured data)");
            else if (E < 5.0) Assessment = QStringLiteral("Medium (mixed content)");
            else if (E < 7.0) Assessment = QStringLiteral("High (compiled code or compressed regions)");
            else Assessment = QStringLiteral("Very high (encrypted or compressed)");
            Result[QStringLiteral("assessment")] = Assessment;
            return Result;
        });

    RegisterTool(QStringLiteral("get_file_entropy_map"),
        QStringLiteral("Calculate entropy per block across the file. Returns array of {offset, entropy}."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("block_size"), Schema::Integer(QStringLiteral("Block size in bytes (default 256)"), 16, 65536)}
        }, {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            int BlockSize = A.value(QStringLiteral("block_size")).toInt(256);
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QJsonArray Blocks;
            for (int Offset = 0; Offset < Data.size(); Offset += BlockSize) {
                int ThisSize = std::min(BlockSize, static_cast<int>(Data.size()) - Offset);
                double E = CalcEntropy(Data.constData() + Offset, ThisSize);
                QJsonObject Block;
                Block[QStringLiteral("offset")] = Offset;
                Block[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(Offset, 16).toUpper();
                Block[QStringLiteral("entropy")] = static_cast<int>(E * 1000.0) / 1000.0;
                Blocks.append(Block);
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("file_size")] = Data.size();
            Result[QStringLiteral("block_size")] = BlockSize;
            Result[QStringLiteral("block_count")] = Blocks.size();
            Result[QStringLiteral("blocks")] = Blocks;
            return Result;
        });

    RegisterTool(QStringLiteral("detect_file_type"),
        QStringLiteral("Detect file type by inspecting magic bytes at the beginning of the file."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Header = File.read(16);
            File.close();
            if (Header.isEmpty())
                return Schema::Err(QStringLiteral("File is empty"));
            QString Type = QStringLiteral("Unknown");
            QString Magic = QString::fromLatin1(Header.left(8).toHex());
            if (Header.size() >= 2 && static_cast<uint8_t>(Header[0]) == 0x4D && static_cast<uint8_t>(Header[1]) == 0x5A) Type = QStringLiteral("PE Executable (MZ)");
            else if (Header.size() >= 4 && static_cast<uint8_t>(Header[0]) == 0x7F && Header[1] == 'E' && Header[2] == 'L' && Header[3] == 'F') Type = QStringLiteral("ELF Executable");
            else if (Header.size() >= 4 && static_cast<uint8_t>(Header[0]) == 0xCF && static_cast<uint8_t>(Header[1]) == 0xFA && static_cast<uint8_t>(Header[2]) == 0xED && static_cast<uint8_t>(Header[3]) == 0xFE) Type = QStringLiteral("Mach-O 64-bit");
            else if (Header.size() >= 4 && static_cast<uint8_t>(Header[0]) == 0xCE && static_cast<uint8_t>(Header[1]) == 0xFA && static_cast<uint8_t>(Header[2]) == 0xED && static_cast<uint8_t>(Header[3]) == 0xFE) Type = QStringLiteral("Mach-O 32-bit");
            else if (Header.size() >= 4 && static_cast<uint8_t>(Header[0]) == 0xCA && static_cast<uint8_t>(Header[1]) == 0xFE && static_cast<uint8_t>(Header[2]) == 0xBA && static_cast<uint8_t>(Header[3]) == 0xBE) Type = QStringLiteral("Mach-O Universal / Java Class");
            else if (Header.size() >= 4 && Header[0] == 'P' && Header[1] == 'K' && Header[2] == '\x03' && Header[3] == '\x04') Type = QStringLiteral("ZIP Archive");
            else if (Header.size() >= 2 && static_cast<uint8_t>(Header[0]) == 0x1F && static_cast<uint8_t>(Header[1]) == 0x8B) Type = QStringLiteral("GZIP Compressed");
            else if (Header.size() >= 6 && static_cast<uint8_t>(Header[0]) == 0xFD && Header[1] == '7' && Header[2] == 'z' && Header[3] == 'X' && Header[4] == 'Z' && Header[5] == '\0') Type = QStringLiteral("XZ Compressed");
            else if (Header.size() >= 3 && Header[0] == 'B' && Header[1] == 'Z' && Header[2] == 'h') Type = QStringLiteral("BZIP2 Compressed");
            else if (Header.size() >= 4 && Header[0] == 'R' && Header[1] == 'a' && Header[2] == 'r' && Header[3] == '!') Type = QStringLiteral("RAR Archive");
            else if (Header.size() >= 6 && Header[0] == '7' && Header[1] == 'z' && static_cast<uint8_t>(Header[2]) == 0xBC && static_cast<uint8_t>(Header[3]) == 0xAF && static_cast<uint8_t>(Header[4]) == 0x27 && static_cast<uint8_t>(Header[5]) == 0x1C) Type = QStringLiteral("7z Archive");
            else if (Header.size() >= 8 && static_cast<uint8_t>(Header[0]) == 0x89 && Header[1] == 'P' && Header[2] == 'N' && Header[3] == 'G' && Header[4] == '\r' && Header[5] == '\n' && Header[6] == '\x1a' && Header[7] == '\n') Type = QStringLiteral("PNG Image");
            else if (Header.size() >= 2 && static_cast<uint8_t>(Header[0]) == 0xFF && static_cast<uint8_t>(Header[1]) == 0xD8) Type = QStringLiteral("JPEG Image");
            else if (Header.size() >= 6 && Header[0] == 'G' && Header[1] == 'I' && Header[2] == 'F' && Header[3] == '8') Type = QStringLiteral("GIF Image");
            else if (Header.size() >= 4 && Header[0] == 'R' && Header[1] == 'I' && Header[2] == 'F' && Header[3] == 'F') Type = QStringLiteral("RIFF (WAV/AVI/WebP)");
            else if (Header.size() >= 4 && Header[0] == '%' && Header[1] == 'P' && Header[2] == 'D' && Header[3] == 'F') Type = QStringLiteral("PDF Document");
            else if (Header.size() >= 8 && Header[0] == '\xD0' && static_cast<uint8_t>(Header[1]) == 0xCF && Header[2] == '\x11' && static_cast<uint8_t>(Header[3]) == 0xE0) Type = QStringLiteral("OLE2 (MS Office legacy)");
            else if (Header.size() >= 4 && Header[0] == 'O' && Header[1] == 'g' && Header[2] == 'g' && Header[3] == 'S') Type = QStringLiteral("OGG Container");
            else if (Header.size() >= 4 && Header[0] == 'f' && Header[1] == 'L' && Header[2] == 'a' && Header[3] == 'C') Type = QStringLiteral("FLAC Audio");
            else if (Header.size() >= 3 && static_cast<uint8_t>(Header[0]) == 0xFF && (static_cast<uint8_t>(Header[1]) & 0xE0) == 0xE0) Type = QStringLiteral("MP3 Audio");
            else if (Header.size() >= 4 && Header[0] == 'd' && Header[1] == 'e' && Header[2] == 'x' && Header[3] == '\n') Type = QStringLiteral("Android DEX");
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("type")] = Type;
            Result[QStringLiteral("magic_bytes")] = Magic;
            return Result;
        });

    RegisterTool(QStringLiteral("hex_dump_file"),
        QStringLiteral("Read bytes from file and format as hex dump with offset, hex, and ASCII columns."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("offset"), Schema::Integer(QStringLiteral("Start offset (default 0)"), 0)},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to dump (default 256)"), 1, 65536)}
        }, {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            int Offset = A.value(QStringLiteral("offset")).toInt(0);
            int Size = A.value(QStringLiteral("size")).toInt(256);
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            File.seek(Offset);
            QByteArray Data = File.read(Size);
            File.close();
            if (Data.isEmpty())
                return Schema::Err(QStringLiteral("No data at specified offset"));
            QString Dump;
            int BytesPerLine = 16;
            for (int I = 0; I < Data.size(); I += BytesPerLine) {
                QString OffsetStr = QString::number(Offset + I, 16).rightJustified(8, '0').toUpper();
                QString HexPart;
                QString AscPart;
                for (int J = 0; J < BytesPerLine; ++J) {
                    if (I + J < Data.size()) {
                        uint8_t B = static_cast<uint8_t>(Data[I + J]);
                        HexPart += QString::number(B, 16).rightJustified(2, '0').toUpper() + QStringLiteral(" ");
                        AscPart += (B >= 0x20 && B <= 0x7E) ? QChar(B) : QChar('.');
                    } else {
                        HexPart += QStringLiteral("   ");
                        AscPart += QChar(' ');
                    }
                    if (J == 7) HexPart += QChar(' ');
                }
                Dump += OffsetStr + QStringLiteral("  ") + HexPart + QStringLiteral(" |") + AscPart + QStringLiteral("|\n");
            }
            QJsonObject Result;
            Result[QStringLiteral("offset")] = Offset;
            Result[QStringLiteral("size")] = Data.size();
            Result[QStringLiteral("dump")] = Dump;
            return Result;
        });

    RegisterTool(QStringLiteral("read_file_bytes"),
        QStringLiteral("Read N bytes from file at offset and return as hex string."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("offset"), Schema::Integer(QStringLiteral("Start offset"), 0)},
            {QStringLiteral("size"), Schema::Integer(QStringLiteral("Number of bytes to read"), 1, 1048576)}
        }, {QStringLiteral("path"), QStringLiteral("offset"), QStringLiteral("size")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            int Offset = A.value(QStringLiteral("offset")).toInt();
            int Size = A.value(QStringLiteral("size")).toInt();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            File.seek(Offset);
            QByteArray Data = File.read(Size);
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("offset")] = Offset;
            Result[QStringLiteral("size")] = Data.size();
            Result[QStringLiteral("hex")] = QString::fromLatin1(Data.toHex(' '));
            Result[QStringLiteral("raw_hex")] = QString::fromLatin1(Data.toHex());
            return Result;
        });

    RegisterTool(QStringLiteral("write_file_bytes"),
        QStringLiteral("Write hex-encoded bytes to a file at the specified offset."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("offset"), Schema::Integer(QStringLiteral("Byte offset to write at"), 0)},
            {QStringLiteral("hex_data"), Schema::String(QStringLiteral("Hex-encoded bytes to write"))}
        }, {QStringLiteral("path"), QStringLiteral("offset"), QStringLiteral("hex_data")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            int Offset = A.value(QStringLiteral("offset")).toInt();
            QByteArray WriteData = QByteArray::fromHex(A.value(QStringLiteral("hex_data")).toString().toLatin1());
            if (WriteData.isEmpty())
                return Schema::Err(QStringLiteral("Invalid hex data"));
            QFile File(Path);
            if (!File.open(QIODevice::ReadWrite))
                return Schema::Err(QStringLiteral("Cannot open file for writing: ") + File.errorString());
            File.seek(Offset);
            qint64 Written = File.write(WriteData);
            File.close();
            QJsonObject Result;
            Result[QStringLiteral("success")] = (Written == WriteData.size());
            Result[QStringLiteral("bytes_written")] = static_cast<int>(Written);
            Result[QStringLiteral("offset")] = Offset;
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_sections_from_file"),
        QStringLiteral("Parse PE section headers from file. Returns section names, addresses, sizes, and characteristics."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to PE file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            if (Data.size() < 64)
                return Schema::Err(QStringLiteral("File too small"));
            uint16_t DosMagic = *reinterpret_cast<const uint16_t*>(Data.constData());
            if (DosMagic != 0x5A4D)
                return Schema::Err(QStringLiteral("Not a PE file"));
            uint32_t PeOffset = *reinterpret_cast<const uint32_t*>(Data.constData() + 0x3C);
            if (static_cast<int>(PeOffset + 24) > Data.size())
                return Schema::Err(QStringLiteral("Invalid PE offset"));
            uint32_t PeSig = *reinterpret_cast<const uint32_t*>(Data.constData() + PeOffset);
            if (PeSig != 0x00004550)
                return Schema::Err(QStringLiteral("Invalid PE signature"));
            uint16_t NumSections = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 6);
            uint16_t OptHeaderSize = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 20);
            int SectionTableOffset = static_cast<int>(PeOffset) + 24 + OptHeaderSize;
            QJsonArray Sections;
            for (int I = 0; I < NumSections; ++I) {
                int EntryOffset = SectionTableOffset + I * 40;
                if (EntryOffset + 40 > Data.size()) break;
                const uint8_t* Sec = reinterpret_cast<const uint8_t*>(Data.constData() + EntryOffset);
                char NameBuf[9] = {};
                std::memcpy(NameBuf, Sec, 8);
                QJsonObject SecObj;
                SecObj[QStringLiteral("name")] = QString::fromUtf8(NameBuf);
                SecObj[QStringLiteral("virtual_size")] = static_cast<int>(*reinterpret_cast<const uint32_t*>(Sec + 8));
                SecObj[QStringLiteral("virtual_address")] = QStringLiteral("0x") + QString::number(*reinterpret_cast<const uint32_t*>(Sec + 12), 16).toUpper();
                SecObj[QStringLiteral("raw_size")] = static_cast<int>(*reinterpret_cast<const uint32_t*>(Sec + 16));
                SecObj[QStringLiteral("raw_offset")] = QStringLiteral("0x") + QString::number(*reinterpret_cast<const uint32_t*>(Sec + 20), 16).toUpper();
                uint32_t Chars = *reinterpret_cast<const uint32_t*>(Sec + 36);
                SecObj[QStringLiteral("characteristics")] = QStringLiteral("0x") + QString::number(Chars, 16).toUpper();
                QString Flags;
                if (Chars & 0x00000020) Flags += QStringLiteral("CODE ");
                if (Chars & 0x00000040) Flags += QStringLiteral("INITIALIZED ");
                if (Chars & 0x00000080) Flags += QStringLiteral("UNINITIALIZED ");
                if (Chars & 0x20000000) Flags += QStringLiteral("EXECUTE ");
                if (Chars & 0x40000000) Flags += QStringLiteral("READ ");
                if (Chars & 0x80000000) Flags += QStringLiteral("WRITE ");
                SecObj[QStringLiteral("flags")] = Flags.trimmed();
                int SecRawOff = static_cast<int>(*reinterpret_cast<const uint32_t*>(Sec + 20));
                int SecRawSz = static_cast<int>(*reinterpret_cast<const uint32_t*>(Sec + 16));
                if (SecRawOff > 0 && SecRawSz > 0 && SecRawOff + SecRawSz <= Data.size()) {
                    SecObj[QStringLiteral("entropy")] = static_cast<int>(CalcEntropy(Data.constData() + SecRawOff, SecRawSz) * 1000.0) / 1000.0;
                }
                Sections.append(SecObj);
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("section_count")] = NumSections;
            Result[QStringLiteral("sections")] = Sections;
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_imports_from_file"),
        QStringLiteral("Parse PE import table from file. Returns list of imported DLLs and their functions."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to PE file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            if (Data.size() < 64)
                return Schema::Err(QStringLiteral("File too small"));
            if (*reinterpret_cast<const uint16_t*>(Data.constData()) != 0x5A4D)
                return Schema::Err(QStringLiteral("Not a PE file"));
            uint32_t PeOffset = *reinterpret_cast<const uint32_t*>(Data.constData() + 0x3C);
            if (static_cast<int>(PeOffset + 24) > Data.size())
                return Schema::Err(QStringLiteral("Invalid PE"));
            if (*reinterpret_cast<const uint32_t*>(Data.constData() + PeOffset) != 0x00004550)
                return Schema::Err(QStringLiteral("Invalid PE signature"));
            uint16_t Machine = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 4);
            bool Is64 = (Machine == 0x8664);
            uint16_t NumSections = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 6);
            uint16_t OptHeaderSize = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 20);
            int OptBase = static_cast<int>(PeOffset) + 24;
            uint32_t ImportRva = 0;
            if (Is64 && OptBase + 120 <= Data.size()) {
                ImportRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 112);
            } else if (!Is64 && OptBase + 104 <= Data.size()) {
                ImportRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 96);
            }
            if (ImportRva == 0) {
                QJsonObject R;
                R[QStringLiteral("imports")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                return R;
            }
            int SectionTableOffset = OptBase + OptHeaderSize;
            auto RvaToFile = [&](uint32_t Rva) -> int {
                for (int I = 0; I < NumSections; ++I) {
                    int So = SectionTableOffset + I * 40;
                    if (So + 40 > Data.size()) return -1;
                    uint32_t Va = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 12);
                    uint32_t Vs = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 8);
                    uint32_t RawOff = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 20);
                    if (Rva >= Va && Rva < Va + Vs)
                        return static_cast<int>(RawOff + (Rva - Va));
                }
                return -1;
            };
            int ImportFileOff = RvaToFile(ImportRva);
            if (ImportFileOff < 0 || ImportFileOff + 20 > Data.size()) {
                QJsonObject R;
                R[QStringLiteral("imports")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                R[QStringLiteral("note")] = QStringLiteral("Import directory RVA could not be resolved");
                return R;
            }
            QJsonArray Imports;
            for (int Idx = 0; Idx < 256; ++Idx) {
                int DescOff = ImportFileOff + Idx * 20;
                if (DescOff + 20 > Data.size()) break;
                uint32_t NameRva = *reinterpret_cast<const uint32_t*>(Data.constData() + DescOff + 12);
                uint32_t ThunkRva = *reinterpret_cast<const uint32_t*>(Data.constData() + DescOff);
                if (ThunkRva == 0 && NameRva == 0) break;
                if (NameRva == 0) break;
                int NameOff = RvaToFile(NameRva);
                QString DllName;
                if (NameOff >= 0 && NameOff < Data.size()) {
                    int End = NameOff;
                    while (End < Data.size() && Data[End] != '\0') ++End;
                    DllName = QString::fromLatin1(Data.constData() + NameOff, End - NameOff);
                }
                QJsonObject ImportEntry;
                ImportEntry[QStringLiteral("dll")] = DllName;
                QJsonArray Functions;
                if (ThunkRva != 0) {
                    int ThunkOff = RvaToFile(ThunkRva);
                    int EntrySize = Is64 ? 8 : 4;
                    if (ThunkOff >= 0) {
                        for (int J = 0; J < 1024; ++J) {
                            int Pos = ThunkOff + J * EntrySize;
                            if (Pos + EntrySize > Data.size()) break;
                            uint64_t ThunkData = 0;
                            std::memcpy(&ThunkData, Data.constData() + Pos, EntrySize);
                            if (ThunkData == 0) break;
                            bool IsOrdinal = Is64 ? (ThunkData & 0x8000000000000000ULL) != 0
                                                  : (ThunkData & 0x80000000UL) != 0;
                            if (IsOrdinal) {
                                Functions.append(QStringLiteral("Ordinal#") + QString::number(ThunkData & 0xFFFF));
                            } else {
                                uint32_t HintNameRva = static_cast<uint32_t>(ThunkData & 0x7FFFFFFF);
                                int FuncNameOff = RvaToFile(HintNameRva);
                                if (FuncNameOff >= 0 && FuncNameOff + 2 < Data.size()) {
                                    int FnStart = FuncNameOff + 2;
                                    int FnEnd = FnStart;
                                    while (FnEnd < Data.size() && Data[FnEnd] != '\0' && (FnEnd - FnStart) < 255) ++FnEnd;
                                    Functions.append(QString::fromLatin1(Data.constData() + FnStart, FnEnd - FnStart));
                                }
                            }
                        }
                    }
                }
                ImportEntry[QStringLiteral("functions")] = Functions;
                ImportEntry[QStringLiteral("function_count")] = Functions.size();
                Imports.append(ImportEntry);
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("count")] = Imports.size();
            Result[QStringLiteral("imports")] = Imports;
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_exports_from_file"),
        QStringLiteral("Parse PE export table from file. Returns exported function names, ordinals, and RVAs."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to PE file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            if (Data.size() < 64 || *reinterpret_cast<const uint16_t*>(Data.constData()) != 0x5A4D)
                return Schema::Err(QStringLiteral("Not a PE file"));
            uint32_t PeOffset = *reinterpret_cast<const uint32_t*>(Data.constData() + 0x3C);
            if (static_cast<int>(PeOffset + 24) > Data.size() || *reinterpret_cast<const uint32_t*>(Data.constData() + PeOffset) != 0x00004550)
                return Schema::Err(QStringLiteral("Invalid PE"));
            uint16_t Machine = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 4);
            bool Is64 = (Machine == 0x8664);
            uint16_t NumSections = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 6);
            uint16_t OptHeaderSize = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 20);
            int OptBase = static_cast<int>(PeOffset) + 24;
            int SectionTableOffset = OptBase + OptHeaderSize;
            uint32_t ExportRva = 0;
            if (Is64 && OptBase + 100 <= Data.size())
                ExportRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 96);
            else if (!Is64 && OptBase + 84 <= Data.size())
                ExportRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 80);
            if (ExportRva == 0) {
                QJsonObject R;
                R[QStringLiteral("exports")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                return R;
            }
            auto RvaToFile = [&](uint32_t Rva) -> int {
                for (int I = 0; I < NumSections; ++I) {
                    int So = SectionTableOffset + I * 40;
                    if (So + 40 > Data.size()) return -1;
                    uint32_t Va = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 12);
                    uint32_t Vs = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 8);
                    uint32_t RawOff = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 20);
                    if (Rva >= Va && Rva < Va + Vs)
                        return static_cast<int>(RawOff + (Rva - Va));
                }
                return -1;
            };
            int ExportOff = RvaToFile(ExportRva);
            if (ExportOff < 0 || ExportOff + 40 > Data.size()) {
                QJsonObject R;
                R[QStringLiteral("exports")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                return R;
            }
            const uint8_t* Ed = reinterpret_cast<const uint8_t*>(Data.constData() + ExportOff);
            uint32_t NumFunctions = *reinterpret_cast<const uint32_t*>(Ed + 20);
            uint32_t NumNames = *reinterpret_cast<const uint32_t*>(Ed + 24);
            uint32_t AddrFuncsRva = *reinterpret_cast<const uint32_t*>(Ed + 28);
            uint32_t AddrNamesRva = *reinterpret_cast<const uint32_t*>(Ed + 32);
            uint32_t AddrOrdsRva = *reinterpret_cast<const uint32_t*>(Ed + 36);
            uint32_t OrdBase = *reinterpret_cast<const uint32_t*>(Ed + 16);
            if (NumNames > 10000) NumNames = 10000;
            if (NumFunctions > 10000) NumFunctions = 10000;
            int NamesOff = RvaToFile(AddrNamesRva);
            int OrdsOff = RvaToFile(AddrOrdsRva);
            int FuncsOff = RvaToFile(AddrFuncsRva);
            QJsonArray Exports;
            if (NamesOff >= 0 && OrdsOff >= 0 && FuncsOff >= 0) {
                for (uint32_t I = 0; I < NumNames; ++I) {
                    int NameRvaOff = NamesOff + static_cast<int>(I) * 4;
                    int OrdOff = OrdsOff + static_cast<int>(I) * 2;
                    if (NameRvaOff + 4 > Data.size() || OrdOff + 2 > Data.size()) break;
                    uint32_t NameRva = *reinterpret_cast<const uint32_t*>(Data.constData() + NameRvaOff);
                    uint16_t OrdIdx = *reinterpret_cast<const uint16_t*>(Data.constData() + OrdOff);
                    int NameFileOff = RvaToFile(NameRva);
                    QString FuncName;
                    if (NameFileOff >= 0) {
                        int End = NameFileOff;
                        while (End < Data.size() && Data[End] != '\0' && (End - NameFileOff) < 255) ++End;
                        FuncName = QString::fromLatin1(Data.constData() + NameFileOff, End - NameFileOff);
                    }
                    uint32_t FuncRva = 0;
                    int FuncRvaOff = FuncsOff + static_cast<int>(OrdIdx) * 4;
                    if (FuncRvaOff + 4 <= Data.size())
                        FuncRva = *reinterpret_cast<const uint32_t*>(Data.constData() + FuncRvaOff);
                    QJsonObject Entry;
                    Entry[QStringLiteral("name")] = FuncName;
                    Entry[QStringLiteral("ordinal")] = static_cast<int>(OrdIdx + OrdBase);
                    Entry[QStringLiteral("rva")] = QStringLiteral("0x") + QString::number(FuncRva, 16).toUpper();
                    Exports.append(Entry);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("count")] = Exports.size();
            Result[QStringLiteral("exports")] = Exports;
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_resources_from_file"),
        QStringLiteral("Parse PE resource directory from file. Returns resource types and entries."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to PE file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            if (Data.size() < 64 || *reinterpret_cast<const uint16_t*>(Data.constData()) != 0x5A4D)
                return Schema::Err(QStringLiteral("Not a PE file"));
            uint32_t PeOffset = *reinterpret_cast<const uint32_t*>(Data.constData() + 0x3C);
            if (static_cast<int>(PeOffset + 24) > Data.size() || *reinterpret_cast<const uint32_t*>(Data.constData() + PeOffset) != 0x00004550)
                return Schema::Err(QStringLiteral("Invalid PE"));
            uint16_t Machine = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 4);
            bool Is64 = (Machine == 0x8664);
            int OptBase = static_cast<int>(PeOffset) + 24;
            uint32_t ResourceRva = 0;
            uint32_t ResourceSize = 0;
            if (Is64 && OptBase + 136 <= Data.size()) {
                ResourceRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 112 + 16);
                ResourceSize = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 112 + 20);
            } else if (!Is64 && OptBase + 120 <= Data.size()) {
                ResourceRva = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 96 + 16);
                ResourceSize = *reinterpret_cast<const uint32_t*>(Data.constData() + OptBase + 96 + 20);
            }
            if (ResourceRva == 0) {
                QJsonObject R;
                R[QStringLiteral("resources")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                return R;
            }
            uint16_t NumSections = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 6);
            uint16_t OptHeaderSize = *reinterpret_cast<const uint16_t*>(Data.constData() + PeOffset + 20);
            int SectionTableOffset = OptBase + OptHeaderSize;
            auto RvaToFile = [&](uint32_t Rva) -> int {
                for (int I = 0; I < NumSections; ++I) {
                    int So = SectionTableOffset + I * 40;
                    if (So + 40 > Data.size()) return -1;
                    uint32_t Va = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 12);
                    uint32_t Vs = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 8);
                    uint32_t RawOff = *reinterpret_cast<const uint32_t*>(Data.constData() + So + 20);
                    if (Rva >= Va && Rva < Va + Vs)
                        return static_cast<int>(RawOff + (Rva - Va));
                }
                return -1;
            };
            int ResOff = RvaToFile(ResourceRva);
            if (ResOff < 0 || ResOff + 16 > Data.size()) {
                QJsonObject R;
                R[QStringLiteral("resources")] = QJsonArray();
                R[QStringLiteral("count")] = 0;
                return R;
            }
            auto TypeName = [](uint32_t Id) -> QString {
                switch (Id) {
                case 1: return QStringLiteral("RT_CURSOR");
                case 2: return QStringLiteral("RT_BITMAP");
                case 3: return QStringLiteral("RT_ICON");
                case 4: return QStringLiteral("RT_MENU");
                case 5: return QStringLiteral("RT_DIALOG");
                case 6: return QStringLiteral("RT_STRING");
                case 7: return QStringLiteral("RT_FONTDIR");
                case 8: return QStringLiteral("RT_FONT");
                case 9: return QStringLiteral("RT_ACCELERATOR");
                case 10: return QStringLiteral("RT_RCDATA");
                case 11: return QStringLiteral("RT_MESSAGETABLE");
                case 12: return QStringLiteral("RT_GROUP_CURSOR");
                case 14: return QStringLiteral("RT_GROUP_ICON");
                case 16: return QStringLiteral("RT_VERSION");
                case 24: return QStringLiteral("RT_MANIFEST");
                default: return QStringLiteral("RT_") + QString::number(Id);
                }
            };
            uint16_t NumNamed = *reinterpret_cast<const uint16_t*>(Data.constData() + ResOff + 12);
            uint16_t NumId = *reinterpret_cast<const uint16_t*>(Data.constData() + ResOff + 14);
            int TotalEntries = NumNamed + NumId;
            QJsonArray Resources;
            for (int I = 0; I < TotalEntries && I < 64; ++I) {
                int EntryOff = ResOff + 16 + I * 8;
                if (EntryOff + 8 > Data.size()) break;
                uint32_t NameOrId = *reinterpret_cast<const uint32_t*>(Data.constData() + EntryOff);
                uint32_t OffsetOrData = *reinterpret_cast<const uint32_t*>(Data.constData() + EntryOff + 4);
                QJsonObject ResEntry;
                bool IsNamed = (NameOrId & 0x80000000) != 0;
                if (IsNamed) {
                    ResEntry[QStringLiteral("type")] = QStringLiteral("Named");
                } else {
                    ResEntry[QStringLiteral("type_id")] = static_cast<int>(NameOrId);
                    ResEntry[QStringLiteral("type")] = TypeName(NameOrId);
                }
                bool IsDir = (OffsetOrData & 0x80000000) != 0;
                ResEntry[QStringLiteral("is_directory")] = IsDir;
                if (IsDir) {
                    int SubDirOff = ResOff + static_cast<int>(OffsetOrData & 0x7FFFFFFF);
                    if (SubDirOff + 16 <= Data.size()) {
                        uint16_t SubNamed = *reinterpret_cast<const uint16_t*>(Data.constData() + SubDirOff + 12);
                        uint16_t SubId = *reinterpret_cast<const uint16_t*>(Data.constData() + SubDirOff + 14);
                        ResEntry[QStringLiteral("entries")] = SubNamed + SubId;
                    }
                }
                Resources.append(ResEntry);
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("resource_rva")] = QStringLiteral("0x") + QString::number(ResourceRva, 16).toUpper();
            Result[QStringLiteral("resource_size")] = static_cast<int>(ResourceSize);
            Result[QStringLiteral("count")] = Resources.size();
            Result[QStringLiteral("resources")] = Resources;
            return Result;
        });

    RegisterTool(QStringLiteral("get_pe_version_info"),
        QStringLiteral("Parse VS_VERSION_INFO from PE resources. Returns file version, product version, company name, description."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to PE file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QByteArray Marker("VS_VERSION_INFO", 15);
            QByteArray MarkerW;
            for (int I = 0; I < Marker.size(); ++I) {
                MarkerW.append(Marker[I]);
                MarkerW.append('\0');
            }
            int Pos = Data.indexOf(MarkerW);
            if (Pos < 0)
                return Schema::Err(QStringLiteral("No VS_VERSION_INFO found"));
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            int FixedInfoOff = Pos + MarkerW.size();
            while (FixedInfoOff < Data.size() - 1 && (FixedInfoOff % 4) != 0) ++FixedInfoOff;
            while (FixedInfoOff < Data.size() - 4) {
                uint32_t Sig = *reinterpret_cast<const uint32_t*>(Data.constData() + FixedInfoOff);
                if (Sig == 0xFEEF04BD) break;
                ++FixedInfoOff;
            }
            if (FixedInfoOff + 52 <= Data.size()) {
                uint32_t Sig = *reinterpret_cast<const uint32_t*>(Data.constData() + FixedInfoOff);
                if (Sig == 0xFEEF04BD) {
                    uint16_t FvMs = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 10);
                    uint16_t FvLs = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 8);
                    uint16_t FvMs2 = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 14);
                    uint16_t FvLs2 = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 12);
                    Result[QStringLiteral("file_version")] = QString::number(FvMs) + QStringLiteral(".") + QString::number(FvLs) + QStringLiteral(".") + QString::number(FvMs2) + QStringLiteral(".") + QString::number(FvLs2);
                    uint16_t PvMs = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 18);
                    uint16_t PvLs = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 16);
                    uint16_t PvMs2 = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 22);
                    uint16_t PvLs2 = *reinterpret_cast<const uint16_t*>(Data.constData() + FixedInfoOff + 20);
                    Result[QStringLiteral("product_version")] = QString::number(PvMs) + QStringLiteral(".") + QString::number(PvLs) + QStringLiteral(".") + QString::number(PvMs2) + QStringLiteral(".") + QString::number(PvLs2);
                }
            }
            auto FindStringValue = [&](const char* Key) -> QString {
                QByteArray KeyW;
                int KeyLen = static_cast<int>(strlen(Key));
                for (int I = 0; I < KeyLen; ++I) {
                    KeyW.append(Key[I]);
                    KeyW.append('\0');
                }
                int Idx = Data.indexOf(KeyW, Pos);
                if (Idx < 0) return QString();
                int ValStart = Idx + KeyW.size();
                while (ValStart < Data.size() - 1 && Data[ValStart] == '\0' && Data[ValStart + 1] == '\0') ValStart += 2;
                if (ValStart >= Data.size() - 1) return QString();
                QString Val;
                for (int J = ValStart; J + 1 < Data.size(); J += 2) {
                    uint16_t Ch = static_cast<uint8_t>(Data[J]) | (static_cast<uint8_t>(Data[J + 1]) << 8);
                    if (Ch == 0) break;
                    Val += QChar(Ch);
                }
                return Val;
            };
            QString CompanyName = FindStringValue("CompanyName");
            QString FileDescription = FindStringValue("FileDescription");
            QString FileVersion = FindStringValue("FileVersion");
            QString InternalName = FindStringValue("InternalName");
            QString OriginalFilename = FindStringValue("OriginalFilename");
            QString ProductName = FindStringValue("ProductName");
            QString ProductVersion = FindStringValue("ProductVersion");
            QString LegalCopyright = FindStringValue("LegalCopyright");
            if (!CompanyName.isEmpty()) Result[QStringLiteral("company_name")] = CompanyName;
            if (!FileDescription.isEmpty()) Result[QStringLiteral("file_description")] = FileDescription;
            if (!FileVersion.isEmpty()) Result[QStringLiteral("file_version_string")] = FileVersion;
            if (!InternalName.isEmpty()) Result[QStringLiteral("internal_name")] = InternalName;
            if (!OriginalFilename.isEmpty()) Result[QStringLiteral("original_filename")] = OriginalFilename;
            if (!ProductName.isEmpty()) Result[QStringLiteral("product_name")] = ProductName;
            if (!ProductVersion.isEmpty()) Result[QStringLiteral("product_version_string")] = ProductVersion;
            if (!LegalCopyright.isEmpty()) Result[QStringLiteral("legal_copyright")] = LegalCopyright;
            return Result;
        });

    RegisterTool(QStringLiteral("get_elf_info"),
        QStringLiteral("Parse ELF header: class (32/64), endianness, type, machine, entry point, program/section header counts."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to ELF file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.read(256);
            File.close();
            if (Data.size() < 64)
                return Schema::Err(QStringLiteral("File too small for ELF"));
            if (Data.size() < 4 || static_cast<uint8_t>(Data[0]) != 0x7F || Data[1] != 'E' || Data[2] != 'L' || Data[3] != 'F')
                return Schema::Err(QStringLiteral("Not an ELF file"));
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            uint8_t EiClass = static_cast<uint8_t>(Data[4]);
            Result[QStringLiteral("class")] = (EiClass == 1) ? QStringLiteral("ELF32") : QStringLiteral("ELF64");
            uint8_t EiData = static_cast<uint8_t>(Data[5]);
            Result[QStringLiteral("endianness")] = (EiData == 1) ? QStringLiteral("Little Endian") : QStringLiteral("Big Endian");
            uint8_t EiOsabi = static_cast<uint8_t>(Data[7]);
            if (EiOsabi == 0) Result[QStringLiteral("osabi")] = QStringLiteral("ELFOSABI_NONE/SYSV");
            else if (EiOsabi == 3) Result[QStringLiteral("osabi")] = QStringLiteral("ELFOSABI_LINUX");
            else Result[QStringLiteral("osabi")] = QString::number(EiOsabi);
            if (EiClass == 2) {
                uint16_t EType = *reinterpret_cast<const uint16_t*>(Data.constData() + 16);
                uint16_t EMachine = *reinterpret_cast<const uint16_t*>(Data.constData() + 18);
                uint64_t EEntry = *reinterpret_cast<const uint64_t*>(Data.constData() + 24);
                uint16_t EPhnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 56);
                uint16_t EShnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 60);
                QString TypeStr;
                switch (EType) {
                case 0: TypeStr = QStringLiteral("ET_NONE"); break;
                case 1: TypeStr = QStringLiteral("ET_REL"); break;
                case 2: TypeStr = QStringLiteral("ET_EXEC"); break;
                case 3: TypeStr = QStringLiteral("ET_DYN"); break;
                case 4: TypeStr = QStringLiteral("ET_CORE"); break;
                default: TypeStr = QStringLiteral("Unknown (") + QString::number(EType) + QStringLiteral(")"); break;
                }
                Result[QStringLiteral("type")] = TypeStr;
                QString MachStr;
                switch (EMachine) {
                case 3: MachStr = QStringLiteral("EM_386 (x86)"); break;
                case 40: MachStr = QStringLiteral("EM_ARM"); break;
                case 62: MachStr = QStringLiteral("EM_X86_64"); break;
                case 183: MachStr = QStringLiteral("EM_AARCH64"); break;
                case 243: MachStr = QStringLiteral("EM_RISCV"); break;
                default: MachStr = QStringLiteral("Unknown (") + QString::number(EMachine) + QStringLiteral(")"); break;
                }
                Result[QStringLiteral("machine")] = MachStr;
                Result[QStringLiteral("entry_point")] = QStringLiteral("0x") + QString::number(EEntry, 16).toUpper();
                Result[QStringLiteral("program_headers")] = EPhnum;
                Result[QStringLiteral("section_headers")] = EShnum;
            } else {
                uint16_t EType = *reinterpret_cast<const uint16_t*>(Data.constData() + 16);
                uint16_t EMachine = *reinterpret_cast<const uint16_t*>(Data.constData() + 18);
                uint32_t EEntry = *reinterpret_cast<const uint32_t*>(Data.constData() + 24);
                uint16_t EPhnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 44);
                uint16_t EShnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 48);
                Result[QStringLiteral("type")] = QString::number(EType);
                Result[QStringLiteral("machine")] = QString::number(EMachine);
                Result[QStringLiteral("entry_point")] = QStringLiteral("0x") + QString::number(EEntry, 16).toUpper();
                Result[QStringLiteral("program_headers")] = EPhnum;
                Result[QStringLiteral("section_headers")] = EShnum;
            }
            return Result;
        });

    RegisterTool(QStringLiteral("get_elf_sections"),
        QStringLiteral("Parse ELF section headers: name, type, flags, address, offset, size."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to ELF file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            if (Data.size() < 64 || static_cast<uint8_t>(Data[0]) != 0x7F || Data[1] != 'E' || Data[2] != 'L' || Data[3] != 'F')
                return Schema::Err(QStringLiteral("Not an ELF file"));
            uint8_t EiClass = static_cast<uint8_t>(Data[4]);
            bool Is64 = (EiClass == 2);
            QJsonArray Sections;
            if (Is64) {
                uint64_t EShoff = *reinterpret_cast<const uint64_t*>(Data.constData() + 40);
                uint16_t EShentsize = *reinterpret_cast<const uint16_t*>(Data.constData() + 58);
                uint16_t EShnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 60);
                uint16_t EShstrndx = *reinterpret_cast<const uint16_t*>(Data.constData() + 62);
                QByteArray ShstrtabData;
                if (EShstrndx < EShnum) {
                    int StrSecOff = static_cast<int>(EShoff) + EShstrndx * EShentsize;
                    if (StrSecOff + 64 <= Data.size()) {
                        uint64_t StrOff = *reinterpret_cast<const uint64_t*>(Data.constData() + StrSecOff + 24);
                        uint64_t StrSize = *reinterpret_cast<const uint64_t*>(Data.constData() + StrSecOff + 32);
                        if (static_cast<int>(StrOff + StrSize) <= Data.size())
                            ShstrtabData = Data.mid(static_cast<int>(StrOff), static_cast<int>(StrSize));
                    }
                }
                for (int I = 0; I < EShnum; ++I) {
                    int Off = static_cast<int>(EShoff) + I * EShentsize;
                    if (Off + 64 > Data.size()) break;
                    const uint8_t* Sh = reinterpret_cast<const uint8_t*>(Data.constData() + Off);
                    uint32_t ShName = *reinterpret_cast<const uint32_t*>(Sh);
                    uint32_t ShType = *reinterpret_cast<const uint32_t*>(Sh + 4);
                    uint64_t ShFlags = *reinterpret_cast<const uint64_t*>(Sh + 8);
                    uint64_t ShAddr = *reinterpret_cast<const uint64_t*>(Sh + 16);
                    uint64_t ShOffset = *reinterpret_cast<const uint64_t*>(Sh + 24);
                    uint64_t ShSz = *reinterpret_cast<const uint64_t*>(Sh + 32);
                    QJsonObject SecObj;
                    QString Name;
                    if (!ShstrtabData.isEmpty() && static_cast<int>(ShName) < ShstrtabData.size()) {
                        Name = QString::fromUtf8(ShstrtabData.constData() + ShName);
                    } else {
                        Name = QStringLiteral("section_") + QString::number(I);
                    }
                    SecObj[QStringLiteral("name")] = Name;
                    QString TypeStr;
                    switch (ShType) {
                    case 0: TypeStr = QStringLiteral("SHT_NULL"); break;
                    case 1: TypeStr = QStringLiteral("SHT_PROGBITS"); break;
                    case 2: TypeStr = QStringLiteral("SHT_SYMTAB"); break;
                    case 3: TypeStr = QStringLiteral("SHT_STRTAB"); break;
                    case 4: TypeStr = QStringLiteral("SHT_RELA"); break;
                    case 5: TypeStr = QStringLiteral("SHT_HASH"); break;
                    case 6: TypeStr = QStringLiteral("SHT_DYNAMIC"); break;
                    case 7: TypeStr = QStringLiteral("SHT_NOTE"); break;
                    case 8: TypeStr = QStringLiteral("SHT_NOBITS"); break;
                    case 9: TypeStr = QStringLiteral("SHT_REL"); break;
                    case 11: TypeStr = QStringLiteral("SHT_DYNSYM"); break;
                    default: TypeStr = QStringLiteral("0x") + QString::number(ShType, 16); break;
                    }
                    SecObj[QStringLiteral("type")] = TypeStr;
                    QString FlagStr;
                    if (ShFlags & 0x1) FlagStr += QStringLiteral("W");
                    if (ShFlags & 0x2) FlagStr += QStringLiteral("A");
                    if (ShFlags & 0x4) FlagStr += QStringLiteral("X");
                    SecObj[QStringLiteral("flags")] = FlagStr;
                    SecObj[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(ShAddr, 16).toUpper();
                    SecObj[QStringLiteral("offset")] = QStringLiteral("0x") + QString::number(ShOffset, 16).toUpper();
                    SecObj[QStringLiteral("size")] = static_cast<qint64>(ShSz);
                    Sections.append(SecObj);
                }
            } else {
                uint32_t EShoff = *reinterpret_cast<const uint32_t*>(Data.constData() + 32);
                uint16_t EShentsize = *reinterpret_cast<const uint16_t*>(Data.constData() + 46);
                uint16_t EShnum = *reinterpret_cast<const uint16_t*>(Data.constData() + 48);
                uint16_t EShstrndx = *reinterpret_cast<const uint16_t*>(Data.constData() + 50);
                QByteArray ShstrtabData;
                if (EShstrndx < EShnum) {
                    int StrSecOff = static_cast<int>(EShoff) + EShstrndx * EShentsize;
                    if (StrSecOff + 40 <= Data.size()) {
                        uint32_t StrOff = *reinterpret_cast<const uint32_t*>(Data.constData() + StrSecOff + 16);
                        uint32_t StrSize = *reinterpret_cast<const uint32_t*>(Data.constData() + StrSecOff + 20);
                        if (static_cast<int>(StrOff + StrSize) <= Data.size())
                            ShstrtabData = Data.mid(static_cast<int>(StrOff), static_cast<int>(StrSize));
                    }
                }
                for (int I = 0; I < EShnum; ++I) {
                    int Off = static_cast<int>(EShoff) + I * EShentsize;
                    if (Off + 40 > Data.size()) break;
                    const uint8_t* Sh = reinterpret_cast<const uint8_t*>(Data.constData() + Off);
                    uint32_t ShName = *reinterpret_cast<const uint32_t*>(Sh);
                    uint32_t ShType = *reinterpret_cast<const uint32_t*>(Sh + 4);
                    uint32_t ShFlags = *reinterpret_cast<const uint32_t*>(Sh + 8);
                    uint32_t ShAddr = *reinterpret_cast<const uint32_t*>(Sh + 12);
                    uint32_t ShOffset = *reinterpret_cast<const uint32_t*>(Sh + 16);
                    uint32_t ShSz = *reinterpret_cast<const uint32_t*>(Sh + 20);
                    QJsonObject SecObj;
                    QString Name;
                    if (!ShstrtabData.isEmpty() && static_cast<int>(ShName) < ShstrtabData.size())
                        Name = QString::fromUtf8(ShstrtabData.constData() + ShName);
                    else
                        Name = QStringLiteral("section_") + QString::number(I);
                    SecObj[QStringLiteral("name")] = Name;
                    SecObj[QStringLiteral("type")] = QString::number(ShType);
                    QString FlagStr;
                    if (ShFlags & 0x1) FlagStr += QStringLiteral("W");
                    if (ShFlags & 0x2) FlagStr += QStringLiteral("A");
                    if (ShFlags & 0x4) FlagStr += QStringLiteral("X");
                    SecObj[QStringLiteral("flags")] = FlagStr;
                    SecObj[QStringLiteral("address")] = QStringLiteral("0x") + QString::number(ShAddr, 16).toUpper();
                    SecObj[QStringLiteral("offset")] = QStringLiteral("0x") + QString::number(ShOffset, 16).toUpper();
                    SecObj[QStringLiteral("size")] = static_cast<int>(ShSz);
                    Sections.append(SecObj);
                }
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("section_count")] = Sections.size();
            Result[QStringLiteral("sections")] = Sections;
            return Result;
        });

    RegisterTool(QStringLiteral("search_file_bytes"),
        QStringLiteral("Search for a hex byte pattern in a file. Returns array of offsets where the pattern was found."),
        Schema::Build({
            {QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))},
            {QStringLiteral("hex_pattern"), Schema::String(QStringLiteral("Hex-encoded bytes to search for (e.g. '4D5A9000')"))},
            {QStringLiteral("max_results"), Schema::Integer(QStringLiteral("Maximum results to return (default 100)"), 1, 10000)}
        }, {QStringLiteral("path"), QStringLiteral("hex_pattern")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QByteArray Pattern = QByteArray::fromHex(A.value(QStringLiteral("hex_pattern")).toString().remove(' ').toLatin1());
            int MaxResults = A.value(QStringLiteral("max_results")).toInt(100);
            if (Pattern.isEmpty())
                return Schema::Err(QStringLiteral("Invalid hex pattern"));
            QFile File(Path);
            if (!File.open(QIODevice::ReadOnly))
                return Schema::Err(QStringLiteral("Cannot open file: ") + File.errorString());
            QByteArray Data = File.readAll();
            File.close();
            QJsonArray Matches;
            int SearchFrom = 0;
            while (SearchFrom + Pattern.size() <= Data.size() && Matches.size() < MaxResults) {
                int Idx = Data.indexOf(Pattern, SearchFrom);
                if (Idx < 0) break;
                QJsonObject Match;
                Match[QStringLiteral("offset")] = Idx;
                Match[QStringLiteral("offset_hex")] = QStringLiteral("0x") + QString::number(Idx, 16).toUpper();
                Matches.append(Match);
                SearchFrom = Idx + 1;
            }
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("pattern")] = QString::fromLatin1(Pattern.toHex(' '));
            Result[QStringLiteral("count")] = Matches.size();
            Result[QStringLiteral("matches")] = Matches;
            if (Matches.size() >= MaxResults)
                Result[QStringLiteral("truncated")] = true;
            return Result;
        });

    RegisterTool(QStringLiteral("file_size"),
        QStringLiteral("Get the size of a file in bytes."),
        Schema::Build({{QStringLiteral("path"), Schema::String(QStringLiteral("Path to the file"))}},
                       {QStringLiteral("path")}),
        [this](const QJsonObject& A) -> QJsonValue {
            QString Path = A.value(QStringLiteral("path")).toString();
            QFileInfo Info(Path);
            if (!Info.exists())
                return Schema::Err(QStringLiteral("File does not exist: ") + Path);
            QJsonObject Result;
            Result[QStringLiteral("path")] = Path;
            Result[QStringLiteral("size")] = Info.size();
            Result[QStringLiteral("size_hex")] = QStringLiteral("0x") + QString::number(Info.size(), 16).toUpper();
            QString HumanSize;
            double Sz = static_cast<double>(Info.size());
            if (Sz < 1024.0) HumanSize = QString::number(Info.size()) + QStringLiteral(" B");
            else if (Sz < 1024.0 * 1024.0) HumanSize = QString::number(Sz / 1024.0, 'f', 2) + QStringLiteral(" KB");
            else if (Sz < 1024.0 * 1024.0 * 1024.0) HumanSize = QString::number(Sz / (1024.0 * 1024.0), 'f', 2) + QStringLiteral(" MB");
            else HumanSize = QString::number(Sz / (1024.0 * 1024.0 * 1024.0), 'f', 2) + QStringLiteral(" GB");
            Result[QStringLiteral("human_readable")] = HumanSize;
            return Result;
        });
}

}
