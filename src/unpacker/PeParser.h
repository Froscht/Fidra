#pragma once

#include <QString>
#include <QList>
#include <QPair>
#include <QByteArray>
#include <memory>
#include <cstdint>
#include <LIEF/PE.hpp>

namespace Fidra {

struct PeDosHeader {
    uint16_t Magic;
    uint16_t Cblp;
    uint16_t Cp;
    uint16_t Crlc;
    uint16_t Cparhdr;
    uint16_t Minalloc;
    uint16_t Maxalloc;
    uint16_t Ss;
    uint16_t Sp;
    uint16_t Csum;
    uint16_t Ip;
    uint16_t Cs;
    uint16_t Lfarlc;
    uint16_t Ovno;
    uint16_t Oemid;
    uint16_t Oeminfo;
    int32_t Lfanew;
};

struct PeFileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct PeDataDirectory {
    QString Name;
    uint32_t Rva;
    uint32_t Size;
};

struct PeOptionalHeader {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    QList<PeDataDirectory> DataDirectories;
};

struct PeSectionInfo {
    QString Name;
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint32_t RawSize;
    uint32_t RawOffset;
    uint32_t Characteristics;
    double Entropy;
};

struct PeImportEntry {
    QString Name;
    uint16_t Hint;
    uint16_t Ordinal;
    bool IsOrdinal;
};

struct PeImportDll {
    QString DllName;
    QList<PeImportEntry> Functions;
};

struct PeExportEntry {
    uint16_t Ordinal;
    QString Name;
    uint64_t Address;
    QString ForwarderName;
};

struct PeResourceEntry {
    uint32_t Id;
    QString Name;
    QString Type;
    uint32_t Offset;
    uint32_t Size;
    int Depth;
    QByteArray Data;
};

struct PeTlsCallback {
    uint64_t Address;
};

struct PeRichEntry {
    uint16_t Id;
    uint16_t BuildId;
    uint32_t Count;
};

struct PackerDetection {
    QString Name;
    double Confidence;
    QString Details;
};

class PeParser {
public:
    PeParser();
    ~PeParser();

    bool ParseFile(const QString& FilePath);
    bool ParseMemory(const QByteArray& Data);

    bool IsValid() const;
    bool IsPe32Plus() const;

    PeDosHeader GetDosHeader() const;
    PeFileHeader GetFileHeader() const;
    PeOptionalHeader GetOptionalHeader() const;
    QList<PeSectionInfo> GetSections() const;
    QList<PeImportDll> GetImports() const;
    QList<PeExportEntry> GetExports() const;
    QList<PeResourceEntry> GetResources() const;
    QList<PeTlsCallback> GetTlsCallbacks() const;
    QList<PeRichEntry> GetRichHeader() const;
    QList<PackerDetection> DetectPackers() const;

    static double CalculateEntropy(const uint8_t* Data, size_t Size);
    QList<QPair<uint64_t, double>> CalculateFileEntropy(size_t BlockSize = 256) const;

    const QByteArray& GetRawData() const;
    LIEF::PE::Binary* GetBinary() const;

private:
    std::unique_ptr<LIEF::PE::Binary> BinaryData;
    QByteArray RawData;
    bool Valid;

    void WalkResourceNode(const LIEF::PE::ResourceNode& Node, QList<PeResourceEntry>& Entries, int Depth, const QString& TypeName) const;
};

}
