#pragma once

#include <fidra/Types.h>
#include <QString>
#include <QList>
#include <QByteArray>
#include <QMap>
#include <cstdint>
#include <memory>

namespace Fidra {

class ICore;
class PeParser;

struct ResolvedImport {
    uint64_t IatAddress;
    uint64_t ResolvedAddress;
    QString ModuleName;
    QString FunctionName;
    uint16_t Ordinal;
    bool IsOrdinal;
    bool IsValid;
};

struct IatFixupResult {
    int TotalEntries;
    int ResolvedEntries;
    int FailedEntries;
    QList<ResolvedImport> Imports;
    QByteArray RebuiltData;
    bool Success;
    QString ErrorMessage;
};

class IatRebuilder {
public:
    explicit IatRebuilder(PeParser* Parser);
    ~IatRebuilder();

    void SetCore(ICore* Core);

    IatFixupResult ScanAndRebuild(uint64_t BaseAddress);
    IatFixupResult RebuildFromMemory(uint64_t BaseAddress);

    QList<ResolvedImport> ScanForApiCalls(uint64_t BaseAddress, uint64_t Size);
    bool ResolveAddress(uint64_t Address, QString& ModuleName, QString& FunctionName);

    QByteArray BuildImportDirectory(const QList<ResolvedImport>& Imports);
    bool FixSectionPermissions(QByteArray& PeData);

    void SetModuleMap(const QMap<QString, uint64_t>& Map);

private:
    struct ModuleExport {
        QString FunctionName;
        uint16_t Ordinal;
        uint64_t Rva;
    };

    void BuildModuleExportMap();
    bool IsExecutableRegion(uint64_t Address);
    bool IsApiAddress(uint64_t Address, const QList<MemoryRegion>& Regions);
    uint32_t RvaToOffset(uint32_t Rva, const QByteArray& PeData);

    PeParser* ParserRef;
    ICore* CoreRef;
    QMap<QString, uint64_t> ModuleBaseMap;
    QMap<uint64_t, ModuleExport> AddressToExport;
    bool ExportMapBuilt;
};

}
