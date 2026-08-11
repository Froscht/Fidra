#pragma once

#include "SymbolServer.h"
#include "../analysis/AnalysisTypes.h"
#include <QMap>
#include <QList>
#include <QNetworkAccessManager>

namespace Fidra {

class SymbolResolver : public QObject {
    Q_OBJECT

public:
    explicit SymbolResolver(QObject* Parent = nullptr);
    ~SymbolResolver() override;

    void LoadFromExports(const QList<ExportEntry>& Exports, Address ImageBase);
    void LoadFromImports(const QList<ImportEntry>& Imports);
    void LoadFromDwarf(const QString& BinaryPath);
    void LoadFromSymbolFile(const QString& Path);

    void SetSymbolServer(const QString& Url);
    void FetchSymbolsAsync(const QString& ModuleName, const QString& BuildId);

    SymbolInfo Resolve(Address Addr) const;
    QList<SymbolInfo> Search(const QString& Pattern) const;
    QList<SymbolInfo> GetAllSymbols() const;
    int SymbolCount() const;

    void AddSymbol(const SymbolInfo& Info);
    void RemoveSymbol(Address Addr);

signals:
    void SymbolsLoaded(int Count);
    void FetchComplete(const QString& Module, int SymbolCount);
    void FetchError(const QString& Module, const QString& Error);

private:
    struct ElfSectionInfo {
        uint64_t Offset;
        uint64_t Size;
    };

    struct DwarfAbbrevAttr {
        uint16_t Name;
        uint16_t Form;
    };

    struct DwarfAbbrevEntry {
        uint32_t Code;
        uint16_t Tag;
        bool HasChildren;
        QList<DwarfAbbrevAttr> Attrs;
    };

    bool ReadElfSections(const QByteArray& Data, QMap<QString, ElfSectionInfo>& Sections);
    QMap<uint32_t, DwarfAbbrevEntry> ParseAbbrevTable(const uint8_t* Data, size_t Size);
    void ParseDebugInfo(const uint8_t* InfoData, size_t InfoSize,
                        const QMap<uint32_t, DwarfAbbrevEntry>& Abbrevs,
                        const uint8_t* StrData, size_t StrSize,
                        QList<SymbolInfo>& Result);
    uint64_t ReadUleb128(const uint8_t*& Ptr, const uint8_t* End);
    int64_t ReadSleb128(const uint8_t*& Ptr, const uint8_t* End);
    void SkipDwarfForm(uint16_t Form, const uint8_t*& Ptr, const uint8_t* End, uint8_t AddrSize);

    QMap<Address, SymbolInfo> Symbols;
    QString ServerUrl;
    QNetworkAccessManager* NetManager;
};

}
