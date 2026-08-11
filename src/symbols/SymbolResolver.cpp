#include "SymbolResolver.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <cstring>

namespace Fidra {

struct Elf64Header {
    uint8_t Ident[16];
    uint16_t Type;
    uint16_t Machine;
    uint32_t Version;
    uint64_t Entry;
    uint64_t PhOff;
    uint64_t ShOff;
    uint32_t Flags;
    uint16_t EhSize;
    uint16_t PhEntSize;
    uint16_t PhNum;
    uint16_t ShEntSize;
    uint16_t ShNum;
    uint16_t ShStrNdx;
};

struct Elf32Header {
    uint8_t Ident[16];
    uint16_t Type;
    uint16_t Machine;
    uint32_t Version;
    uint32_t Entry;
    uint32_t PhOff;
    uint32_t ShOff;
    uint32_t Flags;
    uint16_t EhSize;
    uint16_t PhEntSize;
    uint16_t PhNum;
    uint16_t ShEntSize;
    uint16_t ShNum;
    uint16_t ShStrNdx;
};

struct Elf64SectionHeader {
    uint32_t Name;
    uint32_t Type;
    uint64_t Flags;
    uint64_t Addr;
    uint64_t Offset;
    uint64_t Size;
    uint32_t Link;
    uint32_t Info;
    uint64_t AddrAlign;
    uint64_t EntSize;
};

struct Elf32SectionHeader {
    uint32_t Name;
    uint32_t Type;
    uint32_t Flags;
    uint32_t Addr;
    uint32_t Offset;
    uint32_t Size;
    uint32_t Link;
    uint32_t Info;
    uint32_t AddrAlign;
    uint32_t EntSize;
};

SymbolResolver::SymbolResolver(QObject* Parent)
    : QObject(Parent)
    , NetManager(new QNetworkAccessManager(this))
{
}

SymbolResolver::~SymbolResolver() = default;

void SymbolResolver::LoadFromExports(const QList<ExportEntry>& Exports, Address ImageBase)
{
    int Loaded = 0;
    for (const auto& Exp : Exports) {
        if (Exp.Name.isEmpty())
            continue;

        SymbolInfo Info;
        if (Exp.Addr > ImageBase) {
            Info.Addr = Exp.Addr;
        } else {
            Info.Addr = static_cast<Address>(Exp.Rva) + ImageBase;
        }
        Info.Name = Exp.Name;
        Info.Module = QString();
        Info.Source = QStringLiteral("export");
        Info.Size = 0;

        if (!Symbols.contains(Info.Addr)) {
            Symbols.insert(Info.Addr, Info);
            ++Loaded;
        }
    }

    if (Loaded > 0) {
        emit SymbolsLoaded(Loaded);
    }
}

void SymbolResolver::LoadFromImports(const QList<ImportEntry>& Imports)
{
    int Loaded = 0;
    for (const auto& Imp : Imports) {
        if (Imp.FuncName.isEmpty() && Imp.Ordinal == 0)
            continue;

        SymbolInfo Info;
        Info.Addr = Imp.IatAddress;
        if (!Imp.FuncName.isEmpty()) {
            Info.Name = Imp.DllName + QStringLiteral("!") + Imp.FuncName;
        } else {
            Info.Name = Imp.DllName + QStringLiteral("!Ordinal_") + QString::number(Imp.Ordinal);
        }
        Info.Module = Imp.DllName;
        Info.Source = QStringLiteral("import");
        Info.Size = 0;

        if (!Symbols.contains(Info.Addr)) {
            Symbols.insert(Info.Addr, Info);
            ++Loaded;
        }
    }

    if (Loaded > 0) {
        emit SymbolsLoaded(Loaded);
    }
}

void SymbolResolver::LoadFromDwarf(const QString& BinaryPath)
{
    QFile File(BinaryPath);
    if (!File.open(QIODevice::ReadOnly)) {
        return;
    }

    QByteArray Data = File.readAll();
    File.close();

    if (Data.size() < 4) {
        return;
    }

    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    if (Raw[0] != 0x7f || Raw[1] != 'E' || Raw[2] != 'L' || Raw[3] != 'F') {
        return;
    }

    QMap<QString, ElfSectionInfo> Sections;
    if (!ReadElfSections(Data, Sections)) {
        return;
    }

    if (!Sections.contains(QStringLiteral(".debug_info")) ||
        !Sections.contains(QStringLiteral(".debug_abbrev"))) {
        return;
    }

    auto AbbrevSection = Sections.value(QStringLiteral(".debug_abbrev"));
    auto InfoSection = Sections.value(QStringLiteral(".debug_info"));

    if (AbbrevSection.Offset + AbbrevSection.Size > static_cast<uint64_t>(Data.size()) ||
        InfoSection.Offset + InfoSection.Size > static_cast<uint64_t>(Data.size())) {
        return;
    }

    const uint8_t* AbbrevData = Raw + AbbrevSection.Offset;
    const uint8_t* InfoData = Raw + InfoSection.Offset;

    auto Abbrevs = ParseAbbrevTable(AbbrevData, AbbrevSection.Size);

    const uint8_t* StrData = nullptr;
    size_t StrSize = 0;
    if (Sections.contains(QStringLiteral(".debug_str"))) {
        auto StrSection = Sections.value(QStringLiteral(".debug_str"));
        if (StrSection.Offset + StrSection.Size <= static_cast<uint64_t>(Data.size())) {
            StrData = Raw + StrSection.Offset;
            StrSize = StrSection.Size;
        }
    }

    QList<SymbolInfo> Result;
    ParseDebugInfo(InfoData, InfoSection.Size, Abbrevs, StrData, StrSize, Result);

    int Loaded = 0;
    for (const auto& Sym : Result) {
        if (!Symbols.contains(Sym.Addr)) {
            Symbols.insert(Sym.Addr, Sym);
            ++Loaded;
        }
    }

    if (Loaded > 0) {
        emit SymbolsLoaded(Loaded);
    }
}

void SymbolResolver::LoadFromSymbolFile(const QString& Path)
{
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }

    QTextStream Stream(&File);
    int Loaded = 0;

    while (!Stream.atEnd()) {
        QString Line = Stream.readLine().trimmed();
        if (Line.isEmpty() || Line.startsWith(QStringLiteral("#"))) {
            continue;
        }

        QStringList Parts = Line.split(QRegularExpression(QStringLiteral("\\s+")));
        if (Parts.size() < 2) {
            continue;
        }

        bool Ok = false;
        Address Addr = Parts[0].toULongLong(&Ok, 16);
        if (!Ok) {
            continue;
        }

        SymbolInfo Info;
        Info.Addr = Addr;
        Info.Name = Parts[1];
        Info.Module = QString();
        Info.Source = QStringLiteral("symfile");
        Info.Size = 0;

        if (Parts.size() >= 3) {
            bool SizeOk = false;
            int ParsedSize = Parts[2].toInt(&SizeOk);
            if (SizeOk) {
                Info.Size = ParsedSize;
            }
        }

        Symbols.insert(Info.Addr, Info);
        ++Loaded;
    }

    File.close();

    if (Loaded > 0) {
        emit SymbolsLoaded(Loaded);
    }
}

void SymbolResolver::SetSymbolServer(const QString& Url)
{
    ServerUrl = Url;
    if (ServerUrl.endsWith(QStringLiteral("/"))) {
        ServerUrl.chop(1);
    }
}

void SymbolResolver::FetchSymbolsAsync(const QString& ModuleName, const QString& BuildId)
{
    if (ServerUrl.isEmpty()) {
        emit FetchError(ModuleName, QStringLiteral("No symbol server URL configured"));
        return;
    }

    QString RequestUrl = ServerUrl + QStringLiteral("/symbols/") + ModuleName +
                         QStringLiteral("/") + BuildId + QStringLiteral("/symbols.json");

    QUrl ReqUrl(RequestUrl);
    QNetworkRequest Request(ReqUrl);
    Request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply* Reply = NetManager->get(Request);

    connect(Reply, &QNetworkReply::finished, this, [this, Reply, ModuleName]() {
        Reply->deleteLater();

        if (Reply->error() != QNetworkReply::NoError) {
            emit FetchError(ModuleName, Reply->errorString());
            return;
        }

        QByteArray ResponseData = Reply->readAll();
        QJsonParseError ParseError;
        QJsonDocument Doc = QJsonDocument::fromJson(ResponseData, &ParseError);

        if (ParseError.error != QJsonParseError::NoError) {
            emit FetchError(ModuleName, QStringLiteral("JSON parse error: ") + ParseError.errorString());
            return;
        }

        if (!Doc.isArray()) {
            emit FetchError(ModuleName, QStringLiteral("Expected JSON array response"));
            return;
        }

        QJsonArray Arr = Doc.array();
        int Loaded = 0;

        for (const auto& Val : Arr) {
            if (!Val.isObject()) continue;

            QJsonObject Obj = Val.toObject();
            SymbolInfo Info;

            Info.Name = Obj.value(QStringLiteral("name")).toString();
            if (Info.Name.isEmpty()) continue;

            QJsonValue OffsetVal = Obj.value(QStringLiteral("offset"));
            if (OffsetVal.isDouble()) {
                Info.Addr = static_cast<Address>(OffsetVal.toDouble());
            } else if (OffsetVal.isString()) {
                bool Ok = false;
                Info.Addr = OffsetVal.toString().toULongLong(&Ok, 16);
                if (!Ok) continue;
            } else {
                continue;
            }

            Info.Module = ModuleName;
            Info.Source = QStringLiteral("server");
            Info.Size = Obj.value(QStringLiteral("size")).toInt(0);

            Symbols.insert(Info.Addr, Info);
            ++Loaded;
        }

        emit FetchComplete(ModuleName, Loaded);
    });
}

SymbolInfo SymbolResolver::Resolve(Address Addr) const
{
    auto It = Symbols.find(Addr);
    if (It != Symbols.end()) {
        return It.value();
    }

    It = Symbols.upperBound(Addr);
    if (It != Symbols.begin()) {
        --It;
        SymbolInfo Found = It.value();
        Address Delta = Addr - Found.Addr;
        if (Found.Size > 0 && Delta < static_cast<Address>(Found.Size)) {
            SymbolInfo Result = Found;
            Result.Name = Found.Name + QStringLiteral("+0x") + QString::number(Delta, 16);
            Result.Addr = Addr;
            return Result;
        }

        if (Found.Size == 0 && Delta < 0x1000) {
            SymbolInfo Result = Found;
            Result.Name = Found.Name + QStringLiteral("+0x") + QString::number(Delta, 16);
            Result.Addr = Addr;
            return Result;
        }
    }

    SymbolInfo Empty;
    Empty.Addr = Addr;
    Empty.Size = 0;
    return Empty;
}

QList<SymbolInfo> SymbolResolver::Search(const QString& Pattern) const
{
    QList<SymbolInfo> Results;
    for (auto It = Symbols.constBegin(); It != Symbols.constEnd(); ++It) {
        if (It.value().Name.contains(Pattern, Qt::CaseInsensitive)) {
            Results.append(It.value());
        }
    }
    return Results;
}

QList<SymbolInfo> SymbolResolver::GetAllSymbols() const
{
    return Symbols.values();
}

int SymbolResolver::SymbolCount() const
{
    return Symbols.size();
}

void SymbolResolver::AddSymbol(const SymbolInfo& Info)
{
    Symbols.insert(Info.Addr, Info);
    emit SymbolsLoaded(1);
}

void SymbolResolver::RemoveSymbol(Address Addr)
{
    Symbols.remove(Addr);
}

bool SymbolResolver::ReadElfSections(const QByteArray& Data, QMap<QString, ElfSectionInfo>& Sections)
{
    const uint8_t* Raw = reinterpret_cast<const uint8_t*>(Data.constData());
    size_t DataSize = static_cast<size_t>(Data.size());

    if (DataSize < 16) return false;

    uint8_t ElfClass = Raw[4];
    bool Is64 = (ElfClass == 2);

    if (Is64) {
        if (DataSize < sizeof(Elf64Header)) return false;

        Elf64Header Hdr;
        std::memcpy(&Hdr, Raw, sizeof(Hdr));

        if (Hdr.ShOff == 0 || Hdr.ShNum == 0) return false;
        if (Hdr.ShOff + static_cast<uint64_t>(Hdr.ShNum) * Hdr.ShEntSize > DataSize) return false;
        if (Hdr.ShStrNdx >= Hdr.ShNum) return false;

        Elf64SectionHeader StrTabHdr;
        std::memcpy(&StrTabHdr, Raw + Hdr.ShOff + Hdr.ShStrNdx * Hdr.ShEntSize, sizeof(StrTabHdr));

        if (StrTabHdr.Offset + StrTabHdr.Size > DataSize) return false;
        const char* StrTab = reinterpret_cast<const char*>(Raw + StrTabHdr.Offset);

        for (uint16_t I = 0; I < Hdr.ShNum; ++I) {
            Elf64SectionHeader Shdr;
            std::memcpy(&Shdr, Raw + Hdr.ShOff + I * Hdr.ShEntSize, sizeof(Shdr));

            if (Shdr.Name < StrTabHdr.Size) {
                QString SectionName = QString::fromUtf8(StrTab + Shdr.Name);
                ElfSectionInfo Info;
                Info.Offset = Shdr.Offset;
                Info.Size = Shdr.Size;
                Sections.insert(SectionName, Info);
            }
        }
    } else {
        if (DataSize < sizeof(Elf32Header)) return false;

        Elf32Header Hdr;
        std::memcpy(&Hdr, Raw, sizeof(Hdr));

        if (Hdr.ShOff == 0 || Hdr.ShNum == 0) return false;
        if (Hdr.ShOff + static_cast<uint64_t>(Hdr.ShNum) * Hdr.ShEntSize > DataSize) return false;
        if (Hdr.ShStrNdx >= Hdr.ShNum) return false;

        Elf32SectionHeader StrTabHdr;
        std::memcpy(&StrTabHdr, Raw + Hdr.ShOff + Hdr.ShStrNdx * Hdr.ShEntSize, sizeof(StrTabHdr));

        if (StrTabHdr.Offset + StrTabHdr.Size > DataSize) return false;
        const char* StrTab = reinterpret_cast<const char*>(Raw + StrTabHdr.Offset);

        for (uint16_t I = 0; I < Hdr.ShNum; ++I) {
            Elf32SectionHeader Shdr;
            std::memcpy(&Shdr, Raw + Hdr.ShOff + I * Hdr.ShEntSize, sizeof(Shdr));

            if (Shdr.Name < StrTabHdr.Size) {
                QString SectionName = QString::fromUtf8(StrTab + Shdr.Name);
                ElfSectionInfo Info;
                Info.Offset = Shdr.Offset;
                Info.Size = Shdr.Size;
                Sections.insert(SectionName, Info);
            }
        }
    }

    return true;
}

QMap<uint32_t, SymbolResolver::DwarfAbbrevEntry> SymbolResolver::ParseAbbrevTable(const uint8_t* Data, size_t Size)
{
    QMap<uint32_t, DwarfAbbrevEntry> Abbrevs;
    const uint8_t* Ptr = Data;
    const uint8_t* End = Data + Size;

    while (Ptr < End) {
        uint64_t Code = ReadUleb128(Ptr, End);
        if (Code == 0) break;

        DwarfAbbrevEntry Entry;
        Entry.Code = static_cast<uint32_t>(Code);

        if (Ptr >= End) break;
        Entry.Tag = static_cast<uint16_t>(ReadUleb128(Ptr, End));

        if (Ptr >= End) break;
        Entry.HasChildren = (*Ptr++ != 0);

        while (Ptr < End) {
            uint64_t AttrName = ReadUleb128(Ptr, End);
            if (Ptr >= End) break;
            uint64_t AttrForm = ReadUleb128(Ptr, End);

            if (AttrName == 0 && AttrForm == 0) break;

            DwarfAbbrevAttr Attr;
            Attr.Name = static_cast<uint16_t>(AttrName);
            Attr.Form = static_cast<uint16_t>(AttrForm);
            Entry.Attrs.append(Attr);
        }

        Abbrevs.insert(Entry.Code, Entry);
    }

    return Abbrevs;
}

void SymbolResolver::ParseDebugInfo(const uint8_t* InfoData, size_t InfoSize,
                                     const QMap<uint32_t, DwarfAbbrevEntry>& Abbrevs,
                                     const uint8_t* StrData, size_t StrSize,
                                     QList<SymbolInfo>& Result)
{
    const uint8_t* Ptr = InfoData;
    const uint8_t* End = InfoData + InfoSize;

    while (Ptr < End) {
        const uint8_t* UnitStart = Ptr;

        if (Ptr + 4 > End) break;
        uint32_t UnitLength;
        std::memcpy(&UnitLength, Ptr, 4);
        Ptr += 4;

        bool Is64BitDwarf = false;
        uint64_t ActualLength = UnitLength;
        if (UnitLength == 0xFFFFFFFF) {
            if (Ptr + 8 > End) break;
            std::memcpy(&ActualLength, Ptr, 8);
            Ptr += 8;
            Is64BitDwarf = true;
        }

        const uint8_t* UnitEnd = Ptr + ActualLength;
        if (UnitEnd > End) break;

        if (Ptr + 2 > UnitEnd) { Ptr = UnitEnd; continue; }
        uint16_t Version;
        std::memcpy(&Version, Ptr, 2);
        Ptr += 2;

        uint8_t AddrSize = 8;

        if (Version >= 5) {
            if (Ptr + 1 > UnitEnd) { Ptr = UnitEnd; continue; }
            Ptr += 1;

            if (Ptr + 1 > UnitEnd) { Ptr = UnitEnd; continue; }
            AddrSize = *Ptr++;

            if (Is64BitDwarf) {
                if (Ptr + 8 > UnitEnd) { Ptr = UnitEnd; continue; }
                Ptr += 8;
            } else {
                if (Ptr + 4 > UnitEnd) { Ptr = UnitEnd; continue; }
                Ptr += 4;
            }
        } else {
            if (Is64BitDwarf) {
                if (Ptr + 8 > UnitEnd) { Ptr = UnitEnd; continue; }
                Ptr += 8;
            } else {
                if (Ptr + 4 > UnitEnd) { Ptr = UnitEnd; continue; }
                Ptr += 4;
            }

            if (Ptr + 1 > UnitEnd) { Ptr = UnitEnd; continue; }
            AddrSize = *Ptr++;
        }

        while (Ptr < UnitEnd) {
            uint64_t AbbrevCode = ReadUleb128(Ptr, UnitEnd);
            if (AbbrevCode == 0) continue;

            auto AbbrevIt = Abbrevs.find(static_cast<uint32_t>(AbbrevCode));
            if (AbbrevIt == Abbrevs.end()) {
                Ptr = UnitEnd;
                break;
            }

            const DwarfAbbrevEntry& Abbrev = AbbrevIt.value();

            constexpr uint16_t DwTagSubprogram = 0x2e;
            constexpr uint16_t DwAtName = 0x03;
            constexpr uint16_t DwAtLowPc = 0x11;
            constexpr uint16_t DwAtHighPc = 0x12;

            bool IsSubprogram = (Abbrev.Tag == DwTagSubprogram);
            QString FuncName;
            Address FuncAddr = 0;
            Address HighPc = 0;
            bool HasHighPc = false;
            bool HighPcIsOffset = false;

            for (const auto& Attr : Abbrev.Attrs) {
                if (Ptr >= UnitEnd) break;

                const uint8_t* AttrStart = Ptr;

                if (IsSubprogram && Attr.Name == DwAtName) {
                    constexpr uint16_t DwFormString = 0x08;
                    constexpr uint16_t DwFormStrp = 0x0e;

                    if (Attr.Form == DwFormString) {
                        FuncName = QString::fromUtf8(reinterpret_cast<const char*>(Ptr));
                        Ptr += strlen(reinterpret_cast<const char*>(Ptr)) + 1;
                        continue;
                    } else if (Attr.Form == DwFormStrp) {
                        uint64_t StrOffset;
                        if (Is64BitDwarf) {
                            if (Ptr + 8 <= UnitEnd) {
                                std::memcpy(&StrOffset, Ptr, 8);
                                Ptr += 8;
                            } else { Ptr = UnitEnd; break; }
                        } else {
                            if (Ptr + 4 <= UnitEnd) {
                                uint32_t Off32;
                                std::memcpy(&Off32, Ptr, 4);
                                StrOffset = Off32;
                                Ptr += 4;
                            } else { Ptr = UnitEnd; break; }
                        }
                        if (StrData && StrOffset < StrSize) {
                            FuncName = QString::fromUtf8(reinterpret_cast<const char*>(StrData + StrOffset));
                        }
                        continue;
                    }
                }

                if (IsSubprogram && Attr.Name == DwAtLowPc) {
                    constexpr uint16_t DwFormAddr = 0x01;
                    if (Attr.Form == DwFormAddr) {
                        if (AddrSize == 8 && Ptr + 8 <= UnitEnd) {
                            std::memcpy(&FuncAddr, Ptr, 8);
                            Ptr += 8;
                        } else if (AddrSize == 4 && Ptr + 4 <= UnitEnd) {
                            uint32_t Addr32;
                            std::memcpy(&Addr32, Ptr, 4);
                            FuncAddr = Addr32;
                            Ptr += 4;
                        } else {
                            Ptr += AddrSize;
                        }
                        continue;
                    }
                }

                if (IsSubprogram && Attr.Name == DwAtHighPc) {
                    constexpr uint16_t DwFormAddr = 0x01;
                    constexpr uint16_t DwFormData1 = 0x0b;
                    constexpr uint16_t DwFormData2 = 0x05;
                    constexpr uint16_t DwFormData4 = 0x06;
                    constexpr uint16_t DwFormData8 = 0x07;
                    constexpr uint16_t DwFormUdata = 0x0f;

                    HasHighPc = true;
                    if (Attr.Form == DwFormAddr) {
                        HighPcIsOffset = false;
                        if (AddrSize == 8 && Ptr + 8 <= UnitEnd) {
                            std::memcpy(&HighPc, Ptr, 8);
                            Ptr += 8;
                        } else if (AddrSize == 4 && Ptr + 4 <= UnitEnd) {
                            uint32_t Hp32;
                            std::memcpy(&Hp32, Ptr, 4);
                            HighPc = Hp32;
                            Ptr += 4;
                        } else {
                            Ptr += AddrSize;
                        }
                        continue;
                    } else if (Attr.Form == DwFormData1 && Ptr + 1 <= UnitEnd) {
                        HighPcIsOffset = true;
                        HighPc = *Ptr++;
                        continue;
                    } else if (Attr.Form == DwFormData2 && Ptr + 2 <= UnitEnd) {
                        HighPcIsOffset = true;
                        uint16_t V;
                        std::memcpy(&V, Ptr, 2);
                        HighPc = V;
                        Ptr += 2;
                        continue;
                    } else if (Attr.Form == DwFormData4 && Ptr + 4 <= UnitEnd) {
                        HighPcIsOffset = true;
                        uint32_t V;
                        std::memcpy(&V, Ptr, 4);
                        HighPc = V;
                        Ptr += 4;
                        continue;
                    } else if (Attr.Form == DwFormData8 && Ptr + 8 <= UnitEnd) {
                        HighPcIsOffset = true;
                        std::memcpy(&HighPc, Ptr, 8);
                        Ptr += 8;
                        continue;
                    } else if (Attr.Form == DwFormUdata) {
                        HighPcIsOffset = true;
                        HighPc = ReadUleb128(Ptr, UnitEnd);
                        continue;
                    }
                }

                SkipDwarfForm(Attr.Form, Ptr, UnitEnd, AddrSize);
            }

            if (IsSubprogram && !FuncName.isEmpty() && FuncAddr != 0) {
                SymbolInfo Info;
                Info.Addr = FuncAddr;
                Info.Name = FuncName;
                Info.Module = QString();
                Info.Source = QStringLiteral("dwarf");

                if (HasHighPc) {
                    if (HighPcIsOffset) {
                        Info.Size = static_cast<int>(HighPc);
                    } else if (HighPc > FuncAddr) {
                        Info.Size = static_cast<int>(HighPc - FuncAddr);
                    } else {
                        Info.Size = 0;
                    }
                } else {
                    Info.Size = 0;
                }

                Result.append(Info);
            }
        }

        Ptr = UnitEnd;
    }
}

uint64_t SymbolResolver::ReadUleb128(const uint8_t*& Ptr, const uint8_t* End)
{
    uint64_t Val = 0;
    int Shift = 0;
    while (Ptr < End) {
        uint8_t Byte = *Ptr++;
        Val |= static_cast<uint64_t>(Byte & 0x7f) << Shift;
        if ((Byte & 0x80) == 0) break;
        Shift += 7;
        if (Shift >= 64) break;
    }
    return Val;
}

int64_t SymbolResolver::ReadSleb128(const uint8_t*& Ptr, const uint8_t* End)
{
    int64_t Val = 0;
    int Shift = 0;
    uint8_t Byte = 0;
    while (Ptr < End) {
        Byte = *Ptr++;
        Val |= static_cast<int64_t>(Byte & 0x7f) << Shift;
        Shift += 7;
        if ((Byte & 0x80) == 0) break;
        if (Shift >= 64) break;
    }
    if (Shift < 64 && (Byte & 0x40)) {
        Val |= -(static_cast<int64_t>(1) << Shift);
    }
    return Val;
}

void SymbolResolver::SkipDwarfForm(uint16_t Form, const uint8_t*& Ptr, const uint8_t* End, uint8_t AddrSize)
{
    constexpr uint16_t DwFormAddr = 0x01;
    constexpr uint16_t DwFormBlock2 = 0x03;
    constexpr uint16_t DwFormBlock4 = 0x04;
    constexpr uint16_t DwFormData2 = 0x05;
    constexpr uint16_t DwFormData4 = 0x06;
    constexpr uint16_t DwFormData8 = 0x07;
    constexpr uint16_t DwFormString = 0x08;
    constexpr uint16_t DwFormBlock = 0x09;
    constexpr uint16_t DwFormBlock1 = 0x0a;
    constexpr uint16_t DwFormData1 = 0x0b;
    constexpr uint16_t DwFormFlag = 0x0c;
    constexpr uint16_t DwFormSdata = 0x0d;
    constexpr uint16_t DwFormStrp = 0x0e;
    constexpr uint16_t DwFormUdata = 0x0f;
    constexpr uint16_t DwFormRefAddr = 0x10;
    constexpr uint16_t DwFormRef1 = 0x11;
    constexpr uint16_t DwFormRef2 = 0x12;
    constexpr uint16_t DwFormRef4 = 0x13;
    constexpr uint16_t DwFormRef8 = 0x14;
    constexpr uint16_t DwFormRefUdata = 0x15;
    constexpr uint16_t DwFormIndirect = 0x16;
    constexpr uint16_t DwFormSecOffset = 0x17;
    constexpr uint16_t DwFormExprloc = 0x18;
    constexpr uint16_t DwFormFlagPresent = 0x19;
    constexpr uint16_t DwFormLineStrp = 0x1c;
    constexpr uint16_t DwFormStrx1 = 0x25;
    constexpr uint16_t DwFormStrx2 = 0x26;
    constexpr uint16_t DwFormStrx4 = 0x27;
    constexpr uint16_t DwFormAddrx1 = 0x29;
    constexpr uint16_t DwFormAddrx2 = 0x2a;
    constexpr uint16_t DwFormData16 = 0x1e;
    constexpr uint16_t DwFormRefSig8 = 0x20;
    constexpr uint16_t DwFormStrx = 0x1a;
    constexpr uint16_t DwFormAddrx = 0x1b;
    constexpr uint16_t DwFormLoclistx = 0x2c;
    constexpr uint16_t DwFormRnglistx = 0x23;
    constexpr uint16_t DwFormRefSup4 = 0x1c;
    constexpr uint16_t DwFormRefSup8 = 0x24;
    constexpr uint16_t DwFormImplicitConst = 0x21;

    switch (Form) {
    case DwFormAddr:
        Ptr += AddrSize;
        break;
    case DwFormData1:
    case DwFormRef1:
    case DwFormFlag:
    case DwFormStrx1:
    case DwFormAddrx1:
        Ptr += 1;
        break;
    case DwFormData2:
    case DwFormRef2:
    case DwFormStrx2:
    case DwFormAddrx2:
        Ptr += 2;
        break;
    case DwFormData4:
    case DwFormRef4:
    case DwFormStrx4:
        Ptr += 4;
        break;
    case DwFormData8:
    case DwFormRef8:
    case DwFormRefSig8:
    case DwFormRefSup8:
        Ptr += 8;
        break;
    case DwFormData16:
        Ptr += 16;
        break;
    case DwFormSdata:
        ReadSleb128(Ptr, End);
        break;
    case DwFormUdata:
    case DwFormRefUdata:
    case DwFormStrx:
    case DwFormAddrx:
    case DwFormLoclistx:
    case DwFormRnglistx:
        ReadUleb128(Ptr, End);
        break;
    case DwFormString:
        while (Ptr < End && *Ptr != 0) ++Ptr;
        if (Ptr < End) ++Ptr;
        break;
    case DwFormStrp:
    case DwFormSecOffset:
    case DwFormLineStrp:
    case DwFormRefAddr:
        Ptr += 4;
        break;
    case DwFormBlock1:
        if (Ptr < End) {
            uint8_t Len = *Ptr++;
            Ptr += Len;
        }
        break;
    case DwFormBlock2:
        if (Ptr + 2 <= End) {
            uint16_t Len;
            std::memcpy(&Len, Ptr, 2);
            Ptr += 2 + Len;
        }
        break;
    case DwFormBlock4:
        if (Ptr + 4 <= End) {
            uint32_t Len;
            std::memcpy(&Len, Ptr, 4);
            Ptr += 4 + Len;
        }
        break;
    case DwFormBlock:
    case DwFormExprloc: {
        uint64_t Len = ReadUleb128(Ptr, End);
        Ptr += Len;
        break;
    }
    case DwFormFlagPresent:
    case DwFormImplicitConst:
        break;
    case DwFormIndirect: {
        uint64_t RealForm = ReadUleb128(Ptr, End);
        SkipDwarfForm(static_cast<uint16_t>(RealForm), Ptr, End, AddrSize);
        break;
    }
    default:
        break;
    }

    if (Ptr > End) Ptr = End;
}

}
