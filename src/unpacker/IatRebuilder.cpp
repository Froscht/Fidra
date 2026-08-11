#include "IatRebuilder.h"
#include "PeParser.h"
#include <fidra/ICore.h>
#include <cstring>
#include <algorithm>

namespace Fidra {

IatRebuilder::IatRebuilder(PeParser* Parser)
    : ParserRef(Parser)
    , CoreRef(nullptr)
    , ExportMapBuilt(false)
{
}

IatRebuilder::~IatRebuilder() = default;

void IatRebuilder::SetCore(ICore* Core)
{
    CoreRef = Core;
}

void IatRebuilder::BuildModuleExportMap()
{
    if (!CoreRef)
        return;

    AddressToExport.clear();
    ModuleBaseMap.clear();

    auto Regions = CoreRef->GetMemoryRegions();

    QMap<QString, uint64_t> ProcessedModules;

    for (const auto& Region : Regions) {
        if (Region.ModuleName.isEmpty())
            continue;

        QString ModLower = Region.ModuleName.toLower();
        if (ProcessedModules.contains(ModLower))
            continue;

        ProcessedModules[ModLower] = Region.Base;
        ModuleBaseMap[ModLower] = Region.Base;

        uint8_t HeaderBuf[0x1000];
        if (!CoreRef->ReadMemory(Region.Base, HeaderBuf, sizeof(HeaderBuf)))
            continue;

        if (HeaderBuf[0] != 'M' || HeaderBuf[1] != 'Z')
            continue;

        uint32_t NtOffset = *reinterpret_cast<uint32_t*>(HeaderBuf + 0x3C);
        if (NtOffset + 0x18 + 0x70 + 8 * 16 > sizeof(HeaderBuf))
            continue;

        uint32_t NtSig = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset);
        if (NtSig != 0x00004550)
            continue;

        uint16_t OptMagic = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOffset + 0x18);
        uint32_t ExportDirRva = 0;
        uint32_t ExportDirSize = 0;

        if (OptMagic == 0x20B) {
            ExportDirRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x70);
            ExportDirSize = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x74);
        } else if (OptMagic == 0x10B) {
            ExportDirRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x60);
            ExportDirSize = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x64);
        } else {
            continue;
        }

        if (ExportDirRva == 0 || ExportDirSize == 0)
            continue;

        QByteArray ExportBuf(ExportDirSize + 0x1000, 0);
        if (!CoreRef->ReadMemory(Region.Base + ExportDirRva, ExportBuf.data(), ExportBuf.size()))
            continue;

        uint32_t OrdinalBase = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x10);
        uint32_t NumberOfFunctions = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x14);
        uint32_t NumberOfNames = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x18);
        uint32_t AddressOfFunctionsRva = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x1C);
        uint32_t AddressOfNamesRva = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x20);
        uint32_t AddressOfOrdinalsRva = *reinterpret_cast<uint32_t*>(ExportBuf.data() + 0x24);

        if (NumberOfFunctions > 0x10000)
            continue;

        QByteArray FuncAddrs(NumberOfFunctions * 4, 0);
        if (!CoreRef->ReadMemory(Region.Base + AddressOfFunctionsRva, FuncAddrs.data(), FuncAddrs.size()))
            continue;

        QByteArray NameAddrs(NumberOfNames * 4, 0);
        QByteArray OrdinalAddrs(NumberOfNames * 2, 0);

        if (NumberOfNames > 0) {
            CoreRef->ReadMemory(Region.Base + AddressOfNamesRva, NameAddrs.data(), NameAddrs.size());
            CoreRef->ReadMemory(Region.Base + AddressOfOrdinalsRva, OrdinalAddrs.data(), OrdinalAddrs.size());
        }

        QMap<uint16_t, QString> OrdinalToName;
        for (uint32_t I = 0; I < NumberOfNames; ++I) {
            uint32_t NameRva = *reinterpret_cast<uint32_t*>(NameAddrs.data() + I * 4);
            uint16_t OrdIdx = *reinterpret_cast<uint16_t*>(OrdinalAddrs.data() + I * 2);

            char NameBuf[512] = {};
            if (CoreRef->ReadMemory(Region.Base + NameRva, NameBuf, sizeof(NameBuf) - 1)) {
                OrdinalToName[OrdIdx] = QString::fromLatin1(NameBuf);
            }
        }

        for (uint32_t I = 0; I < NumberOfFunctions; ++I) {
            uint32_t FuncRva = *reinterpret_cast<uint32_t*>(FuncAddrs.data() + I * 4);
            if (FuncRva == 0)
                continue;

            if (FuncRva >= ExportDirRva && FuncRva < ExportDirRva + ExportDirSize)
                continue;

            ModuleExport Export;
            Export.Ordinal = static_cast<uint16_t>(OrdinalBase + I);
            Export.Rva = FuncRva;

            if (OrdinalToName.contains(static_cast<uint16_t>(I))) {
                Export.FunctionName = OrdinalToName[static_cast<uint16_t>(I)];
            } else {
                Export.FunctionName = QString("Ordinal_%1").arg(Export.Ordinal);
            }

            uint64_t AbsAddr = Region.Base + FuncRva;
            AddressToExport[AbsAddr] = Export;
        }
    }

    ExportMapBuilt = true;
}

bool IatRebuilder::IsExecutableRegion(uint64_t Address)
{
    if (!CoreRef)
        return false;

    auto Regions = CoreRef->GetMemoryRegions();
    for (const auto& Region : Regions) {
        if (Address >= Region.Base && Address < Region.Base + Region.Size) {
            return (Region.Protection & 0xF0) != 0;
        }
    }
    return false;
}

bool IatRebuilder::IsApiAddress(uint64_t Address, const QList<MemoryRegion>& Regions)
{
    for (const auto& Region : Regions) {
        if (Address >= Region.Base && Address < Region.Base + Region.Size) {
            return !Region.ModuleName.isEmpty();
        }
    }
    return false;
}

uint32_t IatRebuilder::RvaToOffset(uint32_t Rva, const QByteArray& PeData)
{
    if (PeData.size() < 0x40)
        return 0;

    const uint8_t* Data = reinterpret_cast<const uint8_t*>(PeData.constData());
    uint32_t NtOffset = *reinterpret_cast<const uint32_t*>(Data + 0x3C);

    if (NtOffset + 6 > static_cast<uint32_t>(PeData.size()))
        return 0;

    uint16_t NumberOfSections = *reinterpret_cast<const uint16_t*>(Data + NtOffset + 0x06);
    uint16_t SizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(Data + NtOffset + 0x14);

    uint32_t SectionStart = NtOffset + 0x18 + SizeOfOptionalHeader;

    for (uint16_t I = 0; I < NumberOfSections; ++I) {
        uint32_t SecOff = SectionStart + I * 40;
        if (SecOff + 40 > static_cast<uint32_t>(PeData.size()))
            break;

        uint32_t VirtualAddress = *reinterpret_cast<const uint32_t*>(Data + SecOff + 12);
        uint32_t VirtualSize = *reinterpret_cast<const uint32_t*>(Data + SecOff + 8);
        uint32_t RawOffset = *reinterpret_cast<const uint32_t*>(Data + SecOff + 20);

        if (Rva >= VirtualAddress && Rva < VirtualAddress + VirtualSize) {
            return Rva - VirtualAddress + RawOffset;
        }
    }

    return Rva;
}

bool IatRebuilder::ResolveAddress(uint64_t Address, QString& ModuleName, QString& FunctionName)
{
    if (!ExportMapBuilt)
        BuildModuleExportMap();

    auto It = AddressToExport.find(Address);
    if (It != AddressToExport.end()) {
        FunctionName = It.value().FunctionName;

        for (auto MapIt = ModuleBaseMap.begin(); MapIt != ModuleBaseMap.end(); ++MapIt) {
            uint64_t Base = MapIt.value();
            if (Address >= Base && Address < Base + 0x10000000) {
                ModuleName = MapIt.key();
                return true;
            }
        }

        ModuleName = "unknown";
        return true;
    }

    if (!CoreRef)
        return false;

    auto Regions = CoreRef->GetMemoryRegions();
    for (const auto& Region : Regions) {
        if (Address >= Region.Base && Address < Region.Base + Region.Size) {
            if (!Region.ModuleName.isEmpty()) {
                ModuleName = Region.ModuleName.toLower();
                FunctionName = QString("sub_%1").arg(Address - Region.Base, 0, 16);
                return true;
            }
        }
    }

    return false;
}

IatFixupResult IatRebuilder::ScanAndRebuild(uint64_t BaseAddress)
{
    IatFixupResult Result;
    Result.TotalEntries = 0;
    Result.ResolvedEntries = 0;
    Result.FailedEntries = 0;
    Result.Success = false;

    if (!CoreRef) {
        Result.ErrorMessage = "No core interface set";
        return Result;
    }

    if (!ExportMapBuilt)
        BuildModuleExportMap();

    uint8_t HeaderBuf[0x1000];
    if (!CoreRef->ReadMemory(BaseAddress, HeaderBuf, sizeof(HeaderBuf))) {
        Result.ErrorMessage = "Failed to read PE header from memory";
        return Result;
    }

    if (HeaderBuf[0] != 'M' || HeaderBuf[1] != 'Z') {
        Result.ErrorMessage = "Invalid DOS signature";
        return Result;
    }

    uint32_t NtOffset = *reinterpret_cast<uint32_t*>(HeaderBuf + 0x3C);
    uint16_t OptMagic = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOffset + 0x18);
    bool Is64 = (OptMagic == 0x20B);

    uint32_t IatRva = 0;
    uint32_t IatSize = 0;

    if (Is64) {
        IatRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x70 + 12 * 8);
        IatSize = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x70 + 12 * 8 + 4);
    } else {
        IatRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x60 + 12 * 8);
        IatSize = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x60 + 12 * 8 + 4);
    }

    if (IatRva == 0 || IatSize == 0) {
        uint32_t ImportRva = 0;
        if (Is64) {
            ImportRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x70 + 1 * 8);
        } else {
            ImportRva = *reinterpret_cast<uint32_t*>(HeaderBuf + NtOffset + 0x18 + 0x60 + 1 * 8);
        }

        if (ImportRva == 0) {
            Result.ErrorMessage = "No IAT or import directory found";
            return Result;
        }

        IatRva = ImportRva;
        IatSize = 0x10000;
    }

    uint32_t ReadSize = (IatSize > 0 && IatSize < 0x100000) ? IatSize : 0x10000;
    QByteArray IatData(ReadSize, 0);
    if (!CoreRef->ReadMemory(BaseAddress + IatRva, IatData.data(), ReadSize)) {
        Result.ErrorMessage = "Failed to read IAT from memory";
        return Result;
    }

    uint32_t EntrySize = Is64 ? 8 : 4;
    uint32_t NumEntries = ReadSize / EntrySize;
    int ConsecutiveZeros = 0;

    for (uint32_t I = 0; I < NumEntries; ++I) {
        uint64_t Entry = 0;
        if (Is64) {
            Entry = *reinterpret_cast<uint64_t*>(IatData.data() + I * EntrySize);
        } else {
            Entry = *reinterpret_cast<uint32_t*>(IatData.data() + I * EntrySize);
        }

        if (Entry == 0) {
            ConsecutiveZeros++;
            if (ConsecutiveZeros >= 2)
                break;
            continue;
        }
        ConsecutiveZeros = 0;

        Result.TotalEntries++;
        ResolvedImport Import;
        Import.IatAddress = BaseAddress + IatRva + I * EntrySize;
        Import.ResolvedAddress = Entry;
        Import.Ordinal = 0;
        Import.IsOrdinal = false;
        Import.IsValid = false;

        QString ModName, FuncName;
        if (ResolveAddress(Entry, ModName, FuncName)) {
            Import.ModuleName = ModName;
            Import.FunctionName = FuncName;
            Import.IsValid = true;
            Result.ResolvedEntries++;
        } else {
            Import.ModuleName = "unresolved";
            Import.FunctionName = QString("0x%1").arg(Entry, 0, 16);
            Result.FailedEntries++;
        }

        Result.Imports.append(Import);
    }

    Result.RebuiltData = BuildImportDirectory(Result.Imports);
    Result.Success = Result.ResolvedEntries > 0;

    return Result;
}

IatFixupResult IatRebuilder::RebuildFromMemory(uint64_t BaseAddress)
{
    IatFixupResult Result = ScanAndRebuild(BaseAddress);

    if (!CoreRef)
        return Result;

    uint8_t HeaderBuf[0x1000];
    if (!CoreRef->ReadMemory(BaseAddress, HeaderBuf, sizeof(HeaderBuf)))
        return Result;

    uint32_t NtOffset = *reinterpret_cast<uint32_t*>(HeaderBuf + 0x3C);
    uint16_t OptMagic = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOffset + 0x18);
    bool Is64 = (OptMagic == 0x20B);

    uint16_t NumberOfSections = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOffset + 0x06);
    uint16_t SizeOfOptionalHeader = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOffset + 0x14);
    uint32_t SectionStart = NtOffset + 0x18 + SizeOfOptionalHeader;

    auto Regions = CoreRef->GetMemoryRegions();
    QSet<uint64_t> SeenAddresses;
    for (const auto& Imp : Result.Imports)
        SeenAddresses.insert(Imp.IatAddress);

    for (uint16_t S = 0; S < NumberOfSections; ++S) {
        uint32_t SecOff = SectionStart + S * 40;
        if (SecOff + 40 > sizeof(HeaderBuf))
            break;

        uint32_t SecChars = *reinterpret_cast<uint32_t*>(HeaderBuf + SecOff + 36);
        if (!(SecChars & 0x20000000))
            continue;

        uint32_t SecVa = *reinterpret_cast<uint32_t*>(HeaderBuf + SecOff + 12);
        uint32_t SecVSize = *reinterpret_cast<uint32_t*>(HeaderBuf + SecOff + 8);

        if (SecVSize > 0x10000000 || SecVSize == 0)
            continue;

        const uint32_t ChunkSize = 0x10000;
        for (uint32_t Off = 0; Off < SecVSize; Off += ChunkSize) {
            uint32_t ReadLen = std::min(ChunkSize, SecVSize - Off);
            QByteArray CodeBuf(ReadLen, 0);
            if (!CoreRef->ReadMemory(BaseAddress + SecVa + Off, CodeBuf.data(), ReadLen))
                continue;

            const uint8_t* Code = reinterpret_cast<const uint8_t*>(CodeBuf.constData());

            for (uint32_t I = 0; I + 6 <= ReadLen; ++I) {
                if (Code[I] != 0xFF)
                    continue;
                if (Code[I + 1] != 0x15 && Code[I + 1] != 0x25)
                    continue;

                uint64_t TargetAddr = 0;

                if (Is64) {
                    int32_t Disp = *reinterpret_cast<const int32_t*>(Code + I + 2);
                    uint64_t InstrAddr = BaseAddress + SecVa + Off + I;
                    TargetAddr = InstrAddr + 6 + Disp;
                } else {
                    TargetAddr = *reinterpret_cast<const uint32_t*>(Code + I + 2);
                }

                if (SeenAddresses.contains(TargetAddr))
                    continue;

                uint64_t PointerValue = 0;
                if (Is64) {
                    if (!CoreRef->ReadMemory(TargetAddr, &PointerValue, 8))
                        continue;
                } else {
                    uint32_t Tmp = 0;
                    if (!CoreRef->ReadMemory(TargetAddr, &Tmp, 4))
                        continue;
                    PointerValue = Tmp;
                }

                if (!IsApiAddress(PointerValue, Regions))
                    continue;

                SeenAddresses.insert(TargetAddr);

                ResolvedImport Import;
                Import.IatAddress = TargetAddr;
                Import.ResolvedAddress = PointerValue;
                Import.Ordinal = 0;
                Import.IsOrdinal = false;
                Import.IsValid = false;

                QString ModName, FuncName;
                if (ResolveAddress(PointerValue, ModName, FuncName)) {
                    Import.ModuleName = ModName;
                    Import.FunctionName = FuncName;
                    Import.IsValid = true;
                    Result.ResolvedEntries++;
                } else {
                    Import.ModuleName = "unresolved";
                    Import.FunctionName = QString("0x%1").arg(PointerValue, 0, 16);
                    Result.FailedEntries++;
                }

                Result.TotalEntries++;
                Result.Imports.append(Import);
            }
        }
    }

    Result.RebuiltData = BuildImportDirectory(Result.Imports);
    Result.Success = Result.ResolvedEntries > 0;
    return Result;
}

QList<ResolvedImport> IatRebuilder::ScanForApiCalls(uint64_t BaseAddress, uint64_t Size)
{
    QList<ResolvedImport> Results;

    if (!CoreRef)
        return Results;

    if (!ExportMapBuilt)
        BuildModuleExportMap();

    auto Regions = CoreRef->GetMemoryRegions();

    bool Is64 = true;
    uint8_t HeaderBuf[0x200];
    if (CoreRef->ReadMemory(BaseAddress, HeaderBuf, sizeof(HeaderBuf))) {
        if (HeaderBuf[0] == 'M' && HeaderBuf[1] == 'Z') {
            uint32_t NtOff = *reinterpret_cast<uint32_t*>(HeaderBuf + 0x3C);
            if (NtOff + 0x18 < sizeof(HeaderBuf)) {
                uint16_t Magic = *reinterpret_cast<uint16_t*>(HeaderBuf + NtOff + 0x18);
                Is64 = (Magic == 0x20B);
            }
        }
    }

    QSet<uint64_t> SeenTargets;
    const uint32_t ChunkSize = 0x10000;

    for (uint64_t Off = 0; Off < Size; Off += ChunkSize) {
        uint32_t ReadLen = static_cast<uint32_t>(std::min(static_cast<uint64_t>(ChunkSize), Size - Off));
        QByteArray Buf(ReadLen, 0);
        if (!CoreRef->ReadMemory(BaseAddress + Off, Buf.data(), ReadLen))
            continue;

        const uint8_t* Code = reinterpret_cast<const uint8_t*>(Buf.constData());

        for (uint32_t I = 0; I + 6 <= ReadLen; ++I) {
            if (Code[I] != 0xFF)
                continue;
            if (Code[I + 1] != 0x15 && Code[I + 1] != 0x25)
                continue;

            uint64_t TargetAddr = 0;

            if (Is64) {
                int32_t Disp = *reinterpret_cast<const int32_t*>(Code + I + 2);
                uint64_t InstrAddr = BaseAddress + Off + I;
                TargetAddr = InstrAddr + 6 + Disp;
            } else {
                TargetAddr = *reinterpret_cast<const uint32_t*>(Code + I + 2);
            }

            if (SeenTargets.contains(TargetAddr))
                continue;
            SeenTargets.insert(TargetAddr);

            uint64_t PointerValue = 0;
            if (Is64) {
                if (!CoreRef->ReadMemory(TargetAddr, &PointerValue, 8))
                    continue;
            } else {
                uint32_t Tmp = 0;
                if (!CoreRef->ReadMemory(TargetAddr, &Tmp, 4))
                    continue;
                PointerValue = Tmp;
            }

            if (!IsApiAddress(PointerValue, Regions))
                continue;

            ResolvedImport Import;
            Import.IatAddress = TargetAddr;
            Import.ResolvedAddress = PointerValue;
            Import.Ordinal = 0;
            Import.IsOrdinal = false;
            Import.IsValid = false;

            QString ModName, FuncName;
            if (ResolveAddress(PointerValue, ModName, FuncName)) {
                Import.ModuleName = ModName;
                Import.FunctionName = FuncName;
                Import.IsValid = true;
            } else {
                Import.ModuleName = "unresolved";
                Import.FunctionName = QString("0x%1").arg(PointerValue, 0, 16);
            }

            Results.append(Import);
        }
    }

    return Results;
}

QByteArray IatRebuilder::BuildImportDirectory(const QList<ResolvedImport>& Imports)
{
    QMap<QString, QList<const ResolvedImport*>> GroupedByModule;

    for (const auto& Imp : Imports) {
        if (!Imp.IsValid)
            continue;
        GroupedByModule[Imp.ModuleName].append(&Imp);
    }

    if (GroupedByModule.isEmpty())
        return {};

    int NumDescriptors = GroupedByModule.size() + 1;
    uint32_t DescriptorsSize = NumDescriptors * 20;

    uint32_t IltStart = DescriptorsSize;
    uint32_t TotalIltEntries = 0;
    for (auto It = GroupedByModule.begin(); It != GroupedByModule.end(); ++It) {
        TotalIltEntries += It.value().size() + 1;
    }
    uint32_t IltSize = TotalIltEntries * 8;

    uint32_t IatStart = IltStart + IltSize;
    uint32_t IatSize = IltSize;

    uint32_t HintNameStart = IatStart + IatSize;
    uint32_t HintNameOffset = HintNameStart;

    QMap<QString, uint32_t> DllNameOffsets;
    QMap<QString, QList<uint32_t>> FuncHintOffsets;

    for (auto It = GroupedByModule.begin(); It != GroupedByModule.end(); ++It) {
        DllNameOffsets[It.key()] = HintNameOffset;
        QByteArray DllName = It.key().toLatin1();
        HintNameOffset += DllName.size() + 1;
        if (HintNameOffset & 1)
            HintNameOffset++;

        QList<uint32_t> Offsets;
        for (const auto* Imp : It.value()) {
            Offsets.append(HintNameOffset);
            QByteArray FuncName = Imp->FunctionName.toLatin1();
            HintNameOffset += 2 + FuncName.size() + 1;
            if (HintNameOffset & 1)
                HintNameOffset++;
        }
        FuncHintOffsets[It.key()] = Offsets;
    }

    uint32_t TotalSize = HintNameOffset;
    QByteArray Result(TotalSize, 0);
    uint8_t* Out = reinterpret_cast<uint8_t*>(Result.data());

    uint32_t DescIdx = 0;
    uint32_t IltIdx = 0;
    uint32_t IatIdx = 0;

    for (auto It = GroupedByModule.begin(); It != GroupedByModule.end(); ++It) {
        uint32_t DescOff = DescIdx * 20;

        uint32_t ThisIltRva = IltStart + IltIdx * 8;
        uint32_t ThisIatRva = IatStart + IatIdx * 8;
        uint32_t DllNameRva = DllNameOffsets[It.key()];

        *reinterpret_cast<uint32_t*>(Out + DescOff + 0) = ThisIltRva;
        *reinterpret_cast<uint32_t*>(Out + DescOff + 4) = 0;
        *reinterpret_cast<uint32_t*>(Out + DescOff + 8) = 0;
        *reinterpret_cast<uint32_t*>(Out + DescOff + 12) = DllNameRva;
        *reinterpret_cast<uint32_t*>(Out + DescOff + 16) = ThisIatRva;

        QByteArray DllName = It.key().toLatin1();
        std::memcpy(Out + DllNameRva, DllName.constData(), DllName.size());

        const auto& FuncOffsets = FuncHintOffsets[It.key()];
        const auto& FuncList = It.value();

        for (int F = 0; F < FuncList.size(); ++F) {
            uint64_t HintNameRva = FuncOffsets[F];

            *reinterpret_cast<uint64_t*>(Out + IltStart + IltIdx * 8) = HintNameRva;
            *reinterpret_cast<uint64_t*>(Out + IatStart + IatIdx * 8) = HintNameRva;

            *reinterpret_cast<uint16_t*>(Out + HintNameRva) = FuncList[F]->Ordinal;
            QByteArray FuncName = FuncList[F]->FunctionName.toLatin1();
            std::memcpy(Out + HintNameRva + 2, FuncName.constData(), FuncName.size());

            IltIdx++;
            IatIdx++;
        }

        *reinterpret_cast<uint64_t*>(Out + IltStart + IltIdx * 8) = 0;
        *reinterpret_cast<uint64_t*>(Out + IatStart + IatIdx * 8) = 0;
        IltIdx++;
        IatIdx++;

        DescIdx++;
    }

    std::memset(Out + DescIdx * 20, 0, 20);

    return Result;
}

bool IatRebuilder::FixSectionPermissions(QByteArray& PeData)
{
    if (PeData.size() < 0x40)
        return false;

    uint8_t* Data = reinterpret_cast<uint8_t*>(PeData.data());

    if (Data[0] != 'M' || Data[1] != 'Z')
        return false;

    uint32_t NtOffset = *reinterpret_cast<uint32_t*>(Data + 0x3C);
    if (NtOffset + 0x18 > static_cast<uint32_t>(PeData.size()))
        return false;

    uint32_t NtSig = *reinterpret_cast<uint32_t*>(Data + NtOffset);
    if (NtSig != 0x00004550)
        return false;

    uint16_t NumberOfSections = *reinterpret_cast<uint16_t*>(Data + NtOffset + 0x06);
    uint16_t SizeOfOptionalHeader = *reinterpret_cast<uint16_t*>(Data + NtOffset + 0x14);

    uint32_t SectionStart = NtOffset + 0x18 + SizeOfOptionalHeader;

    const uint32_t ScnMemExecute = 0x20000000;
    const uint32_t ScnMemRead    = 0x40000000;
    const uint32_t ScnMemWrite   = 0x80000000;
    const uint32_t ScnCntCode    = 0x00000020;

    for (uint16_t I = 0; I < NumberOfSections; ++I) {
        uint32_t SecOff = SectionStart + I * 40;
        if (SecOff + 40 > static_cast<uint32_t>(PeData.size()))
            break;

        char Name[9] = {};
        std::memcpy(Name, Data + SecOff, 8);
        QString SecName = QString::fromLatin1(Name).trimmed().toLower();

        uint32_t* Characteristics = reinterpret_cast<uint32_t*>(Data + SecOff + 36);

        if (SecName == ".text" || SecName == "code" || (*Characteristics & ScnCntCode)) {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemExecute | ScnMemRead | ScnCntCode;
        } else if (SecName == ".rdata" || SecName == ".rodata") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead;
        } else if (SecName == ".data" || SecName == ".bss") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead | ScnMemWrite;
        } else if (SecName == ".idata" || SecName == ".didat") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead | ScnMemWrite;
        } else if (SecName == ".rsrc") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead;
        } else if (SecName == ".reloc") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead;
        } else if (SecName == ".edata") {
            *Characteristics = (*Characteristics & ~(ScnMemRead | ScnMemWrite | ScnMemExecute))
                             | ScnMemRead;
        }
    }

    return true;
}

void IatRebuilder::SetModuleMap(const QMap<QString, uint64_t>& Map)
{
    ModuleBaseMap = Map;
    ExportMapBuilt = false;
}

}
