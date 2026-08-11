#include "ProcessDumper.h"

#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QThread>
#include <QDir>
#include <QSet>
#include <QMap>
#include <QRegularExpression>

#include <cmath>
#include <cstring>

#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#endif

namespace Fidra {

ProcessDumper::ProcessDumper(QObject* Parent)
    : QObject(Parent)
    , AttachedPid(0)
    , MemFd(-1)
    , Cancelled(0)
    , ScatterGatherEnabled(true)
{
}

ProcessDumper::~ProcessDumper() {
    Detach();
}

bool ProcessDumper::AttachToProcess(uint32_t Pid) {
#ifdef __linux__
    Detach();

    QString MemPath = QString("/proc/%1/mem").arg(Pid);
    int Fd = ::open(MemPath.toUtf8().constData(), O_RDONLY);
    if (Fd < 0) {
        emit LogMessage(QString("Failed to open %1").arg(MemPath));
        return false;
    }

    QString CommPath = QString("/proc/%1/comm").arg(Pid);
    QFile CommFile(CommPath);
    if (!CommFile.open(QIODevice::ReadOnly)) {
        ::close(Fd);
        emit LogMessage(QString("Process %1 does not exist").arg(Pid));
        return false;
    }
    CommFile.close();

    MemFd = Fd;
    AttachedPid = Pid;
    Cancelled.storeRelaxed(0);

    emit LogMessage(QString("Attached to PID %1").arg(Pid));
    return true;
#else
    Q_UNUSED(Pid);
    emit LogMessage("Live dump only supported on Linux");
    return false;
#endif
}

void ProcessDumper::Detach() {
#ifdef __linux__
    if (MemFd >= 0) {
        ::close(MemFd);
        MemFd = -1;
    }
#endif
    AttachedPid = 0;
}

bool ProcessDumper::IsAttached() const {
    return AttachedPid != 0 && MemFd >= 0;
}

QVector<ModuleInfo> ProcessDumper::EnumerateModules() {
    QVector<ModuleInfo> Modules;
#ifdef __linux__
    if (!IsAttached()) return Modules;

    QString MapsPath = QString("/proc/%1/maps").arg(AttachedPid);
    QFile MapsFile(MapsPath);
    if (!MapsFile.open(QIODevice::ReadOnly | QIODevice::Text))
        return Modules;

    QMap<QString, Address> LowestBase;
    QMap<QString, Address> HighestEnd;

    while (!MapsFile.atEnd()) {
        QString Line = QString::fromUtf8(MapsFile.readLine()).trimmed();
        QStringList Parts = Line.split(QRegularExpression("\\s+"));
        if (Parts.size() < 6) continue;

        QString Path = Parts.last();
        if (Path.startsWith('[') || Path.isEmpty()) continue;
        if (Path.contains("memfd:")) continue;

        QStringList AddrParts = Parts[0].split('-');
        if (AddrParts.size() != 2) continue;

        bool OkLo = false, OkHi = false;
        Address Lo = AddrParts[0].toULongLong(&OkLo, 16);
        Address Hi = AddrParts[1].toULongLong(&OkHi, 16);
        if (!OkLo || !OkHi) continue;

        if (!LowestBase.contains(Path) || Lo < LowestBase[Path]) {
            LowestBase[Path] = Lo;
        }
        if (!HighestEnd.contains(Path) || Hi > HighestEnd[Path]) {
            HighestEnd[Path] = Hi;
        }
    }
    MapsFile.close();

    for (auto It = LowestBase.constBegin(); It != LowestBase.constEnd(); ++It) {
        QString Path = It.key();
        Address Base = It.value();
        Address End = HighestEnd.value(Path, Base);

        ModuleInfo Info;
        Info.Path = Path;
        Info.Name = QFileInfo(Path).fileName();
        Info.Base = Base;
        Info.Size = End - Base;
        Info.IsMainModule = false;

        uint8_t Header[0x1000];
        memset(Header, 0, sizeof(Header));
        if (ReadProcessMemory(Base, Header, sizeof(Header))) {
            if (Header[0] == 'M' && Header[1] == 'Z') {
                uint32_t LfaNew = 0;
                memcpy(&LfaNew, Header + 0x3C, 4);
                if (LfaNew + 0x60 <= sizeof(Header) &&
                    Header[LfaNew] == 'P' && Header[LfaNew + 1] == 'E' &&
                    Header[LfaNew + 2] == 0 && Header[LfaNew + 3] == 0) {
                    uint32_t SizeOfImage = 0;
                    memcpy(&SizeOfImage, Header + LfaNew + 0x50, 4);
                    if (SizeOfImage > 0 && SizeOfImage <= 0x40000000) {
                        Info.Size = SizeOfImage;
                    }
                }
                QString NameLower = Info.Name.toLower();
                if (NameLower.endsWith(".exe")) {
                    Info.IsMainModule = true;
                }
            } else if (Header[0] == 0x7F && Header[1] == 'E' &&
                       Header[2] == 'L' && Header[3] == 'F') {
                uint8_t EiClass = Header[4];
                if (EiClass == 2) {
                    uint64_t ElfSize = 0;
                    memcpy(&ElfSize, Header + 0x28, 8);
                }
                if (Info.Name == QFileInfo(QString("/proc/%1/exe").arg(AttachedPid)).symLinkTarget().section('/', -1)) {
                    Info.IsMainModule = true;
                }
            }
        }

        Modules.append(Info);
    }

    std::sort(Modules.begin(), Modules.end(), [](const ModuleInfo& A, const ModuleInfo& B) {
        if (A.IsMainModule != B.IsMainModule) return A.IsMainModule > B.IsMainModule;
        return A.Name.toLower() < B.Name.toLower();
    });
#endif
    return Modules;
}

ProcessDumper::PageClassification ProcessDumper::ClassifyPage(const uint8_t* Data, int Size) {
    if (Size < 64)
        return PageClassification::Clean;

    int CcCount = 0;
    for (int I = 0; I < 64; ++I) {
        if (Data[I] == 0xCC)
            ++CcCount;
    }
    if (CcCount > EncryptCcThreshold)
        return PageClassification::CcSentinel;

    double Entropy = CalculateEntropy(Data, Size);
    if (Entropy >= CiphertextEntropy)
        return PageClassification::Ciphertext;

    return PageClassification::Clean;
}

double ProcessDumper::CalculateEntropy(const uint8_t* Data, int Size) {
    if (Size <= 0) return 0.0;

    int Histogram[256];
    memset(Histogram, 0, sizeof(Histogram));

    for (int I = 0; I < Size; ++I) {
        ++Histogram[Data[I]];
    }

    double Entropy = 0.0;
    double Total = static_cast<double>(Size);

    for (int I = 0; I < 256; ++I) {
        if (Histogram[I] == 0) continue;
        double P = static_cast<double>(Histogram[I]) / Total;
        Entropy -= P * std::log2(P);
    }

    return Entropy;
}

bool ProcessDumper::ReadProcessPage(Address Addr, void* Buffer) {
#ifdef __linux__
    if (MemFd < 0) return false;
    ssize_t BytesRead = ::pread(MemFd, Buffer, PageSize, static_cast<off_t>(Addr));
    return BytesRead == PageSize;
#else
    Q_UNUSED(Addr); Q_UNUSED(Buffer);
    return false;
#endif
}

bool ProcessDumper::ReadProcessMemory(Address Addr, void* Buffer, size_t Size) {
#ifdef __linux__
    if (MemFd < 0) return false;
    size_t TotalRead = 0;
    auto* Ptr = static_cast<uint8_t*>(Buffer);

    while (TotalRead < Size) {
        size_t ChunkSize = std::min(Size - TotalRead, static_cast<size_t>(4 * 1024 * 1024));
        ssize_t BytesRead = ::pread(MemFd, Ptr + TotalRead, ChunkSize,
                                     static_cast<off_t>(Addr + TotalRead));
        if (BytesRead <= 0) {
            if (TotalRead == 0) return false;
            break;
        }
        TotalRead += static_cast<size_t>(BytesRead);
    }
    return TotalRead == Size;
#else
    Q_UNUSED(Addr); Q_UNUSED(Buffer); Q_UNUSED(Size);
    return false;
#endif
}

PeFixupInfo ProcessDumper::ParsePeHeader(const uint8_t* Data, size_t Size) {
    PeFixupInfo Info = {};
    if (Size < 0x40 || Data[0] != 'M' || Data[1] != 'Z')
        return Info;

    uint32_t LfaNew = 0;
    memcpy(&LfaNew, Data + 0x3C, 4);
    if (LfaNew + 0x60 > Size)
        return Info;
    if (Data[LfaNew] != 'P' || Data[LfaNew + 1] != 'E' ||
        Data[LfaNew + 2] != 0 || Data[LfaNew + 3] != 0)
        return Info;

    memcpy(&Info.TimeDateStamp, Data + LfaNew + 8, 4);
    memcpy(&Info.NumberOfSections, Data + LfaNew + 6, 2);
    memcpy(&Info.SizeOfImage, Data + LfaNew + 0x50, 4);

    uint16_t Magic = 0;
    memcpy(&Magic, Data + LfaNew + 0x18, 2);
    if (Magic == 0x020B) {
        memcpy(&Info.OriginalBase, Data + LfaNew + 0x30, 8);
    } else if (Magic == 0x010B) {
        uint32_t Base32 = 0;
        memcpy(&Base32, Data + LfaNew + 0x34, 4);
        Info.OriginalBase = Base32;
    }

    return Info;
}

QByteArray ProcessDumper::FixPeForAnalysis(QByteArray& Buffer, Address ImageBase) {
    auto* Buf = reinterpret_cast<uint8_t*>(Buffer.data());
    size_t BufSize = static_cast<size_t>(Buffer.size());

    if (BufSize < 0x40 || Buf[0] != 'M' || Buf[1] != 'Z')
        return Buffer;

    uint32_t LfaNew = 0;
    memcpy(&LfaNew, Buf + 0x3C, 4);
    if (LfaNew + 0x60 > BufSize)
        return Buffer;
    if (Buf[LfaNew] != 'P' || Buf[LfaNew + 1] != 'E' ||
        Buf[LfaNew + 2] != 0 || Buf[LfaNew + 3] != 0)
        return Buffer;

    uint16_t NumSections = 0;
    memcpy(&NumSections, Buf + LfaNew + 6, 2);

    uint32_t OptHeaderOff = LfaNew + 24;
    uint16_t Magic = 0;
    memcpy(&Magic, Buf + OptHeaderOff, 2);

    if (Magic == 0x020B) {
        uint64_t NewBase = ImageBase;
        memcpy(Buf + OptHeaderOff + 24, &NewBase, 8);
    } else if (Magic == 0x010B) {
        uint32_t NewBase = static_cast<uint32_t>(ImageBase);
        memcpy(Buf + OptHeaderOff + 28, &NewBase, 4);
    }

    uint32_t NewSizeOfImage = static_cast<uint32_t>(BufSize);
    memcpy(Buf + OptHeaderOff + 56, &NewSizeOfImage, 4);

    uint16_t SizeOfOptHeader = 0;
    memcpy(&SizeOfOptHeader, Buf + LfaNew + 4 + 16, 2);
    uint32_t SectionHeaderOff = OptHeaderOff + SizeOfOptHeader;

    uint32_t FileAlignment = 0;
    memcpy(&FileAlignment, Buf + OptHeaderOff + 36, 4);
    if (FileAlignment == 0) FileAlignment = 512;

    for (int Si = 0; Si < NumSections; ++Si) {
        uint32_t ShOff = SectionHeaderOff + Si * 40;
        if (ShOff + 40 > BufSize) break;

        char SectionName[9] = {};
        memcpy(SectionName, Buf + ShOff, 8);

        uint32_t VirtualSize = 0;
        memcpy(&VirtualSize, Buf + ShOff + 8, 4);

        uint32_t VirtualAddress = 0;
        memcpy(&VirtualAddress, Buf + ShOff + 12, 4);

        uint32_t RawSize = (VirtualSize + FileAlignment - 1) & ~(FileAlignment - 1);
        memcpy(Buf + ShOff + 16, &RawSize, 4);
        memcpy(Buf + ShOff + 20, &VirtualAddress, 4);

        if (strstr(SectionName, ".text")) {
            uint32_t Chars = 0x60000020;
            memcpy(Buf + ShOff + 36, &Chars, 4);
        } else if (strstr(SectionName, ".data")) {
            uint32_t Chars = 0xC0000040;
            memcpy(Buf + ShOff + 36, &Chars, 4);
        }
    }

    return Buffer;
}

QVector<ProcessDumper::ReadableRange> ProcessDumper::GetReadableRanges(Address ImageBase, uint64_t ImageSize) {
    QVector<ReadableRange> Ranges;
#ifdef __linux__
    if (!IsAttached()) return Ranges;

    Address ImageEnd = ImageBase + ImageSize;

    QString MapsPath = QString("/proc/%1/maps").arg(AttachedPid);
    QFile MapsFile(MapsPath);
    if (!MapsFile.open(QIODevice::ReadOnly | QIODevice::Text))
        return Ranges;

    while (!MapsFile.atEnd()) {
        QString Line = QString::fromUtf8(MapsFile.readLine()).trimmed();
        QStringList Parts = Line.split(QRegularExpression("\\s+"));
        if (Parts.size() < 2) continue;

        QString Perms = Parts[1];
        if (!Perms.contains('r')) continue;

        QStringList AddrParts = Parts[0].split('-');
        if (AddrParts.size() != 2) continue;

        bool OkLo = false, OkHi = false;
        Address Lo = AddrParts[0].toULongLong(&OkLo, 16);
        Address Hi = AddrParts[1].toULongLong(&OkHi, 16);
        if (!OkLo || !OkHi) continue;

        if (Hi <= ImageBase || Lo >= ImageEnd) continue;

        Address ClipLo = std::max(Lo, ImageBase);
        Address ClipHi = std::min(Hi, ImageEnd);

        if (ClipHi > ClipLo) {
            ReadableRange Range;
            Range.Offset = ClipLo - ImageBase;
            Range.Size = ClipHi - ClipLo;
            Ranges.append(Range);
        }
    }
    MapsFile.close();
#else
    Q_UNUSED(ImageBase); Q_UNUSED(ImageSize);
#endif
    return Ranges;
}

bool ProcessDumper::DumpModule(const ModuleInfo& Module, const QString& OutputPath) {
    QMutexLocker Lock(&DumpMutex);
    Cancelled.storeRelaxed(0);

    if (!IsAttached()) {
        emit LogMessage("Not attached to any process");
        return false;
    }

    uint8_t Header[0x1000];
    memset(Header, 0, sizeof(Header));
    if (!ReadProcessMemory(Module.Base, Header, sizeof(Header))) {
        emit LogMessage(QString("Failed to read PE header at 0x%1").arg(Module.Base, 0, 16));
        return false;
    }

    PeFixupInfo PeInfo = ParsePeHeader(Header, sizeof(Header));
    uint64_t ImageSize = Module.Size;
    if (PeInfo.SizeOfImage > 0 && PeInfo.SizeOfImage <= 0x40000000) {
        ImageSize = PeInfo.SizeOfImage;
    }

    int TotalPages = static_cast<int>((ImageSize + PageSize - 1) / PageSize);
    QByteArray DumpBuffer(static_cast<int>(ImageSize), '\0');
    auto* BufPtr = reinterpret_cast<uint8_t*>(DumpBuffer.data());

    int CapturedCount = 0;
    int EncryptedCount = 0;
    int FailedCount = 0;

    emit LogMessage(QString("Dumping %1 (%2 MB, %3 pages)")
                    .arg(Module.Name)
                    .arg(ImageSize / 1024.0 / 1024.0, 0, 'f', 1)
                    .arg(TotalPages));

    auto Ranges = GetReadableRanges(Module.Base, ImageSize);
    uint64_t TotalReadable = 0;
    for (const auto& Range : Ranges) {
        TotalReadable += Range.Size;
    }

    emit LogMessage(QString("%1 readable ranges (%2 MB)")
                    .arg(Ranges.size())
                    .arg(TotalReadable / 1024.0 / 1024.0, 0, 'f', 1));

    constexpr size_t ChunkSize = 4 * 1024 * 1024;

    for (const auto& Range : Ranges) {
        if (Cancelled.loadRelaxed()) break;

        size_t RangeOffset = 0;
        while (RangeOffset < Range.Size) {
            if (Cancelled.loadRelaxed()) break;

            size_t ToRead = std::min(ChunkSize, Range.Size - RangeOffset);
            QByteArray ChunkData(static_cast<int>(ToRead), '\0');

            Address ReadAddr = Module.Base + Range.Offset + RangeOffset;
            ssize_t BytesRead = 0;
#ifdef __linux__
            BytesRead = ::pread(MemFd, ChunkData.data(), ToRead, static_cast<off_t>(ReadAddr));
#endif
            if (BytesRead <= 0) {
                RangeOffset += ToRead;
                continue;
            }

            size_t ActualRead = static_cast<size_t>(BytesRead);
            int StartPage = static_cast<int>((Range.Offset + RangeOffset) / PageSize);
            int EndPage = static_cast<int>((Range.Offset + RangeOffset + ActualRead) / PageSize);

            for (int Pg = StartPage; Pg < EndPage && Pg < TotalPages; ++Pg) {
                size_t LocalOff = static_cast<size_t>((Pg - StartPage)) * PageSize;
                if (LocalOff + PageSize > ActualRead) break;

                auto* PageData = reinterpret_cast<const uint8_t*>(ChunkData.constData()) + LocalOff;
                PageClassification Classification = ClassifyPage(PageData, PageSize);

                if (Classification == PageClassification::Clean) {
                    memcpy(BufPtr + Pg * PageSize, PageData, PageSize);
                    ++CapturedCount;
                } else {
                    ++EncryptedCount;
                }
            }

            RangeOffset += ToRead;
        }

        double Coverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
        DumpProgress Prog;
        Prog.TotalPages = TotalPages;
        Prog.CapturedPages = CapturedCount;
        Prog.EncryptedPages = EncryptedCount;
        Prog.FailedPages = FailedCount;
        Prog.CoveragePercent = Coverage;
        Prog.StatusMessage = QString("Reading %1...").arg(Module.Name);
        emit ProgressChanged(Prog);
    }

    if (Cancelled.loadRelaxed()) {
        emit LogMessage("Dump cancelled");
        return false;
    }

    FixPeForAnalysis(DumpBuffer, Module.Base);

    QFile OutFile(OutputPath);
    if (!OutFile.open(QIODevice::WriteOnly)) {
        emit LogMessage(QString("Failed to write %1").arg(OutputPath));
        return false;
    }
    OutFile.write(DumpBuffer);
    OutFile.close();

    double FinalCoverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
    LastDumpBuffer = DumpBuffer;

    emit LogMessage(QString("Dump complete: %1/%2 pages (%3%)")
                    .arg(CapturedCount).arg(TotalPages)
                    .arg(FinalCoverage, 0, 'f', 1));
    emit DumpComplete(OutputPath, FinalCoverage);
    return true;
}

bool ProcessDumper::DumpModuleProgressive(const ModuleInfo& Module, const QString& OutputPath,
                                           double TargetCoverage, int MaxPasses) {
    QMutexLocker Lock(&DumpMutex);
    Cancelled.storeRelaxed(0);

    if (!IsAttached()) {
        emit LogMessage("Not attached to any process");
        return false;
    }

    uint8_t Header[0x1000];
    memset(Header, 0, sizeof(Header));
    if (!ReadProcessMemory(Module.Base, Header, sizeof(Header))) {
        emit LogMessage(QString("Failed to read PE header at 0x%1").arg(Module.Base, 0, 16));
        return false;
    }

    PeFixupInfo PeInfo = ParsePeHeader(Header, sizeof(Header));
    uint64_t ImageSize = Module.Size;
    if (PeInfo.SizeOfImage > 0 && PeInfo.SizeOfImage <= 0x40000000) {
        ImageSize = PeInfo.SizeOfImage;
    }

    int TotalPages = static_cast<int>((ImageSize + PageSize - 1) / PageSize);
    QByteArray DumpBuffer(static_cast<int>(ImageSize), '\0');
    auto* BufPtr = reinterpret_cast<uint8_t*>(DumpBuffer.data());

    QVector<bool> Captured(TotalPages, false);
    QSet<int> Watchlist;
    int CapturedCount = 0;
    int EncryptedCount = 0;
    int FailedCount = 0;

    emit LogMessage(QString("Progressive dump: %1 (%2 MB, %3 pages, target %4%)")
                    .arg(Module.Name)
                    .arg(ImageSize / 1024.0 / 1024.0, 0, 'f', 1)
                    .arg(TotalPages)
                    .arg(TargetCoverage, 0, 'f', 1));

    auto Ranges = GetReadableRanges(Module.Base, ImageSize);

    constexpr size_t ChunkSize = 4 * 1024 * 1024;

    QSet<int> ScannedPages;
    for (const auto& Range : Ranges) {
        if (Cancelled.loadRelaxed()) break;

        size_t RangeOffset = 0;
        while (RangeOffset < Range.Size) {
            if (Cancelled.loadRelaxed()) break;

            size_t ToRead = std::min(ChunkSize, Range.Size - RangeOffset);
            QByteArray ChunkData(static_cast<int>(ToRead), '\0');

            Address ReadAddr = Module.Base + Range.Offset + RangeOffset;
            ssize_t BytesRead = 0;
#ifdef __linux__
            BytesRead = ::pread(MemFd, ChunkData.data(), ToRead, static_cast<off_t>(ReadAddr));
#endif
            if (BytesRead <= 0) {
                RangeOffset += ToRead;
                continue;
            }

            size_t ActualRead = static_cast<size_t>(BytesRead);
            int StartPage = static_cast<int>((Range.Offset + RangeOffset) / PageSize);
            int EndPage = static_cast<int>((Range.Offset + RangeOffset + ActualRead) / PageSize);

            for (int Pg = StartPage; Pg < EndPage && Pg < TotalPages; ++Pg) {
                ScannedPages.insert(Pg);
                size_t LocalOff = static_cast<size_t>((Pg - StartPage)) * PageSize;
                if (LocalOff + PageSize > ActualRead) break;

                auto* PageData = reinterpret_cast<const uint8_t*>(ChunkData.constData()) + LocalOff;
                PageClassification Classification = ClassifyPage(PageData, PageSize);

                if (Classification == PageClassification::Clean) {
                    memcpy(BufPtr + Pg * PageSize, PageData, PageSize);
                    Captured[Pg] = true;
                    ++CapturedCount;
                } else {
                    Watchlist.insert(Pg);
                }
            }

            RangeOffset += ToRead;
        }
    }

    for (int Pg = 0; Pg < TotalPages; ++Pg) {
        if (!ScannedPages.contains(Pg) && !Captured[Pg]) {
            Watchlist.insert(Pg);
        }
    }

    emit LogMessage(QString("Initial pass: %1 captured, %2 on watchlist")
                    .arg(CapturedCount).arg(Watchlist.size()));

    uint8_t PageBuffer[PageSize];

    for (int Pass = 0; Pass < MaxPasses; ++Pass) {
        if (Cancelled.loadRelaxed()) break;

        double Coverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
        if (Coverage >= TargetCoverage) break;
        if (Watchlist.isEmpty()) break;

        int NewCaptures = 0;
        QSet<int> StillWatching;

        for (int Pg : Watchlist) {
            if (Cancelled.loadRelaxed()) break;

            Address Addr = Module.Base + static_cast<uint64_t>(Pg) * PageSize;
            if (!ReadProcessPage(Addr, PageBuffer)) {
                ++FailedCount;
                StillWatching.insert(Pg);
                continue;
            }

            PageClassification Classification = ClassifyPage(PageBuffer, PageSize);
            if (Classification == PageClassification::Clean) {
                memcpy(BufPtr + Pg * PageSize, PageBuffer, PageSize);
                Captured[Pg] = true;
                ++CapturedCount;
                ++NewCaptures;
            } else {
                StillWatching.insert(Pg);
            }
        }

        Watchlist = StillWatching;
        EncryptedCount = Watchlist.size();

        Coverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
        DumpProgress Prog;
        Prog.TotalPages = TotalPages;
        Prog.CapturedPages = CapturedCount;
        Prog.EncryptedPages = EncryptedCount;
        Prog.FailedPages = FailedCount;
        Prog.CoveragePercent = Coverage;
        Prog.StatusMessage = QString("Pass %1: +%2 pages (%3%)")
                             .arg(Pass + 1).arg(NewCaptures).arg(Coverage, 0, 'f', 1);
        emit ProgressChanged(Prog);

        if (NewCaptures == 0 && Pass > 5) {
            emit LogMessage("Stalled - no new pages decrypted in last pass");
        }

        QThread::msleep(10);
    }

    if (Cancelled.loadRelaxed()) {
        emit LogMessage("Dump cancelled");
        return false;
    }

    FixPeForAnalysis(DumpBuffer, Module.Base);

    QFile OutFile(OutputPath);
    if (!OutFile.open(QIODevice::WriteOnly)) {
        emit LogMessage(QString("Failed to write %1").arg(OutputPath));
        return false;
    }
    OutFile.write(DumpBuffer);
    OutFile.close();

    double FinalCoverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
    LastDumpBuffer = DumpBuffer;

    emit LogMessage(QString("Progressive dump complete: %1/%2 pages (%3%), %4 encrypted remaining")
                    .arg(CapturedCount).arg(TotalPages)
                    .arg(FinalCoverage, 0, 'f', 1)
                    .arg(Watchlist.size()));
    emit DumpComplete(OutputPath, FinalCoverage);
    return true;
}

void ProcessDumper::Cancel() {
    Cancelled.storeRelaxed(1);
}

QByteArray ProcessDumper::GetLastDumpBuffer() const {
    return LastDumpBuffer;
}

void ProcessDumper::SetScatterGatherEnabled(bool Enabled) {
    ScatterGatherEnabled = Enabled;
}

bool ProcessDumper::BatchReadPages(Address Base, const QVector<int>& PageIndices, QByteArray& Buffer) {
#ifdef __linux__
    if (PageIndices.isEmpty()) return false;

    int TotalPages = PageIndices.size();
    if (Buffer.size() < static_cast<qsizetype>(TotalPages) * PageSize) {
        Buffer.resize(TotalPages * PageSize);
    }

    auto* BufPtr = reinterpret_cast<uint8_t*>(Buffer.data());
    int TotalRead = 0;

    constexpr int BatchSize = 256;
    pid_t Pid = static_cast<pid_t>(AttachedPid);

    for (int BatchStart = 0; BatchStart < TotalPages; BatchStart += BatchSize) {
        int BatchEnd = std::min(BatchStart + BatchSize, TotalPages);
        int Count = BatchEnd - BatchStart;

        QVector<struct iovec> LocalIov(Count);
        QVector<struct iovec> RemoteIov(Count);

        for (int I = 0; I < Count; ++I) {
            int Idx = BatchStart + I;
            LocalIov[I].iov_base = BufPtr + static_cast<size_t>(Idx) * PageSize;
            LocalIov[I].iov_len = PageSize;
            RemoteIov[I].iov_base = reinterpret_cast<void*>(Base + static_cast<uint64_t>(PageIndices[Idx]) * PageSize);
            RemoteIov[I].iov_len = PageSize;
        }

        ssize_t BytesRead = process_vm_readv(Pid,
                                              LocalIov.data(), Count,
                                              RemoteIov.data(), Count, 0);
        if (BytesRead > 0) {
            TotalRead += static_cast<int>(BytesRead / PageSize);
        }
    }

    return TotalRead > 0;
#else
    Q_UNUSED(Base); Q_UNUSED(PageIndices); Q_UNUSED(Buffer);
    return false;
#endif
}

bool ProcessDumper::DumpAllModules(const QString& OutputDir, double TargetCoverage, int MaxPasses) {
    if (!IsAttached()) {
        emit LogMessage("Not attached to any process");
        return false;
    }

    Cancelled.storeRelaxed(0);

    QDir Dir(OutputDir);
    if (!Dir.exists()) {
        Dir.mkpath(".");
    }

    QVector<ModuleInfo> Modules = EnumerateModules();
    if (Modules.isEmpty()) {
        emit LogMessage("No modules found");
        return false;
    }

    int DumpedCount = 0;
    int SkippedCount = 0;
    double TotalCoverage = 0.0;

    emit LogMessage(QString("Dumping %1 modules to %2").arg(Modules.size()).arg(OutputDir));

    for (const auto& Mod : Modules) {
        if (Cancelled.loadRelaxed()) {
            emit LogMessage("Batch dump cancelled");
            return false;
        }

        if (Mod.Size < 4096) {
            emit LogMessage(QString("Skipping %1 (size %2 < 4096)").arg(Mod.Name).arg(Mod.Size));
            ++SkippedCount;
            continue;
        }

        QString SafeName = Mod.Name;
        SafeName.replace(QRegularExpression("[^a-zA-Z0-9._-]"), "_");

        QString Ext = ".bin";
        if (Mod.Name.endsWith(".dll", Qt::CaseInsensitive)) {
            Ext = ".dll";
        } else if (Mod.Name.endsWith(".exe", Qt::CaseInsensitive)) {
            Ext = ".exe";
        } else if (Mod.Name.endsWith(".so", Qt::CaseInsensitive) || Mod.Name.contains(".so.")) {
            Ext = ".so";
        }

        QString OutputPath = Dir.filePath(SafeName + "_dump" + Ext);

        emit LogMessage(QString("Dumping module %1/%2: %3 (%4 MB)")
                        .arg(DumpedCount + SkippedCount + 1)
                        .arg(Modules.size())
                        .arg(Mod.Name)
                        .arg(Mod.Size / 1024.0 / 1024.0, 0, 'f', 1));

        bool Result = DumpModuleProgressive(Mod, OutputPath, TargetCoverage, MaxPasses);
        if (Result) {
            ++DumpedCount;
        } else {
            emit LogMessage(QString("Failed to dump %1").arg(Mod.Name));
        }
    }

    TotalCoverage = DumpedCount > 0 ? (100.0 * DumpedCount / (DumpedCount + SkippedCount)) : 0.0;

    emit LogMessage(QString("Batch dump complete: %1 dumped, %2 skipped out of %3 modules")
                    .arg(DumpedCount).arg(SkippedCount).arg(Modules.size()));

    return DumpedCount > 0;
}

bool ProcessDumper::DumpWithMerge(const ModuleInfo& Module, const QString& OutputPath,
                                   const QVector<QString>& PreviousDumps) {
    QMutexLocker Lock(&DumpMutex);
    Cancelled.storeRelaxed(0);

    if (!IsAttached()) {
        emit LogMessage("Not attached to any process");
        return false;
    }

    QVector<QByteArray> PreviousBuffers;
    for (const auto& DumpPath : PreviousDumps) {
        QFile File(DumpPath);
        if (!File.open(QIODevice::ReadOnly)) {
            emit LogMessage(QString("Failed to load previous dump: %1").arg(DumpPath));
            continue;
        }
        PreviousBuffers.append(File.readAll());
        File.close();
        emit LogMessage(QString("Loaded previous dump: %1 (%2 bytes)")
                        .arg(QFileInfo(DumpPath).fileName())
                        .arg(PreviousBuffers.last().size()));
    }

    uint8_t Header[0x1000];
    memset(Header, 0, sizeof(Header));
    if (!ReadProcessMemory(Module.Base, Header, sizeof(Header))) {
        emit LogMessage(QString("Failed to read PE header at 0x%1").arg(Module.Base, 0, 16));
        return false;
    }

    PeFixupInfo PeInfo = ParsePeHeader(Header, sizeof(Header));
    uint64_t ImageSize = Module.Size;
    if (PeInfo.SizeOfImage > 0 && PeInfo.SizeOfImage <= 0x40000000) {
        ImageSize = PeInfo.SizeOfImage;
    }

    int TotalPages = static_cast<int>((ImageSize + PageSize - 1) / PageSize);
    QByteArray DumpBuffer(static_cast<int>(ImageSize), '\0');
    auto* BufPtr = reinterpret_cast<uint8_t*>(DumpBuffer.data());

    int CapturedCount = 0;
    int MergedCount = 0;

    emit LogMessage(QString("Merge dump: %1 (%2 pages, %3 previous dumps)")
                    .arg(Module.Name).arg(TotalPages).arg(PreviousBuffers.size()));

    auto Ranges = GetReadableRanges(Module.Base, ImageSize);

    for (const auto& Range : Ranges) {
        if (Cancelled.loadRelaxed()) break;

        size_t RangeOffset = 0;
        constexpr size_t ChunkSize = 4 * 1024 * 1024;

        while (RangeOffset < Range.Size) {
            if (Cancelled.loadRelaxed()) break;

            size_t ToRead = std::min(ChunkSize, Range.Size - RangeOffset);
            QByteArray ChunkData(static_cast<int>(ToRead), '\0');

            Address ReadAddr = Module.Base + Range.Offset + RangeOffset;
            ssize_t BytesRead = 0;
#ifdef __linux__
            BytesRead = ::pread(MemFd, ChunkData.data(), ToRead, static_cast<off_t>(ReadAddr));
#endif
            if (BytesRead <= 0) {
                RangeOffset += ToRead;
                continue;
            }

            size_t ActualRead = static_cast<size_t>(BytesRead);
            int StartPage = static_cast<int>((Range.Offset + RangeOffset) / PageSize);
            int EndPage = static_cast<int>((Range.Offset + RangeOffset + ActualRead) / PageSize);

            for (int Pg = StartPage; Pg < EndPage && Pg < TotalPages; ++Pg) {
                size_t LocalOff = static_cast<size_t>((Pg - StartPage)) * PageSize;
                if (LocalOff + PageSize > ActualRead) break;

                auto* PageData = reinterpret_cast<const uint8_t*>(ChunkData.constData()) + LocalOff;
                PageClassification Classification = ClassifyPage(PageData, PageSize);

                if (Classification == PageClassification::Clean) {
                    memcpy(BufPtr + Pg * PageSize, PageData, PageSize);
                    ++CapturedCount;
                } else {
                    double BestEntropy = 999.0;
                    int BestIdx = -1;

                    for (int Pi = 0; Pi < PreviousBuffers.size(); ++Pi) {
                        int PageOffset = Pg * PageSize;
                        if (PageOffset + PageSize > PreviousBuffers[Pi].size()) continue;

                        auto* PrevPageData = reinterpret_cast<const uint8_t*>(PreviousBuffers[Pi].constData()) + PageOffset;
                        PageClassification PrevClass = ClassifyPage(PrevPageData, PageSize);

                        if (PrevClass == PageClassification::Clean) {
                            double Entropy = CalculateEntropy(PrevPageData, PageSize);
                            if (Entropy < BestEntropy) {
                                BestEntropy = Entropy;
                                BestIdx = Pi;
                            }
                        }
                    }

                    if (BestIdx >= 0) {
                        int PageOffset = Pg * PageSize;
                        memcpy(BufPtr + PageOffset,
                               PreviousBuffers[BestIdx].constData() + PageOffset, PageSize);
                        ++MergedCount;
                        ++CapturedCount;
                    }
                }
            }

            RangeOffset += ToRead;
        }
    }

    if (Cancelled.loadRelaxed()) {
        emit LogMessage("Merge dump cancelled");
        return false;
    }

    FixPeForAnalysis(DumpBuffer, Module.Base);

    QFile OutFile(OutputPath);
    if (!OutFile.open(QIODevice::WriteOnly)) {
        emit LogMessage(QString("Failed to write %1").arg(OutputPath));
        return false;
    }
    OutFile.write(DumpBuffer);
    OutFile.close();

    double FinalCoverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
    LastDumpBuffer = DumpBuffer;

    emit LogMessage(QString("Merge dump complete: %1/%2 pages (%3%), %4 recovered from previous dumps")
                    .arg(CapturedCount).arg(TotalPages)
                    .arg(FinalCoverage, 0, 'f', 1)
                    .arg(MergedCount));
    emit DumpComplete(OutputPath, FinalCoverage);
    return true;
}

bool ProcessDumper::DumpWithBaseline(const ModuleInfo& Module, const QString& OutputPath,
                                      const QString& BaselinePath) {
    QMutexLocker Lock(&DumpMutex);
    Cancelled.storeRelaxed(0);

    if (!IsAttached()) {
        emit LogMessage("Not attached to any process");
        return false;
    }

    QFile BaselineFile(BaselinePath);
    if (!BaselineFile.open(QIODevice::ReadOnly)) {
        emit LogMessage(QString("Failed to load baseline: %1").arg(BaselinePath));
        return false;
    }
    QByteArray BaselineData = BaselineFile.readAll();
    BaselineFile.close();

    emit LogMessage(QString("Loaded baseline: %1 (%2 bytes)")
                    .arg(QFileInfo(BaselinePath).fileName())
                    .arg(BaselineData.size()));

    uint8_t Header[0x1000];
    memset(Header, 0, sizeof(Header));
    if (!ReadProcessMemory(Module.Base, Header, sizeof(Header))) {
        emit LogMessage(QString("Failed to read PE header at 0x%1").arg(Module.Base, 0, 16));
        return false;
    }

    PeFixupInfo PeInfo = ParsePeHeader(Header, sizeof(Header));
    uint64_t ImageSize = Module.Size;
    if (PeInfo.SizeOfImage > 0 && PeInfo.SizeOfImage <= 0x40000000) {
        ImageSize = PeInfo.SizeOfImage;
    }

    int TotalPages = static_cast<int>((ImageSize + PageSize - 1) / PageSize);
    QByteArray DumpBuffer(static_cast<int>(ImageSize), '\0');

    int BaselineBytes = std::min(static_cast<int>(ImageSize), static_cast<int>(BaselineData.size()));
    memcpy(DumpBuffer.data(), BaselineData.constData(), BaselineBytes);

    auto* BufPtr = reinterpret_cast<uint8_t*>(DumpBuffer.data());

    QSet<int> Watchlist;
    int PreCapturedCount = 0;

    for (int Pg = 0; Pg < TotalPages; ++Pg) {
        int PageOffset = Pg * PageSize;
        if (PageOffset + PageSize > BaselineBytes) {
            Watchlist.insert(Pg);
            continue;
        }

        auto* PageData = reinterpret_cast<const uint8_t*>(BaselineData.constData()) + PageOffset;
        PageClassification Classification = ClassifyPage(PageData, PageSize);

        if (Classification == PageClassification::Clean) {
            ++PreCapturedCount;
        } else {
            Watchlist.insert(Pg);
        }
    }

    int CapturedCount = PreCapturedCount;

    emit LogMessage(QString("Baseline: %1/%2 pages clean, %3 on watchlist")
                    .arg(PreCapturedCount).arg(TotalPages).arg(Watchlist.size()));

    uint8_t PageBuffer[PageSize];
    int MaxPasses = 100;

    for (int Pass = 0; Pass < MaxPasses; ++Pass) {
        if (Cancelled.loadRelaxed()) break;

        double Coverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
        if (Coverage >= 99.0) break;
        if (Watchlist.isEmpty()) break;

        int NewCaptures = 0;
        QSet<int> StillWatching;

        for (int Pg : Watchlist) {
            if (Cancelled.loadRelaxed()) break;

            Address Addr = Module.Base + static_cast<uint64_t>(Pg) * PageSize;
            if (!ReadProcessPage(Addr, PageBuffer)) {
                StillWatching.insert(Pg);
                continue;
            }

            PageClassification Classification = ClassifyPage(PageBuffer, PageSize);
            if (Classification == PageClassification::Clean) {
                memcpy(BufPtr + Pg * PageSize, PageBuffer, PageSize);
                ++CapturedCount;
                ++NewCaptures;
            } else {
                StillWatching.insert(Pg);
            }
        }

        Watchlist = StillWatching;

        Coverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
        DumpProgress Prog;
        Prog.TotalPages = TotalPages;
        Prog.CapturedPages = CapturedCount;
        Prog.EncryptedPages = Watchlist.size();
        Prog.FailedPages = 0;
        Prog.CoveragePercent = Coverage;
        Prog.StatusMessage = QString("Baseline pass %1: +%2 pages (%3%)")
                             .arg(Pass + 1).arg(NewCaptures).arg(Coverage, 0, 'f', 1);
        emit ProgressChanged(Prog);

        if (NewCaptures == 0 && Pass > 5) {
            emit LogMessage("Stalled - no new pages decrypted in last pass");
        }

        QThread::msleep(10);
    }

    if (Cancelled.loadRelaxed()) {
        emit LogMessage("Baseline dump cancelled");
        return false;
    }

    FixPeForAnalysis(DumpBuffer, Module.Base);

    QFile OutFile(OutputPath);
    if (!OutFile.open(QIODevice::WriteOnly)) {
        emit LogMessage(QString("Failed to write %1").arg(OutputPath));
        return false;
    }
    OutFile.write(DumpBuffer);
    OutFile.close();

    double FinalCoverage = TotalPages > 0 ? (100.0 * CapturedCount / TotalPages) : 0.0;
    LastDumpBuffer = DumpBuffer;

    emit LogMessage(QString("Baseline dump complete: %1/%2 pages (%3%), started with %4 from baseline")
                    .arg(CapturedCount).arg(TotalPages)
                    .arg(FinalCoverage, 0, 'f', 1)
                    .arg(PreCapturedCount));
    emit DumpComplete(OutputPath, FinalCoverage);
    return true;
}

}
