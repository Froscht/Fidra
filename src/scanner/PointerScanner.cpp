#include "PointerScanner.h"
#include <QQueue>
#include <QSet>
#include <algorithm>

namespace Fidra {

PointerScanWorker::PointerScanWorker(QObject* Parent)
    : QObject(Parent)
    , CoreRef(nullptr)
{
    Cancelled.storeRelaxed(0);
}

void PointerScanWorker::SetParameters(ICore* Core, const PointerScanConfig& Config)
{
    CoreRef = Core;
    ScanConfig = Config;
}

void PointerScanWorker::Cancel()
{
    Cancelled.storeRelaxed(1);
}

bool PointerScanWorker::IsValidRegion(const MemoryRegion& Region) const
{
    if (Region.Size == 0) return false;

    bool HasRead = (Region.Protection & 0x02) || (Region.Protection & 0x04) ||
                   (Region.Protection & 0x20) || (Region.Protection & 0x40);
    if (!HasRead) return false;

    if (ScanConfig.ScanWritable) {
        bool HasWrite = (Region.Protection & 0x04) || (Region.Protection & 0x08) ||
                        (Region.Protection & 0x40) || (Region.Protection & 0x80);
        if (!HasWrite) return false;
    }

    if (ScanConfig.ScanExecutable) {
        bool HasExec = (Region.Protection & 0x10) || (Region.Protection & 0x20) ||
                       (Region.Protection & 0x40) || (Region.Protection & 0x80);
        if (!HasExec) return false;
    }

    return true;
}

bool PointerScanWorker::IsWithinModule(Address Addr, QString& OutModuleName, Offset& OutOffset) const
{
    for (const auto& Mod : ModuleRanges) {
        if (Addr >= Mod.Base && Addr < Mod.Base + Mod.Size) {
            OutModuleName = Mod.Name;
            OutOffset = static_cast<Offset>(Addr - Mod.Base);
            return true;
        }
    }
    return false;
}

void PointerScanWorker::BuildReversePointerMap()
{
    ReverseMap.clear();
    ModuleRanges.clear();

    auto Regions = CoreRef->GetMemoryRegions();
    QVector<QPair<Address, Address>> ValidRanges;

    for (const auto& Region : Regions) {
        if (Region.Size == 0) continue;
        ValidRanges.append({Region.Base, Region.Base + Region.Size});

        if (!Region.ModuleName.isEmpty()) {
            bool Found = false;
            for (auto& Existing : ModuleRanges) {
                if (Existing.Name == Region.ModuleName) {
                    Address End = std::max(Existing.Base + Existing.Size, Region.Base + Region.Size);
                    Existing.Base = std::min(Existing.Base, Region.Base);
                    Existing.Size = static_cast<size_t>(End - Existing.Base);
                    Found = true;
                    break;
                }
            }
            if (!Found) {
                ModuleRanges.append({Region.Base, Region.Size, Region.ModuleName});
            }
        }
    }

    std::sort(ValidRanges.begin(), ValidRanges.end());

    auto IsValidPointerTarget = [&](Address Val) -> bool {
        int Lo = 0;
        int Hi = ValidRanges.size() - 1;
        while (Lo <= Hi) {
            int Mid = Lo + (Hi - Lo) / 2;
            if (Val < ValidRanges[Mid].first) {
                Hi = Mid - 1;
            } else if (Val >= ValidRanges[Mid].second) {
                Lo = Mid + 1;
            } else {
                return true;
            }
        }
        return false;
    };

    int TotalRegions = Regions.size();
    int ProcessedRegions = 0;
    constexpr size_t ChunkSize = 0x10000;

    for (const auto& Region : Regions) {
        if (Cancelled.loadRelaxed()) return;

        if (!IsValidRegion(Region)) {
            ProcessedRegions++;
            continue;
        }

        size_t RegionSize = Region.Size;
        Address RegionBase = Region.Base;
        QByteArray Buffer;

        for (size_t Pos = 0; Pos < RegionSize; Pos += ChunkSize) {
            if (Cancelled.loadRelaxed()) return;

            size_t ReadSize = std::min(ChunkSize, RegionSize - Pos);
            Buffer.resize(static_cast<qsizetype>(ReadSize));

            if (!CoreRef->ReadMemory(RegionBase + Pos, Buffer.data(), ReadSize))
                continue;

            size_t AlignedSize = ReadSize & ~7ULL;
            const uint64_t* Data = reinterpret_cast<const uint64_t*>(Buffer.constData());
            size_t Count = AlignedSize / sizeof(uint64_t);

            for (size_t I = 0; I < Count; I++) {
                Address PointerValue = Data[I];
                if (PointerValue == 0) continue;
                if (IsValidPointerTarget(PointerValue)) {
                    Address SourceAddr = RegionBase + Pos + I * sizeof(uint64_t);
                    ReverseMap.insert(PointerValue, SourceAddr);
                }
            }
        }

        ProcessedRegions++;
        int Percent = static_cast<int>((static_cast<double>(ProcessedRegions) / TotalRegions) * 70.0);
        emit ScanProgress(Percent);
    }
}

void PointerScanWorker::FindPointerPaths()
{
    Results.clear();

    struct PathNode {
        Address CurrentAddress;
        QVector<QPair<QString, Offset>> CurrentChain;
    };

    QQueue<PathNode> WorkQueue;
    QSet<Address> Visited;

    Address Target = ScanConfig.TargetAddress;
    Offset MaxOff = ScanConfig.MaxOffset > 0 ? ScanConfig.MaxOffset : 0x2000;
    Address RangeLow = Target > static_cast<Address>(MaxOff) ? Target - static_cast<Address>(MaxOff) : 0;
    Address RangeHigh = Target + static_cast<Address>(MaxOff);

    {
        auto ItLow = ReverseMap.lowerBound(RangeLow);
        auto ItHigh = ReverseMap.upperBound(RangeHigh);
        for (auto It = ItLow; It != ItHigh; ++It) {
            if (Cancelled.loadRelaxed()) return;

            Address PointedTo = It.key();
            Address SourceAddr = It.value();
            Offset Off = static_cast<Offset>(Target) - static_cast<Offset>(PointedTo);

            QString ModName;
            Offset ModOff;
            if (IsWithinModule(SourceAddr, ModName, ModOff)) {
                PointerPath Path;
                Path.Chain.append({ModName, ModOff});
                if (Off != 0) Path.Chain.append({"", Off});
                Results.append(Path);
            } else if (!Visited.contains(SourceAddr)) {
                Visited.insert(SourceAddr);
                PathNode Node;
                Node.CurrentAddress = SourceAddr;
                Node.CurrentChain.append({"", Off});
                WorkQueue.enqueue(Node);
            }
        }
    }

    emit ScanProgress(75);

    constexpr int MaxResultsTotal = 100000;
    constexpr int MaxNodesPerLevel = 200000;

    for (int Depth = 1; Depth < ScanConfig.MaxDepth && !WorkQueue.isEmpty(); Depth++) {
        if (Cancelled.loadRelaxed()) return;
        if (Results.size() >= MaxResultsTotal) break;

        QQueue<PathNode> NextQueue;
        int NodesThisLevel = 0;

        while (!WorkQueue.isEmpty() && NodesThisLevel < MaxNodesPerLevel) {
            if (Cancelled.loadRelaxed()) return;

            PathNode Current = WorkQueue.dequeue();
            Address CurAddr = Current.CurrentAddress;
            Address CurLow = CurAddr > static_cast<Address>(MaxOff) ? CurAddr - static_cast<Address>(MaxOff) : 0;
            Address CurHigh = CurAddr + static_cast<Address>(MaxOff);

            auto ItLow = ReverseMap.lowerBound(CurLow);
            auto ItHigh = ReverseMap.upperBound(CurHigh);

            for (auto It = ItLow; It != ItHigh; ++It) {
                Address PointedTo = It.key();
                Address SourceAddr = It.value();
                Offset Off = static_cast<Offset>(CurAddr) - static_cast<Offset>(PointedTo);

                QString ModName;
                Offset ModOff;
                if (IsWithinModule(SourceAddr, ModName, ModOff)) {
                    PointerPath Path;
                    Path.Chain.append({ModName, ModOff});
                    if (Off != 0) Path.Chain.append({"", Off});
                    for (const auto& Step : Current.CurrentChain) {
                        Path.Chain.append(Step);
                    }
                    Results.append(Path);
                    if (Results.size() >= MaxResultsTotal) return;
                } else if (Depth + 1 < ScanConfig.MaxDepth && !Visited.contains(SourceAddr)) {
                    Visited.insert(SourceAddr);
                    PathNode Next;
                    Next.CurrentAddress = SourceAddr;
                    Next.CurrentChain.prepend({"", Off});
                    for (const auto& Step : Current.CurrentChain) {
                        Next.CurrentChain.append(Step);
                    }
                    NextQueue.enqueue(Next);
                }

                NodesThisLevel++;
                if (NodesThisLevel >= MaxNodesPerLevel) break;
            }
        }

        WorkQueue = NextQueue;
        int Percent = 75 + static_cast<int>((static_cast<double>(Depth) / ScanConfig.MaxDepth) * 25.0);
        emit ScanProgress(Percent);
    }

    emit ScanProgress(100);
}

void PointerScanWorker::DoScan()
{
    Cancelled.storeRelaxed(0);
    Results.clear();
    ReverseMap.clear();

    BuildReversePointerMap();

    if (!Cancelled.loadRelaxed()) {
        FindPointerPaths();
    }

    emit ScanComplete(Results);
    emit ScanFinished();
}

PointerScanner::PointerScanner(QObject* Parent)
    : QObject(Parent)
    , WorkerThread(nullptr)
    , Worker(nullptr)
{
    Scanning.storeRelaxed(0);
}

PointerScanner::~PointerScanner()
{
    Cancel();
}

void PointerScanner::StartScan(ICore* Core, const PointerScanConfig& Config)
{
    if (Scanning.loadRelaxed()) {
        Cancel();
    }

    CachedResults.clear();
    Scanning.storeRelaxed(1);

    WorkerThread = new QThread(this);
    Worker = new PointerScanWorker();
    Worker->SetParameters(Core, Config);
    Worker->moveToThread(WorkerThread);

    connect(WorkerThread, &QThread::started, Worker, &PointerScanWorker::DoScan);
    connect(Worker, &PointerScanWorker::ScanProgress, this, &PointerScanner::ScanProgress);
    connect(Worker, &PointerScanWorker::ScanComplete, this, &PointerScanner::OnWorkerComplete);
    connect(Worker, &PointerScanWorker::ScanFinished, this, &PointerScanner::OnScanFinished);
    connect(Worker, &PointerScanWorker::ScanFinished, Worker, &QObject::deleteLater);
    connect(WorkerThread, &QThread::finished, WorkerThread, &QObject::deleteLater);

    WorkerThread->start();
}

void PointerScanner::Cancel()
{
    if (Worker) {
        Worker->Cancel();
    }
    if (WorkerThread && WorkerThread->isRunning()) {
        WorkerThread->quit();
        WorkerThread->wait(5000);
    }
    Scanning.storeRelaxed(0);
    WorkerThread = nullptr;
    Worker = nullptr;
}

QVector<PointerPath> PointerScanner::GetResults()
{
    QMutexLocker Lock(&ResultsMutex);
    return CachedResults;
}

bool PointerScanner::IsScanning() const
{
    return Scanning.loadRelaxed() != 0;
}

void PointerScanner::OnWorkerComplete(QVector<Fidra::PointerPath> Paths)
{
    QMutexLocker Lock(&ResultsMutex);
    CachedResults = std::move(Paths);
    emit ScanComplete(CachedResults.size());
}

void PointerScanner::OnScanFinished()
{
    Scanning.storeRelaxed(0);
    WorkerThread = nullptr;
    Worker = nullptr;
}

}
