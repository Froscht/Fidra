#pragma once

#include <fidra/ICore.h>
#include <QObject>
#include <QThread>
#include <QVector>
#include <QPair>
#include <QMultiMap>
#include <QMutex>
#include <QAtomicInt>

namespace Fidra {

struct PointerPath {
    QVector<QPair<QString, Offset>> Chain;
};

struct PointerScanConfig {
    Address TargetAddress = 0;
    int MaxDepth = 5;
    Offset MaxOffset = 0x2000;
    bool ScanWritable = true;
    bool ScanExecutable = false;
};

class PointerScanWorker : public QObject {
    Q_OBJECT

public:
    explicit PointerScanWorker(QObject* Parent = nullptr);

    void SetParameters(ICore* Core, const PointerScanConfig& Config);
    void Cancel();

public slots:
    void DoScan();

signals:
    void ScanProgress(int Percent);
    void ScanComplete(QVector<Fidra::PointerPath> Paths);
    void ScanFinished();

private:
    struct ModuleRange {
        Address Base;
        size_t Size;
        QString Name;
    };

    void BuildReversePointerMap();
    void FindPointerPaths();
    bool IsWithinModule(Address Addr, QString& OutModuleName, Offset& OutOffset) const;
    bool IsValidRegion(const MemoryRegion& Region) const;
    ICore* CoreRef;
    PointerScanConfig ScanConfig;
    QAtomicInt Cancelled;

    QMultiMap<Address, Address> ReverseMap;
    QVector<ModuleRange> ModuleRanges;
    QVector<PointerPath> Results;
};

class PointerScanner : public QObject {
    Q_OBJECT

public:
    explicit PointerScanner(QObject* Parent = nullptr);
    ~PointerScanner() override;

    void StartScan(ICore* Core, const PointerScanConfig& Config);
    void Cancel();
    QVector<PointerPath> GetResults();
    bool IsScanning() const;

signals:
    void ScanProgress(int Percent);
    void ScanComplete(int PathCount);

private slots:
    void OnWorkerComplete(QVector<Fidra::PointerPath> Paths);
    void OnScanFinished();

private:
    QThread* WorkerThread;
    PointerScanWorker* Worker;
    QVector<PointerPath> CachedResults;
    QMutex ResultsMutex;
    QAtomicInt Scanning;
};

}
