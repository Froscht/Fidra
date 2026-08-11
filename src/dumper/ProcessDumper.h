#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QByteArray>
#include <QVector>
#include <QAtomicInt>
#include <QMutex>

namespace Fidra {

struct ModuleInfo {
    QString Name;
    QString Path;
    Address Base;
    uint64_t Size;
    bool IsMainModule;
};

struct DumpProgress {
    int TotalPages;
    int CapturedPages;
    int EncryptedPages;
    int FailedPages;
    double CoveragePercent;
    QString StatusMessage;
};

struct PeFixupInfo {
    Address OriginalBase;
    uint32_t SizeOfImage;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
};

class ProcessDumper : public QObject {
    Q_OBJECT

public:
    explicit ProcessDumper(QObject* Parent = nullptr);
    ~ProcessDumper() override;

    bool AttachToProcess(uint32_t Pid);
    void Detach();
    bool IsAttached() const;

    QVector<ModuleInfo> EnumerateModules();

    bool DumpModule(const ModuleInfo& Module, const QString& OutputPath);
    bool DumpModuleProgressive(const ModuleInfo& Module, const QString& OutputPath,
                               double TargetCoverage = 99.0, int MaxPasses = 100);

    bool BatchReadPages(Address Base, const QVector<int>& PageIndices, QByteArray& Buffer);
    bool DumpAllModules(const QString& OutputDir, double TargetCoverage = 99.0, int MaxPasses = 100);
    bool DumpWithMerge(const ModuleInfo& Module, const QString& OutputPath, const QVector<QString>& PreviousDumps);
    bool DumpWithBaseline(const ModuleInfo& Module, const QString& OutputPath, const QString& BaselinePath);

    void SetScatterGatherEnabled(bool Enabled);

    void Cancel();

    QByteArray GetLastDumpBuffer() const;

signals:
    void ProgressChanged(DumpProgress Progress);
    void LogMessage(const QString& Message);
    void DumpComplete(const QString& OutputPath, double Coverage);

private:
    static constexpr int PageSize = 4096;
    static constexpr int EncryptCcThreshold = 48;
    static constexpr double CiphertextEntropy = 7.5;

    enum class PageClassification {
        Clean,
        CcSentinel,
        Ciphertext,
        ReadError
    };

    PageClassification ClassifyPage(const uint8_t* Data, int Size);
    double CalculateEntropy(const uint8_t* Data, int Size);

    bool ReadProcessPage(Address Addr, void* Buffer);
    bool ReadProcessMemory(Address Addr, void* Buffer, size_t Size);

    PeFixupInfo ParsePeHeader(const uint8_t* Data, size_t Size);
    QByteArray FixPeForAnalysis(QByteArray& Buffer, Address ImageBase);

    struct ReadableRange {
        uint64_t Offset;
        uint64_t Size;
    };
    QVector<ReadableRange> GetReadableRanges(Address ImageBase, uint64_t ImageSize);

    uint32_t AttachedPid;
    int MemFd;
    QAtomicInt Cancelled;
    bool ScatterGatherEnabled;
    QByteArray LastDumpBuffer;
    mutable QMutex DumpMutex;
};

}
