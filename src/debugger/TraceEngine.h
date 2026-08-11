#pragma once

#include <fidra/Types.h>
#include <QObject>
#include <QThread>
#include <QMutex>
#include <QVector>
#include <QMap>
#include <QSet>
#include <QString>
#include <QByteArray>
#include <QFile>
#include <atomic>

namespace Fidra {

struct TraceEntry {
    uint64_t Index;
    Address InstructionAddr;
    QString Mnemonic;
    QString Operands;
    uint64_t Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp, Rip;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t Rflags;
    QByteArray MemoryAccess;
    Address MemoryAddr;
    bool IsMemoryWrite;
};

struct TraceFilter {
    Address StartAddr = 0;
    Address EndAddr = UINT64_MAX;
    int MaxEntries = 1000000;
    bool TraceIntoLibraries = false;
    QString ModuleFilter;
    QSet<Address> BreakOnAddresses;
    QString Condition;
};

class TraceEngine : public QObject {
    Q_OBJECT

public:
    explicit TraceEngine(QObject* Parent = nullptr);
    ~TraceEngine() override;

    bool StartTrace(int Pid, const TraceFilter& Filter = {});
    void StopTrace();
    bool IsTracing() const;

    QVector<TraceEntry> GetEntries() const;
    TraceEntry GetEntry(uint64_t Index) const;
    uint64_t EntryCount() const;

    QVector<TraceEntry> Search(const QString& MnemonicFilter) const;
    QVector<TraceEntry> SearchByAddress(Address Addr) const;
    QVector<TraceEntry> SearchByRegValue(const QString& RegName, uint64_t Value) const;

    bool SaveTrace(const QString& Path) const;
    bool LoadTrace(const QString& Path);
    void ClearTrace();

    QMap<Address, uint64_t> GetExecutionCounts() const;

signals:
    void TraceProgress(uint64_t Count);
    void TraceStopped(uint64_t TotalEntries);
    void TraceError(const QString& Error);

private:
    class TraceThread;

    void OnTraceEntry(const TraceEntry& Entry);

    mutable QMutex Mutex;
    QVector<TraceEntry> Entries;
    QMap<Address, uint64_t> ExecutionCounts;
    TraceFilter ActiveFilter;
    std::atomic<bool> Tracing;
    TraceThread* WorkerThread;
    int TracedPid;
};

}
