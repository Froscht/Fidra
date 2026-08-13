#pragma once

#include "AnalysisTypes.h"
#include "AnalysisDatabase.h"
#include "SignatureMatcher.h"
#include <QObject>
#include <QThread>
#include <QAtomicInt>
#include <QMutex>
#include <QWaitCondition>
#include <QElapsedTimer>

namespace Fidra {

class AnalysisWorker : public QObject {
    Q_OBJECT

public:
    explicit AnalysisWorker(AnalysisDatabase* Db, QObject* Parent = nullptr);
    ~AnalysisWorker() override;

    void Cancel();

public slots:
    void Run();

signals:
    void ProgressChanged(AnalysisProgress Progress);
    void Finished(bool Success);
    void LogMessage(const QString& Message);

private:
    void LoadBinary();
    void LoadPe(const QByteArray& Data);
    void LoadElf(const QByteArray& Data);
    void LoadMachO(const QByteArray& Data);

    void RunRecursiveDescent();
    void RunRecursiveDescentMT();
    void DisassembleFrom(Address Start);
    void DisassembleFromMT(Address Start, size_t CsHandle);
    void AddDisassemblyTarget(Address Addr);
    void AddDisassemblyTargetMT(Address Addr);

    void FindFunctions();
    void AnalyzeFunctions();
    void AnalyzeFunction(AnalyzedFunction& Func);
    void BuildBasicBlocks(AnalyzedFunction& Func, const QList<AnalyzedInstruction>& Insns);
    void ComputeDominance(AnalyzedFunction& Func);
    void DetectLoops(AnalyzedFunction& Func);
    void ComputeFunctionBoundaryCFG(AnalyzedFunction& Func, const QSet<Address>& OtherFuncStarts);
    CallingConvention DetectCallingConvention(const QList<AnalyzedInstruction>& Insns, bool Is64Bit);
    int ComputeStackFrameEquation(const QList<AnalyzedInstruction>& Insns, const QList<BasicBlock>& Blocks);
    int DetectArgCount(const QList<AnalyzedInstruction>& Insns, bool Is64Bit, CallingConvention Conv);
    void ResolveRelativeJumpTables(const BinaryInfo& Info);

    void FindStrings();
    bool IsAsciiString(const uint8_t* Data, size_t MaxLen, int& OutLen);
    bool IsWideString(const uint8_t* Data, size_t MaxLen, int& OutLen);

    void BuildXrefs();
    void FindStringReferences();

    void NameImportsExports();
    void DetectThunks();
    void ParsePdata();

    void RunLinearSweep();
    void ScanVtables();
    void ScanCodePointers();
    void FillCodeGaps();
    void DetectTailCallFunctions();
    void ResolveJumpTables();
    void MatchSignatures();
    void DemangleNames();
    void DemangleExtended();
    void DetectNonReturning();
    void ParseRtti();
    void ParseSeh();
    void GenerateAutoComments();
    void DetectPackerCompiler();

    void EmitProgress(AnalysisState State, int Percentage, const QString& Message);

    AnalysisDatabase* Db;
    QAtomicInt Cancelled;

    QSet<Address> VisitedAddresses;
    QList<Address> DisassemblyQueue;
    QSet<Address> FunctionStarts;

    QMutex QueueMutex;
    QSet<Address> VisitedMT;
    QList<Address> QueueMT;
    QSet<Address> QueuedSetMT;
    QAtomicInt ActiveWorkers;
    QAtomicInt TotalDisasmMT;

    SignatureMatcher SigMatcher;

    QElapsedTimer AnalysisTimer;
    QString CurrentSectionName;
    Address CurrentAnalysisAddr = 0;
};

class AnalysisEngine : public QObject {
    Q_OBJECT

public:
    explicit AnalysisEngine(QObject* Parent = nullptr);
    ~AnalysisEngine() override;

    bool LoadFile(const QString& FilePath);
    void CancelAnalysis();
    bool IsAnalyzing() const;

    AnalysisDatabase* Database() const;
    AnalysisProgress CurrentProgress() const;

signals:
    void AnalysisStarted(const QString& FilePath);
    void ProgressChanged(AnalysisProgress Progress);
    void AnalysisFinished(bool Success);
    void LogMessage(const QString& Message);

private:
    AnalysisDatabase* Db;
    QThread* WorkerThread;
    AnalysisWorker* Worker;
    AnalysisProgress LastProgress;
    bool Analyzing;
};

}
