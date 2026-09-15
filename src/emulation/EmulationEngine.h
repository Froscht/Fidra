#pragma once

#include <fidra/Types.h>
#include <QString>
#include <QByteArray>
#include <QVector>
#include <cstdint>

namespace Fidra {

class AnalysisDatabase;

struct EmulationTraceEntry {
    Address Pc;
    uint32_t InsnSize;
    uint64_t Rax, Rbx, Rcx, Rdx;
    uint64_t Rsi, Rdi, Rbp, Rsp;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t Rip, Rflags;
};

struct EmulationResult {
    bool Ok = false;
    QString Error;
    Address FinalPc = 0;
    QVector<EmulationTraceEntry> Trace;
    QVector<QString> MemoryEvents;
};

class EmulationEngine {
public:
    EmulationEngine();
    ~EmulationEngine();

    static bool IsAvailable();

    bool Open(Architecture Arch);
    void Close();

    bool MapAllSegments(const AnalysisDatabase& Db);
    bool MapStack(Address Base, size_t Size);

    bool SetRip(Address Value);
    bool SetRegister(int RegisterId, uint64_t Value);
    bool WriteMemory(Address Addr, const QByteArray& Data);

    EmulationResult EmulateFunction(const AnalysisDatabase& Db, Address FunctionStart, size_t MaxInsn = 10000, uint64_t TimeoutUs = 5000000);

private:
    void* Uc;
    Architecture CurrentArch;
};

}
