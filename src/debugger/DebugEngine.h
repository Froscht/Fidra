#pragma once

#include <fidra/Types.h>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <QList>
#include <QMap>
#include <QString>
#include <atomic>

namespace Fidra {

enum class DebugState {
    Idle,
    Running,
    Paused,
    Stopped
};

struct RegisterSet {
    uint64_t Rax, Rbx, Rcx, Rdx;
    uint64_t Rsi, Rdi, Rbp, Rsp;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t Rip;
    uint64_t Rflags;
    uint16_t Cs, Ds, Es, Fs, Gs, Ss;

    struct Xmm {
        uint64_t Low;
        uint64_t High;
    };
    Xmm XmmRegs[16];
};

struct StackFrame {
    Address ReturnAddress;
    Address FramePointer;
    Address StackPointer;
    QString ModuleName;
    QString FunctionName;
};

class DebugEngine : public QThread {
    Q_OBJECT

public:
    explicit DebugEngine(QObject* Parent = nullptr);
    ~DebugEngine() override;

    bool AttachToProcess(uint32_t Pid);
    bool LaunchProcess(const QString& Path, const QString& Args = {});
    void DetachFromProcess();

    DebugState CurrentState() const;

    void Continue();
    void StepInto();
    void StepOver();
    void StepOut();
    void Pause();
    void Stop();

    RegisterSet GetRegisters() const;
    bool SetRegisters(const RegisterSet& Regs);
    bool SetRegister(const QString& Name, uint64_t Value);

    bool AddBreakpoint(Address Addr, bool IsHardware = false);
    bool RemoveBreakpoint(Address Addr);
    bool EnableBreakpoint(Address Addr, bool Enabled);
    QList<Breakpoint> GetBreakpoints() const;

    QList<StackFrame> GetCallStack() const;

    bool ReadDebugMemory(Address Addr, void* Buffer, size_t Size);
    bool WriteDebugMemory(Address Addr, const void* Buffer, size_t Size);

signals:
    void StateChanged(Fidra::DebugState NewState);
    void BreakpointHit(Fidra::Address Addr);
    void SingleStepCompleted();
    void ProcessStarted(uint32_t Pid);
    void ProcessExited(int ExitCode);
    void DebugOutput(const QString& Message);
    void ExceptionOccurred(uint32_t Code, Fidra::Address Addr);
    void RegistersChanged();
    void BreakpointsChanged();

protected:
    void run() override;

private:
    enum class PendingAction {
        None,
        Continue,
        StepInto,
        StepOver,
        StepOut,
        Detach,
        Stop
    };

    struct SoftwareBreakpointInfo {
        Address Addr;
        uint8_t OriginalByte;
        bool Enabled;
        uint32_t HitCount;
        QString Condition;
        bool IsTemporary;
    };

    struct HardwareBreakpointInfo {
        Address Addr;
        int Slot;
        bool Enabled;
        uint32_t HitCount;
        QString Condition;
    };

    void SetState(DebugState NewState);
    void UpdateRegisters();
    void ApplyStepInto();
    void ApplyStepOver();
    void ApplyStepOut();
    bool IsCallInstruction(Address Addr, int& InstructionLength);
    void SetTrapFlag(bool Enable);
    bool InstallSoftwareBreakpoint(Address Addr);
    bool UninstallSoftwareBreakpoint(Address Addr);
    void ReapplyBreakpointAfterStep(Address Addr);
    int FindFreeHwSlot() const;
    bool ApplyHardwareBreakpoint(const HardwareBreakpointInfo& Info);
    bool RemoveHardwareBreakpoint(int Slot);
    void UpdateAllThreadHwBreakpoints();

    mutable QMutex Mutex;
    QWaitCondition WakeCondition;
    std::atomic<DebugState> State;
    std::atomic<PendingAction> Action;
    std::atomic<bool> ShouldStop;

    RegisterSet CachedRegisters;

    QMap<Address, SoftwareBreakpointInfo> SoftBreakpoints;
    QList<HardwareBreakpointInfo> HwBreakpoints;

    Address BreakpointToReapply;
    bool SteppingOverBreakpoint;
    Address TempBreakpointAddr;
    bool HasTempBreakpoint;
    bool InitialBreakpointHit;

#ifdef _WIN32
    void* ProcessHandle;
    uint32_t ProcessId;
    uint32_t MainThreadId;
    void* MainThreadHandle;
    QMap<uint32_t, void*> ThreadHandles;
    uint32_t ActiveThreadId;
#endif
};

}
