#include "DebugEngine.h"
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#include <TlHelp32.h>
#endif

namespace Fidra {

DebugEngine::DebugEngine(QObject* Parent)
    : QThread(Parent)
    , State(DebugState::Idle)
    , Action(PendingAction::None)
    , ShouldStop(false)
    , CachedRegisters{}
    , BreakpointToReapply(0)
    , SteppingOverBreakpoint(false)
    , TempBreakpointAddr(0)
    , HasTempBreakpoint(false)
    , InitialBreakpointHit(false)
#ifdef _WIN32
    , ProcessHandle(nullptr)
    , ProcessId(0)
    , MainThreadId(0)
    , MainThreadHandle(nullptr)
    , ActiveThreadId(0)
#endif
{
}

DebugEngine::~DebugEngine() {
    Stop();
    if (isRunning()) {
        wait(5000);
    }
}

bool DebugEngine::AttachToProcess(uint32_t Pid) {
#ifdef _WIN32
    if (State.load() != DebugState::Idle) {
        return false;
    }

    if (!DebugActiveProcess(Pid)) {
        return false;
    }

    DebugSetProcessKillOnExit(FALSE);

    ProcessId = Pid;
    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (!ProcessHandle) {
        DebugActiveProcessStop(Pid);
        return false;
    }

    ShouldStop.store(false);
    InitialBreakpointHit = false;
    start();
    return true;
#else
    Q_UNUSED(Pid);
    return false;
#endif
}

bool DebugEngine::LaunchProcess(const QString& Path, const QString& Args) {
#ifdef _WIN32
    if (State.load() != DebugState::Idle) {
        return false;
    }

    STARTUPINFOW Si = {};
    Si.cb = sizeof(Si);
    PROCESS_INFORMATION Pi = {};

    QString CmdLine = QString("\"%1\" %2").arg(Path, Args);
    QByteArray CmdLineUtf16 = QByteArray(reinterpret_cast<const char*>(CmdLine.utf16()),
                                          (CmdLine.size() + 1) * 2);

    if (!CreateProcessW(nullptr,
                        reinterpret_cast<LPWSTR>(CmdLineUtf16.data()),
                        nullptr, nullptr, FALSE,
                        DEBUG_PROCESS | CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &Si, &Pi)) {
        return false;
    }

    ProcessHandle = Pi.hProcess;
    ProcessId = Pi.dwProcessId;
    MainThreadId = Pi.dwThreadId;
    MainThreadHandle = Pi.hThread;
    ThreadHandles[MainThreadId] = MainThreadHandle;

    DebugSetProcessKillOnExit(FALSE);

    ShouldStop.store(false);
    InitialBreakpointHit = false;
    start();
    return true;
#else
    Q_UNUSED(Path);
    Q_UNUSED(Args);
    return false;
#endif
}

void DebugEngine::DetachFromProcess() {
    Action.store(PendingAction::Detach);
    if (State.load() == DebugState::Paused) {
        WakeCondition.wakeAll();
    }
}

DebugState DebugEngine::CurrentState() const {
    return State.load();
}

void DebugEngine::Continue() {
    Action.store(PendingAction::Continue);
    WakeCondition.wakeAll();
}

void DebugEngine::StepInto() {
    Action.store(PendingAction::StepInto);
    WakeCondition.wakeAll();
}

void DebugEngine::StepOver() {
    Action.store(PendingAction::StepOver);
    WakeCondition.wakeAll();
}

void DebugEngine::StepOut() {
    Action.store(PendingAction::StepOut);
    WakeCondition.wakeAll();
}

void DebugEngine::Pause() {
#ifdef _WIN32
    if (State.load() == DebugState::Running && ProcessId != 0) {
        DebugBreakProcess(ProcessHandle);
    }
#endif
}

void DebugEngine::Stop() {
    Action.store(PendingAction::Stop);
    ShouldStop.store(true);
    WakeCondition.wakeAll();
}

RegisterSet DebugEngine::GetRegisters() const {
    QMutexLocker Lock(&Mutex);
    return CachedRegisters;
}

bool DebugEngine::SetRegisters(const RegisterSet& Regs) {
#ifdef _WIN32
    QMutexLocker Lock(&Mutex);
    if (State.load() != DebugState::Paused || ActiveThreadId == 0) {
        return false;
    }

    void* ThreadHandle = ThreadHandles.value(ActiveThreadId, nullptr);
    if (!ThreadHandle) {
        return false;
    }

    CONTEXT Ctx = {};
    Ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(ThreadHandle, &Ctx)) {
        return false;
    }

    Ctx.Rax = Regs.Rax;
    Ctx.Rbx = Regs.Rbx;
    Ctx.Rcx = Regs.Rcx;
    Ctx.Rdx = Regs.Rdx;
    Ctx.Rsi = Regs.Rsi;
    Ctx.Rdi = Regs.Rdi;
    Ctx.Rbp = Regs.Rbp;
    Ctx.Rsp = Regs.Rsp;
    Ctx.R8 = Regs.R8;
    Ctx.R9 = Regs.R9;
    Ctx.R10 = Regs.R10;
    Ctx.R11 = Regs.R11;
    Ctx.R12 = Regs.R12;
    Ctx.R13 = Regs.R13;
    Ctx.R14 = Regs.R14;
    Ctx.R15 = Regs.R15;
    Ctx.Rip = Regs.Rip;
    Ctx.EFlags = static_cast<DWORD>(Regs.Rflags);
    Ctx.SegCs = Regs.Cs;
    Ctx.SegDs = Regs.Ds;
    Ctx.SegEs = Regs.Es;
    Ctx.SegFs = Regs.Fs;
    Ctx.SegGs = Regs.Gs;
    Ctx.SegSs = Regs.Ss;

    for (int I = 0; I < 16; ++I) {
        memcpy(&Ctx.FltSave.XmmRegisters[I], &Regs.XmmRegs[I], sizeof(M128A));
    }

    if (!SetThreadContext(ThreadHandle, &Ctx)) {
        return false;
    }

    CachedRegisters = Regs;
    emit RegistersChanged();
    return true;
#else
    Q_UNUSED(Regs);
    return false;
#endif
}

bool DebugEngine::SetRegister(const QString& Name, uint64_t Value) {
    QMutexLocker Lock(&Mutex);
    RegisterSet Regs = CachedRegisters;

    if (Name == "RAX") Regs.Rax = Value;
    else if (Name == "RBX") Regs.Rbx = Value;
    else if (Name == "RCX") Regs.Rcx = Value;
    else if (Name == "RDX") Regs.Rdx = Value;
    else if (Name == "RSI") Regs.Rsi = Value;
    else if (Name == "RDI") Regs.Rdi = Value;
    else if (Name == "RBP") Regs.Rbp = Value;
    else if (Name == "RSP") Regs.Rsp = Value;
    else if (Name == "R8") Regs.R8 = Value;
    else if (Name == "R9") Regs.R9 = Value;
    else if (Name == "R10") Regs.R10 = Value;
    else if (Name == "R11") Regs.R11 = Value;
    else if (Name == "R12") Regs.R12 = Value;
    else if (Name == "R13") Regs.R13 = Value;
    else if (Name == "R14") Regs.R14 = Value;
    else if (Name == "R15") Regs.R15 = Value;
    else if (Name == "RIP") Regs.Rip = Value;
    else if (Name == "RFLAGS") Regs.Rflags = Value;
    else return false;

    Lock.unlock();
    return SetRegisters(Regs);
}

bool DebugEngine::AddBreakpoint(Address Addr, bool IsHardware) {
    QMutexLocker Lock(&Mutex);

    if (IsHardware) {
        int Slot = FindFreeHwSlot();
        if (Slot < 0) {
            return false;
        }

        HardwareBreakpointInfo Info;
        Info.Addr = Addr;
        Info.Slot = Slot;
        Info.Enabled = true;
        Info.HitCount = 0;

        HwBreakpoints.append(Info);

        if (State.load() == DebugState::Paused) {
            ApplyHardwareBreakpoint(Info);
        }
    } else {
        if (SoftBreakpoints.contains(Addr)) {
            return false;
        }

        SoftwareBreakpointInfo Info;
        Info.Addr = Addr;
        Info.OriginalByte = 0;
        Info.Enabled = true;
        Info.HitCount = 0;
        Info.IsTemporary = false;

        SoftBreakpoints[Addr] = Info;

        if (State.load() != DebugState::Idle) {
            InstallSoftwareBreakpoint(Addr);
        }
    }

    emit BreakpointsChanged();
    return true;
}

bool DebugEngine::RemoveBreakpoint(Address Addr) {
    QMutexLocker Lock(&Mutex);

    if (SoftBreakpoints.contains(Addr)) {
        if (State.load() != DebugState::Idle && SoftBreakpoints[Addr].Enabled) {
            UninstallSoftwareBreakpoint(Addr);
        }
        SoftBreakpoints.remove(Addr);
        emit BreakpointsChanged();
        return true;
    }

    for (int I = 0; I < HwBreakpoints.size(); ++I) {
        if (HwBreakpoints[I].Addr == Addr) {
            if (State.load() != DebugState::Idle) {
                RemoveHardwareBreakpoint(HwBreakpoints[I].Slot);
            }
            HwBreakpoints.removeAt(I);
            emit BreakpointsChanged();
            return true;
        }
    }

    return false;
}

bool DebugEngine::EnableBreakpoint(Address Addr, bool Enabled) {
    QMutexLocker Lock(&Mutex);

    if (SoftBreakpoints.contains(Addr)) {
        auto& Bp = SoftBreakpoints[Addr];
        if (Bp.Enabled == Enabled) {
            return true;
        }

        Bp.Enabled = Enabled;
        if (State.load() != DebugState::Idle) {
            if (Enabled) {
                InstallSoftwareBreakpoint(Addr);
            } else {
                UninstallSoftwareBreakpoint(Addr);
            }
        }
        emit BreakpointsChanged();
        return true;
    }

    for (auto& Hw : HwBreakpoints) {
        if (Hw.Addr == Addr) {
            Hw.Enabled = Enabled;
            if (State.load() != DebugState::Idle) {
                UpdateAllThreadHwBreakpoints();
            }
            emit BreakpointsChanged();
            return true;
        }
    }

    return false;
}

QList<Breakpoint> DebugEngine::GetBreakpoints() const {
    QMutexLocker Lock(&Mutex);
    QList<Breakpoint> Result;

    for (auto It = SoftBreakpoints.constBegin(); It != SoftBreakpoints.constEnd(); ++It) {
        if (It->IsTemporary) {
            continue;
        }
        Breakpoint Bp;
        Bp.Location = It->Addr;
        Bp.Enabled = It->Enabled;
        Bp.IsHardware = false;
        Bp.HitCount = It->HitCount;
        Bp.Condition = It->Condition;
        Result.append(Bp);
    }

    for (const auto& Hw : HwBreakpoints) {
        Breakpoint Bp;
        Bp.Location = Hw.Addr;
        Bp.Enabled = Hw.Enabled;
        Bp.IsHardware = true;
        Bp.HitCount = Hw.HitCount;
        Bp.Condition = Hw.Condition;
        Result.append(Bp);
    }

    return Result;
}

QList<StackFrame> DebugEngine::GetCallStack() const {
    QList<StackFrame> Frames;
#ifdef _WIN32
    QMutexLocker Lock(&Mutex);

    if (State.load() != DebugState::Paused || !ProcessHandle) {
        return Frames;
    }

    StackFrame TopFrame;
    TopFrame.ReturnAddress = CachedRegisters.Rip;
    TopFrame.FramePointer = CachedRegisters.Rbp;
    TopFrame.StackPointer = CachedRegisters.Rsp;
    Frames.append(TopFrame);

    Address CurrentRbp = CachedRegisters.Rbp;
    Address CurrentRsp = CachedRegisters.Rsp;

    for (int Depth = 0; Depth < 256; ++Depth) {
        if (CurrentRbp == 0 || CurrentRbp < CurrentRsp) {
            break;
        }

        uint64_t SavedRbp = 0;
        uint64_t RetAddr = 0;
        SIZE_T BytesRead = 0;

        if (!::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(CurrentRbp),
                                 &SavedRbp, sizeof(SavedRbp), &BytesRead) || BytesRead != sizeof(SavedRbp)) {
            break;
        }

        if (!::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(CurrentRbp + 8),
                                 &RetAddr, sizeof(RetAddr), &BytesRead) || BytesRead != sizeof(RetAddr)) {
            break;
        }

        if (RetAddr == 0) {
            break;
        }

        StackFrame Frame;
        Frame.ReturnAddress = RetAddr;
        Frame.FramePointer = SavedRbp;
        Frame.StackPointer = CurrentRbp + 16;
        Frames.append(Frame);

        if (SavedRbp <= CurrentRbp) {
            break;
        }

        CurrentRsp = CurrentRbp + 16;
        CurrentRbp = SavedRbp;
    }
#endif
    return Frames;
}

bool DebugEngine::ReadDebugMemory(Address Addr, void* Buffer, size_t Size) {
#ifdef _WIN32
    if (!ProcessHandle) {
        return false;
    }
    SIZE_T BytesRead = 0;
    return ::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(Addr),
                               Buffer, Size, &BytesRead) && BytesRead == Size;
#else
    Q_UNUSED(Addr);
    Q_UNUSED(Buffer);
    Q_UNUSED(Size);
    return false;
#endif
}

bool DebugEngine::WriteDebugMemory(Address Addr, const void* Buffer, size_t Size) {
#ifdef _WIN32
    if (!ProcessHandle) {
        return false;
    }
    SIZE_T BytesWritten = 0;
    DWORD OldProtect = 0;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), Size, PAGE_EXECUTE_READWRITE, &OldProtect);
    bool Result = ::WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Addr),
                                       Buffer, Size, &BytesWritten) && BytesWritten == Size;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), Size, OldProtect, &OldProtect);
    FlushInstructionCache(ProcessHandle, reinterpret_cast<LPCVOID>(Addr), Size);
    return Result;
#else
    Q_UNUSED(Addr);
    Q_UNUSED(Buffer);
    Q_UNUSED(Size);
    return false;
#endif
}

void DebugEngine::run() {
#ifdef _WIN32
    SetState(DebugState::Running);

    DEBUG_EVENT DebugEvent = {};
    bool KeepRunning = true;

    while (KeepRunning && !ShouldStop.load()) {
        if (!WaitForDebugEvent(&DebugEvent, 100)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) {
                PendingAction CurrentAction = Action.load();
                if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                    KeepRunning = false;
                }
                continue;
            }
            break;
        }

        DWORD ContinueStatus = DBG_CONTINUE;
        ActiveThreadId = DebugEvent.dwThreadId;

        switch (DebugEvent.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            if (MainThreadHandle == nullptr) {
                MainThreadId = DebugEvent.dwThreadId;
                MainThreadHandle = DebugEvent.u.CreateProcessInfo.hThread;
                ProcessHandle = DebugEvent.u.CreateProcessInfo.hProcess;
                ThreadHandles[MainThreadId] = MainThreadHandle;
            }
            if (DebugEvent.u.CreateProcessInfo.hFile) {
                CloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
            }
            emit ProcessStarted(DebugEvent.dwProcessId);
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT: {
            int ExitCode = static_cast<int>(DebugEvent.u.ExitProcess.dwExitCode);
            ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus);
            SetState(DebugState::Stopped);
            emit ProcessExited(ExitCode);
            KeepRunning = false;
            continue;
        }

        case CREATE_THREAD_DEBUG_EVENT: {
            ThreadHandles[DebugEvent.dwThreadId] = DebugEvent.u.CreateThread.hThread;
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT: {
            ThreadHandles.remove(DebugEvent.dwThreadId);
            break;
        }

        case LOAD_DLL_DEBUG_EVENT: {
            if (DebugEvent.u.LoadDll.hFile) {
                CloseHandle(DebugEvent.u.LoadDll.hFile);
            }
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT: {
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT: {
            OUTPUT_DEBUG_STRING_INFO& DebugStr = DebugEvent.u.DebugString;
            QByteArray StrBuffer(DebugStr.nDebugStringLength, 0);
            SIZE_T BytesRead = 0;
            if (::ReadProcessMemory(ProcessHandle, DebugStr.lpDebugStringData,
                                    StrBuffer.data(), DebugStr.nDebugStringLength, &BytesRead)) {
                QString Msg;
                if (DebugStr.fUnicode) {
                    Msg = QString::fromUtf16(reinterpret_cast<const char16_t*>(StrBuffer.constData()));
                } else {
                    Msg = QString::fromLocal8Bit(StrBuffer.constData());
                }
                emit DebugOutput(Msg.trimmed());
            }
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD& ExRec = DebugEvent.u.Exception.ExceptionRecord;
            Address ExAddr = static_cast<Address>(reinterpret_cast<uintptr_t>(ExRec.ExceptionAddress));

            if (ExRec.ExceptionCode == EXCEPTION_BREAKPOINT) {
                if (!InitialBreakpointHit) {
                    InitialBreakpointHit = true;

                    {
                        QMutexLocker Lock(&Mutex);
                        for (auto It = SoftBreakpoints.begin(); It != SoftBreakpoints.end(); ++It) {
                            if (It->Enabled) {
                                InstallSoftwareBreakpoint(It.key());
                            }
                        }
                        UpdateAllThreadHwBreakpoints();
                    }

                    UpdateRegisters();
                    SetState(DebugState::Paused);

                    {
                        QMutexLocker Lock(&Mutex);
                        while (State.load() == DebugState::Paused && !ShouldStop.load()) {
                            PendingAction CurrentAction = Action.exchange(PendingAction::None);
                            if (CurrentAction == PendingAction::Continue) {
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepInto) {
                                ApplyStepInto();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOver) {
                                ApplyStepOver();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOut) {
                                ApplyStepOut();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                                KeepRunning = false;
                                break;
                            }
                            WakeCondition.wait(&Mutex, 50);
                        }
                    }
                    ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus);
                    continue;
                }

                QMutexLocker Lock(&Mutex);
                Address BpAddr = ExAddr - 1;

                if (SoftBreakpoints.contains(BpAddr)) {
                    auto& BpInfo = SoftBreakpoints[BpAddr];
                    BpInfo.HitCount++;

                    UninstallSoftwareBreakpoint(BpAddr);

                    void* ThreadHandle = ThreadHandles.value(DebugEvent.dwThreadId, nullptr);
                    if (ThreadHandle) {
                        CONTEXT Ctx = {};
                        Ctx.ContextFlags = CONTEXT_CONTROL;
                        GetThreadContext(ThreadHandle, &Ctx);
                        Ctx.Rip = BpAddr;
                        SetThreadContext(ThreadHandle, &Ctx);
                    }

                    if (BpInfo.IsTemporary) {
                        SoftBreakpoints.remove(BpAddr);
                        HasTempBreakpoint = false;
                    } else {
                        BreakpointToReapply = BpAddr;
                        SteppingOverBreakpoint = true;
                        SetTrapFlag(true);

                        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus);
                        continue;
                    }

                    Lock.unlock();
                    UpdateRegisters();
                    SetState(DebugState::Paused);
                    emit BreakpointHit(BpAddr);

                    Lock.relock();
                    while (State.load() == DebugState::Paused && !ShouldStop.load()) {
                        PendingAction CurrentAction = Action.exchange(PendingAction::None);
                        if (CurrentAction == PendingAction::Continue) {
                            SetState(DebugState::Running);
                            break;
                        } else if (CurrentAction == PendingAction::StepInto) {
                            ApplyStepInto();
                            SetState(DebugState::Running);
                            break;
                        } else if (CurrentAction == PendingAction::StepOver) {
                            ApplyStepOver();
                            SetState(DebugState::Running);
                            break;
                        } else if (CurrentAction == PendingAction::StepOut) {
                            ApplyStepOut();
                            SetState(DebugState::Running);
                            break;
                        } else if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                            KeepRunning = false;
                            break;
                        }
                        WakeCondition.wait(&Mutex, 50);
                    }
                } else {
                    Lock.unlock();
                    ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            }

            if (ExRec.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                QMutexLocker Lock(&Mutex);

                bool HwBpHit = false;
                for (auto& Hw : HwBreakpoints) {
                    if (Hw.Enabled && Hw.Addr == ExAddr) {
                        Hw.HitCount++;
                        HwBpHit = true;

                        Lock.unlock();
                        UpdateRegisters();
                        SetState(DebugState::Paused);
                        emit BreakpointHit(ExAddr);

                        Lock.relock();
                        while (State.load() == DebugState::Paused && !ShouldStop.load()) {
                            PendingAction CurrentAction = Action.exchange(PendingAction::None);
                            if (CurrentAction == PendingAction::Continue) {
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepInto) {
                                ApplyStepInto();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOver) {
                                ApplyStepOver();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOut) {
                                ApplyStepOut();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                                KeepRunning = false;
                                break;
                            }
                            WakeCondition.wait(&Mutex, 50);
                        }
                        break;
                    }
                }

                if (!HwBpHit) {
                    if (SteppingOverBreakpoint) {
                        SteppingOverBreakpoint = false;
                        InstallSoftwareBreakpoint(BreakpointToReapply);
                        BreakpointToReapply = 0;
                    } else {
                        Lock.unlock();
                        UpdateRegisters();
                        SetState(DebugState::Paused);
                        emit SingleStepCompleted();

                        Lock.relock();
                        while (State.load() == DebugState::Paused && !ShouldStop.load()) {
                            PendingAction CurrentAction = Action.exchange(PendingAction::None);
                            if (CurrentAction == PendingAction::Continue) {
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepInto) {
                                ApplyStepInto();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOver) {
                                ApplyStepOver();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::StepOut) {
                                ApplyStepOut();
                                SetState(DebugState::Running);
                                break;
                            } else if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                                KeepRunning = false;
                                break;
                            }
                            WakeCondition.wait(&Mutex, 50);
                        }
                    }
                }
                break;
            }

            if (DebugEvent.u.Exception.dwFirstChance) {
                emit ExceptionOccurred(ExRec.ExceptionCode, ExAddr);
                ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
            } else {
                UpdateRegisters();
                SetState(DebugState::Paused);
                emit ExceptionOccurred(ExRec.ExceptionCode, ExAddr);

                QMutexLocker Lock(&Mutex);
                while (State.load() == DebugState::Paused && !ShouldStop.load()) {
                    PendingAction CurrentAction = Action.exchange(PendingAction::None);
                    if (CurrentAction == PendingAction::Continue) {
                        ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        SetState(DebugState::Running);
                        break;
                    } else if (CurrentAction == PendingAction::Stop || CurrentAction == PendingAction::Detach) {
                        KeepRunning = false;
                        break;
                    }
                    WakeCondition.wait(&Mutex, 50);
                }
            }
            break;
        }

        default:
            break;
        }

        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus);
    }

    {
        QMutexLocker Lock(&Mutex);
        for (auto It = SoftBreakpoints.begin(); It != SoftBreakpoints.end(); ++It) {
            if (It->Enabled && It->OriginalByte != 0) {
                UninstallSoftwareBreakpoint(It.key());
            }
        }
    }

    PendingAction FinalAction = Action.load();
    if (FinalAction == PendingAction::Detach) {
        DebugActiveProcessStop(ProcessId);
    } else if (FinalAction == PendingAction::Stop) {
        TerminateProcess(ProcessHandle, 0);
    }

    if (ProcessHandle && MainThreadHandle != ProcessHandle) {
        CloseHandle(ProcessHandle);
    }

    ProcessHandle = nullptr;
    MainThreadHandle = nullptr;
    ProcessId = 0;
    MainThreadId = 0;
    ActiveThreadId = 0;
    ThreadHandles.clear();

    SetState(DebugState::Idle);
    ShouldStop.store(false);
    Action.store(PendingAction::None);
#endif
}

void DebugEngine::SetState(DebugState NewState) {
    State.store(NewState);
    emit StateChanged(NewState);
}

void DebugEngine::UpdateRegisters() {
#ifdef _WIN32
    QMutexLocker Lock(&Mutex);

    void* ThreadHandle = ThreadHandles.value(ActiveThreadId, nullptr);
    if (!ThreadHandle) {
        return;
    }

    CONTEXT Ctx = {};
    Ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(ThreadHandle, &Ctx)) {
        return;
    }

    CachedRegisters.Rax = Ctx.Rax;
    CachedRegisters.Rbx = Ctx.Rbx;
    CachedRegisters.Rcx = Ctx.Rcx;
    CachedRegisters.Rdx = Ctx.Rdx;
    CachedRegisters.Rsi = Ctx.Rsi;
    CachedRegisters.Rdi = Ctx.Rdi;
    CachedRegisters.Rbp = Ctx.Rbp;
    CachedRegisters.Rsp = Ctx.Rsp;
    CachedRegisters.R8 = Ctx.R8;
    CachedRegisters.R9 = Ctx.R9;
    CachedRegisters.R10 = Ctx.R10;
    CachedRegisters.R11 = Ctx.R11;
    CachedRegisters.R12 = Ctx.R12;
    CachedRegisters.R13 = Ctx.R13;
    CachedRegisters.R14 = Ctx.R14;
    CachedRegisters.R15 = Ctx.R15;
    CachedRegisters.Rip = Ctx.Rip;
    CachedRegisters.Rflags = Ctx.EFlags;
    CachedRegisters.Cs = Ctx.SegCs;
    CachedRegisters.Ds = Ctx.SegDs;
    CachedRegisters.Es = Ctx.SegEs;
    CachedRegisters.Fs = Ctx.SegFs;
    CachedRegisters.Gs = Ctx.SegGs;
    CachedRegisters.Ss = Ctx.SegSs;

    for (int I = 0; I < 16; ++I) {
        memcpy(&CachedRegisters.XmmRegs[I], &Ctx.FltSave.XmmRegisters[I], sizeof(RegisterSet::Xmm));
    }

    emit RegistersChanged();
#endif
}

void DebugEngine::ApplyStepInto() {
    SetTrapFlag(true);
}

void DebugEngine::ApplyStepOver() {
#ifdef _WIN32
    int InstrLen = 0;
    Address CurrentRip = CachedRegisters.Rip;

    if (IsCallInstruction(CurrentRip, InstrLen)) {
        Address NextAddr = CurrentRip + InstrLen;

        SoftwareBreakpointInfo TempBp;
        TempBp.Addr = NextAddr;
        TempBp.OriginalByte = 0;
        TempBp.Enabled = true;
        TempBp.HitCount = 0;
        TempBp.IsTemporary = true;

        SoftBreakpoints[NextAddr] = TempBp;
        InstallSoftwareBreakpoint(NextAddr);
        HasTempBreakpoint = true;
        TempBreakpointAddr = NextAddr;
    } else {
        SetTrapFlag(true);
    }
#endif
}

void DebugEngine::ApplyStepOut() {
#ifdef _WIN32
    uint64_t RetAddr = 0;
    SIZE_T BytesRead = 0;
    if (::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(CachedRegisters.Rsp),
                            &RetAddr, sizeof(RetAddr), &BytesRead) && BytesRead == sizeof(RetAddr) && RetAddr != 0) {
        SoftwareBreakpointInfo TempBp;
        TempBp.Addr = RetAddr;
        TempBp.OriginalByte = 0;
        TempBp.Enabled = true;
        TempBp.HitCount = 0;
        TempBp.IsTemporary = true;

        SoftBreakpoints[RetAddr] = TempBp;
        InstallSoftwareBreakpoint(RetAddr);
        HasTempBreakpoint = true;
        TempBreakpointAddr = RetAddr;
    }
#endif
}

bool DebugEngine::IsCallInstruction(Address Addr, int& InstructionLength) {
#ifdef _WIN32
    uint8_t Buf[16] = {};
    SIZE_T BytesRead = 0;
    if (!::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(Addr), Buf, sizeof(Buf), &BytesRead)) {
        return false;
    }

    if (Buf[0] == 0xE8) {
        InstructionLength = 5;
        return true;
    }

    if (Buf[0] == 0xFF) {
        uint8_t ModRm = Buf[1];
        uint8_t Reg = (ModRm >> 3) & 7;
        if (Reg == 2 || Reg == 3) {
            uint8_t Mod = (ModRm >> 6) & 3;
            uint8_t Rm = ModRm & 7;
            int Len = 2;

            if (Rm == 4 && Mod != 3) {
                Len++;
            }

            if (Mod == 1) {
                Len++;
            } else if (Mod == 2) {
                Len += 4;
            } else if (Mod == 0 && Rm == 5) {
                Len += 4;
            }

            InstructionLength = Len;
            return true;
        }
    }

    if (Buf[0] == 0x9A) {
        InstructionLength = 7;
        return true;
    }

    int PrefixLen = 0;
    if ((Buf[0] & 0xF0) == 0x40) {
        PrefixLen = 1;
    }

    if (Buf[PrefixLen] == 0xFF) {
        uint8_t ModRm = Buf[PrefixLen + 1];
        uint8_t Reg = (ModRm >> 3) & 7;
        if (Reg == 2 || Reg == 3) {
            uint8_t Mod = (ModRm >> 6) & 3;
            uint8_t Rm = ModRm & 7;
            int Len = PrefixLen + 2;

            if (Rm == 4 && Mod != 3) {
                Len++;
            }

            if (Mod == 1) {
                Len++;
            } else if (Mod == 2) {
                Len += 4;
            } else if (Mod == 0 && Rm == 5) {
                Len += 4;
            }

            InstructionLength = Len;
            return true;
        }
    }

    return false;
#else
    Q_UNUSED(Addr);
    Q_UNUSED(InstructionLength);
    return false;
#endif
}

void DebugEngine::SetTrapFlag(bool Enable) {
#ifdef _WIN32
    void* ThreadHandle = ThreadHandles.value(ActiveThreadId, nullptr);
    if (!ThreadHandle) {
        return;
    }

    CONTEXT Ctx = {};
    Ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(ThreadHandle, &Ctx)) {
        return;
    }

    if (Enable) {
        Ctx.EFlags |= 0x100;
    } else {
        Ctx.EFlags &= ~0x100;
    }

    SetThreadContext(ThreadHandle, &Ctx);
#else
    Q_UNUSED(Enable);
#endif
}

bool DebugEngine::InstallSoftwareBreakpoint(Address Addr) {
#ifdef _WIN32
    if (!ProcessHandle) {
        return false;
    }

    uint8_t OrigByte = 0;
    SIZE_T BytesRead = 0;
    if (!::ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(Addr),
                             &OrigByte, 1, &BytesRead) || BytesRead != 1) {
        return false;
    }

    if (SoftBreakpoints.contains(Addr)) {
        SoftBreakpoints[Addr].OriginalByte = OrigByte;
    }

    uint8_t Int3 = 0xCC;
    DWORD OldProtect = 0;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
    SIZE_T BytesWritten = 0;
    bool Ok = ::WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Addr),
                                   &Int3, 1, &BytesWritten) && BytesWritten == 1;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), 1, OldProtect, &OldProtect);
    FlushInstructionCache(ProcessHandle, reinterpret_cast<LPCVOID>(Addr), 1);

    return Ok;
#else
    Q_UNUSED(Addr);
    return false;
#endif
}

bool DebugEngine::UninstallSoftwareBreakpoint(Address Addr) {
#ifdef _WIN32
    if (!ProcessHandle || !SoftBreakpoints.contains(Addr)) {
        return false;
    }

    uint8_t OrigByte = SoftBreakpoints[Addr].OriginalByte;

    DWORD OldProtect = 0;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
    SIZE_T BytesWritten = 0;
    bool Ok = ::WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Addr),
                                   &OrigByte, 1, &BytesWritten) && BytesWritten == 1;
    VirtualProtectEx(ProcessHandle, reinterpret_cast<LPVOID>(Addr), 1, OldProtect, &OldProtect);
    FlushInstructionCache(ProcessHandle, reinterpret_cast<LPCVOID>(Addr), 1);

    return Ok;
#else
    Q_UNUSED(Addr);
    return false;
#endif
}

void DebugEngine::ReapplyBreakpointAfterStep(Address Addr) {
    InstallSoftwareBreakpoint(Addr);
}

int DebugEngine::FindFreeHwSlot() const {
    bool UsedSlots[4] = { false, false, false, false };
    for (const auto& Hw : HwBreakpoints) {
        if (Hw.Slot >= 0 && Hw.Slot < 4) {
            UsedSlots[Hw.Slot] = true;
        }
    }
    for (int I = 0; I < 4; ++I) {
        if (!UsedSlots[I]) {
            return I;
        }
    }
    return -1;
}

bool DebugEngine::ApplyHardwareBreakpoint(const HardwareBreakpointInfo& Info) {
#ifdef _WIN32
    for (auto It = ThreadHandles.constBegin(); It != ThreadHandles.constEnd(); ++It) {
        void* ThreadHandle = It.value();
        CONTEXT Ctx = {};
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(ThreadHandle, &Ctx)) {
            continue;
        }

        switch (Info.Slot) {
        case 0: Ctx.Dr0 = Info.Addr; break;
        case 1: Ctx.Dr1 = Info.Addr; break;
        case 2: Ctx.Dr2 = Info.Addr; break;
        case 3: Ctx.Dr3 = Info.Addr; break;
        }

        Ctx.Dr7 |= (1ULL << (Info.Slot * 2));
        Ctx.Dr7 &= ~(0xFULL << (16 + Info.Slot * 4));

        SetThreadContext(ThreadHandle, &Ctx);
    }
    return true;
#else
    Q_UNUSED(Info);
    return false;
#endif
}

bool DebugEngine::RemoveHardwareBreakpoint(int Slot) {
#ifdef _WIN32
    for (auto It = ThreadHandles.constBegin(); It != ThreadHandles.constEnd(); ++It) {
        void* ThreadHandle = It.value();
        CONTEXT Ctx = {};
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(ThreadHandle, &Ctx)) {
            continue;
        }

        switch (Slot) {
        case 0: Ctx.Dr0 = 0; break;
        case 1: Ctx.Dr1 = 0; break;
        case 2: Ctx.Dr2 = 0; break;
        case 3: Ctx.Dr3 = 0; break;
        }

        Ctx.Dr7 &= ~(1ULL << (Slot * 2));
        Ctx.Dr7 &= ~(0xFULL << (16 + Slot * 4));

        SetThreadContext(ThreadHandle, &Ctx);
    }
    return true;
#else
    Q_UNUSED(Slot);
    return false;
#endif
}

void DebugEngine::UpdateAllThreadHwBreakpoints() {
#ifdef _WIN32
    for (auto It = ThreadHandles.constBegin(); It != ThreadHandles.constEnd(); ++It) {
        void* ThreadHandle = It.value();
        CONTEXT Ctx = {};
        Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(ThreadHandle, &Ctx)) {
            continue;
        }

        Ctx.Dr0 = 0;
        Ctx.Dr1 = 0;
        Ctx.Dr2 = 0;
        Ctx.Dr3 = 0;
        Ctx.Dr7 = 0;

        for (const auto& Hw : HwBreakpoints) {
            if (!Hw.Enabled) {
                continue;
            }
            switch (Hw.Slot) {
            case 0: Ctx.Dr0 = Hw.Addr; break;
            case 1: Ctx.Dr1 = Hw.Addr; break;
            case 2: Ctx.Dr2 = Hw.Addr; break;
            case 3: Ctx.Dr3 = Hw.Addr; break;
            }
            Ctx.Dr7 |= (1ULL << (Hw.Slot * 2));
        }

        SetThreadContext(ThreadHandle, &Ctx);
    }
#endif
}

}
