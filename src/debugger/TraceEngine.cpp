#include "TraceEngine.h"
#include <QDataStream>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <cstring>
#include <unistd.h>
#include <errno.h>

namespace Fidra {

class TraceEngine::TraceThread : public QThread {
    Q_OBJECT
public:
    explicit TraceThread(TraceEngine* Owner, int Pid, const TraceFilter& Filter)
        : QThread(Owner)
        , OwnerRef(Owner)
        , TargetPid(Pid)
        , CurrentFilter(Filter)
        , ShouldStop(false)
    {
    }

    void RequestStop() {
        ShouldStop.store(true);
    }

signals:
    void EntryRecorded(const Fidra::TraceEntry& Entry);
    void Finished(uint64_t TotalEntries);
    void Error(const QString& Message);

protected:
    void run() override {
        csh CapstoneHandle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &CapstoneHandle) != CS_ERR_OK) {
            emit Error("Failed to initialize capstone disassembler");
            return;
        }
        cs_option(CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

        if (ptrace(PTRACE_ATTACH, TargetPid, nullptr, nullptr) == -1) {
            cs_close(&CapstoneHandle);
            emit Error(QString("Failed to attach to process %1: %2").arg(TargetPid).arg(strerror(errno)));
            return;
        }

        int WaitStatus = 0;
        waitpid(TargetPid, &WaitStatus, 0);

        if (!WIFSTOPPED(WaitStatus)) {
            cs_close(&CapstoneHandle);
            emit Error("Process did not stop after attach");
            return;
        }

        uint64_t EntryIndex = 0;
        cs_insn* Insn = cs_malloc(CapstoneHandle);

        while (!ShouldStop.load() && EntryIndex < static_cast<uint64_t>(CurrentFilter.MaxEntries)) {
            if (ptrace(PTRACE_SINGLESTEP, TargetPid, nullptr, nullptr) == -1) {
                emit Error(QString("PTRACE_SINGLESTEP failed: %1").arg(strerror(errno)));
                break;
            }

            waitpid(TargetPid, &WaitStatus, 0);

            if (WIFEXITED(WaitStatus) || WIFSIGNALED(WaitStatus)) {
                break;
            }

            if (!WIFSTOPPED(WaitStatus)) {
                continue;
            }

            struct user_regs_struct Regs;
            if (ptrace(PTRACE_GETREGS, TargetPid, nullptr, &Regs) == -1) {
                emit Error(QString("PTRACE_GETREGS failed: %1").arg(strerror(errno)));
                break;
            }

            Address CurrentRip = static_cast<Address>(Regs.rip);

            if (CurrentRip < CurrentFilter.StartAddr || CurrentRip > CurrentFilter.EndAddr) {
                continue;
            }

            if (!CurrentFilter.ModuleFilter.isEmpty()) {
                QString MapsLine = ReadModuleForAddress(CurrentRip);
                if (!MapsLine.isEmpty() && !MapsLine.contains(CurrentFilter.ModuleFilter)) {
                    if (!CurrentFilter.TraceIntoLibraries) {
                        continue;
                    }
                }
            }

            uint8_t CodeBuffer[16];
            memset(CodeBuffer, 0, sizeof(CodeBuffer));

            for (int I = 0; I < 2; ++I) {
                long Word = ptrace(PTRACE_PEEKTEXT, TargetPid,
                                   reinterpret_cast<void*>(CurrentRip + I * sizeof(long)), nullptr);
                memcpy(CodeBuffer + I * sizeof(long), &Word, sizeof(long));
            }

            TraceEntry Entry;
            Entry.Index = EntryIndex;
            Entry.InstructionAddr = CurrentRip;
            Entry.Rax = Regs.rax;
            Entry.Rbx = Regs.rbx;
            Entry.Rcx = Regs.rcx;
            Entry.Rdx = Regs.rdx;
            Entry.Rsi = Regs.rsi;
            Entry.Rdi = Regs.rdi;
            Entry.Rbp = Regs.rbp;
            Entry.Rsp = Regs.rsp;
            Entry.Rip = Regs.rip;
            Entry.R8 = Regs.r8;
            Entry.R9 = Regs.r9;
            Entry.R10 = Regs.r10;
            Entry.R11 = Regs.r11;
            Entry.R12 = Regs.r12;
            Entry.R13 = Regs.r13;
            Entry.R14 = Regs.r14;
            Entry.R15 = Regs.r15;
            Entry.Rflags = Regs.eflags;
            Entry.MemoryAddr = 0;
            Entry.IsMemoryWrite = false;

            const uint8_t* CodePtr = CodeBuffer;
            size_t CodeSize = sizeof(CodeBuffer);
            uint64_t DisasmAddr = CurrentRip;

            if (cs_disasm_iter(CapstoneHandle, &CodePtr, &CodeSize, &DisasmAddr, Insn)) {
                Entry.Mnemonic = QString::fromLatin1(Insn->mnemonic);
                Entry.Operands = QString::fromLatin1(Insn->op_str);

                cs_detail* Detail = Insn->detail;
                if (Detail) {
                    for (uint8_t OpIdx = 0; OpIdx < Detail->x86.op_count; ++OpIdx) {
                        cs_x86_op& Op = Detail->x86.operands[OpIdx];
                        if (Op.type == X86_OP_MEM) {
                            Address EffAddr = 0;
                            if (Op.mem.base != X86_REG_INVALID) {
                                EffAddr += GetRegValue(Regs, Op.mem.base);
                            }
                            if (Op.mem.index != X86_REG_INVALID) {
                                EffAddr += GetRegValue(Regs, Op.mem.index) * Op.mem.scale;
                            }
                            EffAddr += Op.mem.disp;
                            Entry.MemoryAddr = EffAddr;

                            if (Op.access & CS_AC_WRITE) {
                                Entry.IsMemoryWrite = true;
                            }

                            long MemWord = ptrace(PTRACE_PEEKDATA, TargetPid,
                                                   reinterpret_cast<void*>(EffAddr), nullptr);
                            if (errno == 0) {
                                Entry.MemoryAccess.resize(sizeof(long));
                                memcpy(Entry.MemoryAccess.data(), &MemWord, sizeof(long));
                            }
                            break;
                        }
                    }
                }
            } else {
                Entry.Mnemonic = "???";
                Entry.Operands = "";
            }

            emit EntryRecorded(Entry);
            ++EntryIndex;

            if (CurrentFilter.BreakOnAddresses.contains(CurrentRip)) {
                break;
            }

            if (EntryIndex % 10000 == 0) {
                emit OwnerRef->TraceProgress(EntryIndex);
            }
        }

        cs_free(Insn, 1);
        cs_close(&CapstoneHandle);

        ptrace(PTRACE_DETACH, TargetPid, nullptr, nullptr);

        emit Finished(EntryIndex);
    }

private:
    uint64_t GetRegValue(const struct user_regs_struct& Regs, x86_reg Reg) const {
        switch (Reg) {
        case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return Regs.rax;
        case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: return Regs.rbx;
        case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: return Regs.rcx;
        case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: return Regs.rdx;
        case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return Regs.rsi;
        case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return Regs.rdi;
        case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return Regs.rbp;
        case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return Regs.rsp;
        case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return Regs.r8;
        case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return Regs.r9;
        case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return Regs.r10;
        case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return Regs.r11;
        case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return Regs.r12;
        case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return Regs.r13;
        case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return Regs.r14;
        case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return Regs.r15;
        case X86_REG_RIP: case X86_REG_EIP: return Regs.rip;
        default: return 0;
        }
    }

    QString ReadModuleForAddress(Address Addr) const {
        QFile MapsFile(QString("/proc/%1/maps").arg(TargetPid));
        if (!MapsFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            return {};
        }

        while (!MapsFile.atEnd()) {
            QString Line = QString::fromLatin1(MapsFile.readLine().trimmed());
            QStringList Parts = Line.split(' ', Qt::SkipEmptyParts);
            if (Parts.size() < 1) continue;

            QStringList Range = Parts[0].split('-');
            if (Range.size() != 2) continue;

            bool Ok1 = false, Ok2 = false;
            Address Start = Range[0].toULongLong(&Ok1, 16);
            Address End = Range[1].toULongLong(&Ok2, 16);
            if (!Ok1 || !Ok2) continue;

            if (Addr >= Start && Addr < End) {
                return Parts.size() > 5 ? Parts.last() : Line;
            }
        }
        return {};
    }

    TraceEngine* OwnerRef;
    int TargetPid;
    TraceFilter CurrentFilter;
    std::atomic<bool> ShouldStop;
};

TraceEngine::TraceEngine(QObject* Parent)
    : QObject(Parent)
    , Tracing(false)
    , WorkerThread(nullptr)
    , TracedPid(0)
{
}

TraceEngine::~TraceEngine() {
    StopTrace();
}

bool TraceEngine::StartTrace(int Pid, const TraceFilter& Filter) {
    if (Tracing.load()) {
        return false;
    }

    ClearTrace();
    ActiveFilter = Filter;
    TracedPid = Pid;
    Tracing.store(true);

    WorkerThread = new TraceThread(this, Pid, Filter);

    connect(WorkerThread, &TraceThread::EntryRecorded, this, &TraceEngine::OnTraceEntry, Qt::QueuedConnection);
    connect(WorkerThread, &TraceThread::Finished, this, [this](uint64_t TotalEntries) {
        Tracing.store(false);
        emit TraceStopped(TotalEntries);
    }, Qt::QueuedConnection);
    connect(WorkerThread, &TraceThread::Error, this, [this](const QString& Message) {
        Tracing.store(false);
        emit TraceError(Message);
    }, Qt::QueuedConnection);
    connect(WorkerThread, &QThread::finished, WorkerThread, &QObject::deleteLater);

    WorkerThread->start();
    return true;
}

void TraceEngine::StopTrace() {
    if (!Tracing.load() || !WorkerThread) {
        return;
    }

    WorkerThread->RequestStop();
    WorkerThread->wait(10000);
    WorkerThread = nullptr;
    Tracing.store(false);
}

bool TraceEngine::IsTracing() const {
    return Tracing.load();
}

QVector<TraceEntry> TraceEngine::GetEntries() const {
    QMutexLocker Lock(&Mutex);
    return Entries;
}

TraceEntry TraceEngine::GetEntry(uint64_t Index) const {
    QMutexLocker Lock(&Mutex);
    if (Index < static_cast<uint64_t>(Entries.size())) {
        return Entries[static_cast<int>(Index)];
    }
    return {};
}

uint64_t TraceEngine::EntryCount() const {
    QMutexLocker Lock(&Mutex);
    return static_cast<uint64_t>(Entries.size());
}

QVector<TraceEntry> TraceEngine::Search(const QString& MnemonicFilter) const {
    QMutexLocker Lock(&Mutex);
    QVector<TraceEntry> Results;
    QString FilterLower = MnemonicFilter.toLower();

    for (const auto& Entry : Entries) {
        if (Entry.Mnemonic.toLower().contains(FilterLower)) {
            Results.append(Entry);
        }
    }
    return Results;
}

QVector<TraceEntry> TraceEngine::SearchByAddress(Address Addr) const {
    QMutexLocker Lock(&Mutex);
    QVector<TraceEntry> Results;

    for (const auto& Entry : Entries) {
        if (Entry.InstructionAddr == Addr) {
            Results.append(Entry);
        }
    }
    return Results;
}

QVector<TraceEntry> TraceEngine::SearchByRegValue(const QString& RegName, uint64_t Value) const {
    QMutexLocker Lock(&Mutex);
    QVector<TraceEntry> Results;
    QString UpperName = RegName.toUpper();

    for (const auto& Entry : Entries) {
        uint64_t RegVal = 0;
        if (UpperName == "RAX") RegVal = Entry.Rax;
        else if (UpperName == "RBX") RegVal = Entry.Rbx;
        else if (UpperName == "RCX") RegVal = Entry.Rcx;
        else if (UpperName == "RDX") RegVal = Entry.Rdx;
        else if (UpperName == "RSI") RegVal = Entry.Rsi;
        else if (UpperName == "RDI") RegVal = Entry.Rdi;
        else if (UpperName == "RBP") RegVal = Entry.Rbp;
        else if (UpperName == "RSP") RegVal = Entry.Rsp;
        else if (UpperName == "RIP") RegVal = Entry.Rip;
        else if (UpperName == "R8") RegVal = Entry.R8;
        else if (UpperName == "R9") RegVal = Entry.R9;
        else if (UpperName == "R10") RegVal = Entry.R10;
        else if (UpperName == "R11") RegVal = Entry.R11;
        else if (UpperName == "R12") RegVal = Entry.R12;
        else if (UpperName == "R13") RegVal = Entry.R13;
        else if (UpperName == "R14") RegVal = Entry.R14;
        else if (UpperName == "R15") RegVal = Entry.R15;
        else if (UpperName == "RFLAGS") RegVal = Entry.Rflags;
        else continue;

        if (RegVal == Value) {
            Results.append(Entry);
        }
    }
    return Results;
}

bool TraceEngine::SaveTrace(const QString& Path) const {
    QMutexLocker Lock(&Mutex);

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) {
        return false;
    }

    QDataStream Stream(&File);
    Stream.setVersion(QDataStream::Qt_6_0);

    Stream << static_cast<quint32>(0x41494441);
    Stream << static_cast<quint32>(1);
    Stream << static_cast<quint64>(Entries.size());

    for (const auto& Entry : Entries) {
        Stream << static_cast<quint64>(Entry.Index);
        Stream << static_cast<quint64>(Entry.InstructionAddr);
        Stream << Entry.Mnemonic;
        Stream << Entry.Operands;
        Stream << static_cast<quint64>(Entry.Rax) << static_cast<quint64>(Entry.Rbx) << static_cast<quint64>(Entry.Rcx) << static_cast<quint64>(Entry.Rdx);
        Stream << static_cast<quint64>(Entry.Rsi) << static_cast<quint64>(Entry.Rdi) << static_cast<quint64>(Entry.Rbp) << static_cast<quint64>(Entry.Rsp) << static_cast<quint64>(Entry.Rip);
        Stream << static_cast<quint64>(Entry.R8) << static_cast<quint64>(Entry.R9) << static_cast<quint64>(Entry.R10) << static_cast<quint64>(Entry.R11);
        Stream << static_cast<quint64>(Entry.R12) << static_cast<quint64>(Entry.R13) << static_cast<quint64>(Entry.R14) << static_cast<quint64>(Entry.R15);
        Stream << static_cast<quint64>(Entry.Rflags);
        Stream << Entry.MemoryAccess;
        Stream << static_cast<quint64>(Entry.MemoryAddr);
        Stream << Entry.IsMemoryWrite;
    }

    return true;
}

bool TraceEngine::LoadTrace(const QString& Path) {
    QFile File(Path);
    if (!File.open(QIODevice::ReadOnly)) {
        return false;
    }

    QDataStream Stream(&File);
    Stream.setVersion(QDataStream::Qt_6_0);

    quint32 Magic = 0;
    quint32 Version = 0;
    quint64 Count = 0;

    Stream >> Magic;
    if (Magic != 0x41494441) {
        return false;
    }

    Stream >> Version;
    if (Version != 1) {
        return false;
    }

    Stream >> Count;

    QMutexLocker Lock(&Mutex);
    Entries.clear();
    ExecutionCounts.clear();
    Entries.reserve(static_cast<int>(Count));

    for (quint64 I = 0; I < Count; ++I) {
        TraceEntry Entry;
        quint64 Tmp;
        Stream >> Tmp; Entry.Index = Tmp;
        Stream >> Tmp; Entry.InstructionAddr = Tmp;
        Stream >> Entry.Mnemonic;
        Stream >> Entry.Operands;
        Stream >> Tmp; Entry.Rax = Tmp; Stream >> Tmp; Entry.Rbx = Tmp; Stream >> Tmp; Entry.Rcx = Tmp; Stream >> Tmp; Entry.Rdx = Tmp;
        Stream >> Tmp; Entry.Rsi = Tmp; Stream >> Tmp; Entry.Rdi = Tmp; Stream >> Tmp; Entry.Rbp = Tmp; Stream >> Tmp; Entry.Rsp = Tmp; Stream >> Tmp; Entry.Rip = Tmp;
        Stream >> Tmp; Entry.R8 = Tmp; Stream >> Tmp; Entry.R9 = Tmp; Stream >> Tmp; Entry.R10 = Tmp; Stream >> Tmp; Entry.R11 = Tmp;
        Stream >> Tmp; Entry.R12 = Tmp; Stream >> Tmp; Entry.R13 = Tmp; Stream >> Tmp; Entry.R14 = Tmp; Stream >> Tmp; Entry.R15 = Tmp;
        Stream >> Tmp; Entry.Rflags = Tmp;
        Stream >> Entry.MemoryAccess;
        Stream >> Tmp; Entry.MemoryAddr = Tmp;
        Stream >> Entry.IsMemoryWrite;

        Entries.append(Entry);
        ExecutionCounts[Entry.InstructionAddr]++;
    }

    return true;
}

void TraceEngine::ClearTrace() {
    QMutexLocker Lock(&Mutex);
    Entries.clear();
    ExecutionCounts.clear();
}

QMap<Address, uint64_t> TraceEngine::GetExecutionCounts() const {
    QMutexLocker Lock(&Mutex);
    return ExecutionCounts;
}

void TraceEngine::OnTraceEntry(const TraceEntry& Entry) {
    QMutexLocker Lock(&Mutex);
    Entries.append(Entry);
    ExecutionCounts[Entry.InstructionAddr]++;
}

}

#include "TraceEngine.moc"
