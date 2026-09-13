#include "InstructionStore.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMutexLocker>
#include <QThread>

#include <cstring>
#include <cstdio>
#include <algorithm>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <windows.h>
static ssize_t safe_pread(int Fd, void* Buf, size_t Size, uint64_t Off) {
    HANDLE H = reinterpret_cast<HANDLE>(_get_osfhandle(Fd));
    OVERLAPPED O{}; O.Offset = static_cast<DWORD>(Off); O.OffsetHigh = static_cast<DWORD>(Off >> 32);
    DWORD Read = 0;
    if (!ReadFile(H, Buf, static_cast<DWORD>(Size), &Read, &O)) return -1;
    return static_cast<ssize_t>(Read);
}
static ssize_t safe_pwrite(int Fd, const void* Buf, size_t Size, uint64_t Off) {
    HANDLE H = reinterpret_cast<HANDLE>(_get_osfhandle(Fd));
    OVERLAPPED O{}; O.Offset = static_cast<DWORD>(Off); O.OffsetHigh = static_cast<DWORD>(Off >> 32);
    DWORD Written = 0;
    if (!WriteFile(H, Buf, static_cast<DWORD>(Size), &Written, &O)) return -1;
    return static_cast<ssize_t>(Written);
}
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
static inline ssize_t safe_pread(int Fd, void* Buf, size_t Size, uint64_t Off) {
    return ::pread(Fd, Buf, Size, static_cast<off_t>(Off));
}
static inline ssize_t safe_pwrite(int Fd, const void* Buf, size_t Size, uint64_t Off) {
    return ::pwrite(Fd, Buf, Size, static_cast<off_t>(Off));
}
#endif

namespace Fidra {

InstructionStore::InstructionStore()
    : RecordsFd(-1), StringsFd(-1),
      RecordsSize(0), StringsSize(0),
      RecordsMap(nullptr), RecordsMapSize(0),
      StringsMap(nullptr), StringsMapSize(0) {}

InstructionStore::~InstructionStore() {
    Close();
    if (!RecordsPath.isEmpty()) QFile::remove(RecordsPath);
    if (!StringsPath.isEmpty()) QFile::remove(StringsPath);
    QDir Parent = QFileInfo(RecordsPath).absoluteDir();
    if (Parent.exists()) Parent.rmdir(Parent.absolutePath());
}

static QString MakeTempDir() {
    QString Base = QDir::tempPath() + QStringLiteral("/fidra-insns-") +
                   QString::number(QCoreApplication::applicationPid()) +
                   QStringLiteral("-") + QString::number(quintptr(QThread::currentThreadId()), 16);
    QDir().mkpath(Base);
    return Base;
}

bool InstructionStore::Open() {
    if (RecordsFd >= 0) return true;
    QString Dir = MakeTempDir();
    RecordsPath = Dir + QStringLiteral("/records.bin");
    StringsPath = Dir + QStringLiteral("/strings.bin");
#ifdef _WIN32
    RecordsFd = _open(RecordsPath.toLocal8Bit().constData(),
                      _O_CREAT | _O_RDWR | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
    StringsFd = _open(StringsPath.toLocal8Bit().constData(),
                      _O_CREAT | _O_RDWR | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
    RecordsFd = ::open(RecordsPath.toLocal8Bit().constData(),
                       O_CREAT | O_RDWR | O_TRUNC, 0644);
    StringsFd = ::open(StringsPath.toLocal8Bit().constData(),
                       O_CREAT | O_RDWR | O_TRUNC, 0644);
#endif
    if (RecordsFd < 0 || StringsFd < 0) {
        Close();
        return false;
    }
    MnemonicTable.append(QString());
    MnemonicIndex.insert(QString(), 0);
    return true;
}

void InstructionStore::Close() {
    if (RecordsFd >= 0) { ::close(RecordsFd); RecordsFd = -1; }
    if (StringsFd >= 0) { ::close(StringsFd); StringsFd = -1; }
    RecordsSize = 0;
    StringsSize = 0;
    AddrIndex.clear();
    MnemonicIndex.clear();
    MnemonicTable.clear();
    RecordsMap = nullptr; RecordsMapSize = 0;
    StringsMap = nullptr; StringsMapSize = 0;
}

void InstructionStore::Clear() {
    QMutexLocker Locker(&Lock);
    Close();
    Open();
}

int InstructionStore::Count() const {
    QMutexLocker Locker(&Lock);
    return AddrIndex.size();
}

uint16_t InstructionStore::InternMnemonic(const QString& S) {
    auto It = MnemonicIndex.constFind(S);
    if (It != MnemonicIndex.constEnd()) return It.value();
    uint16_t Idx = static_cast<uint16_t>(MnemonicTable.size());
    MnemonicTable.append(S);
    MnemonicIndex.insert(S, Idx);
    return Idx;
}

uint32_t InstructionStore::AppendString(const QString& S, uint16_t* OutLen) {
    if (S.isEmpty()) { if (OutLen) *OutLen = 0; return 0; }
    QByteArray B = S.toUtf8();
    uint32_t Off = static_cast<uint32_t>(StringsSize);
    ssize_t W = safe_pwrite(StringsFd, B.constData(), static_cast<size_t>(B.size()), StringsSize);
    if (W != B.size()) {
        if (OutLen) *OutLen = 0;
        return 0;
    }
    StringsSize += static_cast<uint64_t>(B.size());
    if (OutLen) *OutLen = static_cast<uint16_t>(std::min<qsizetype>(B.size(), 65535));
    return Off;
}

QString InstructionStore::ReadString(uint32_t Offset, uint16_t Len) const {
    if (Len == 0) return QString();
    QByteArray Buf(Len, Qt::Uninitialized);
    ssize_t R = safe_pread(StringsFd, Buf.data(), Len, Offset);
    if (R != Len) return QString();
    return QString::fromUtf8(Buf.constData(), Len);
}

void InstructionStore::RemapIfGrown() const {
    // No-op — pread/pwrite path.
}

void InstructionStore::Pack(const AnalyzedInstruction& In, PackedInsn& Out) {
    std::memset(&Out, 0, sizeof(Out));
    Out.Addr = In.Addr;
    Out.BranchTarget = In.BranchTarget;
    Out.MemoryRef = In.MemoryRef;
    Out.Size = In.Size;
    Out.MnemonicIndex = InternMnemonic(In.Mnemonic);
    Out.OperandOffset = AppendString(In.Operands, &Out.OperandLen);
    Out.CommentOffset = AppendString(In.Comment, &Out.CommentLen);
    if (In.IsCall)         Out.Flags |= F1_Call;
    if (In.IsJump)         Out.Flags |= F1_Jump;
    if (In.IsRet)          Out.Flags |= F1_Ret;
    if (In.IsConditional)  Out.Flags |= F1_Cond;
    if (In.IsNop)          Out.Flags |= F1_Nop;
    if (In.IsPush)         Out.Flags |= F1_Push;
    if (In.IsPop)          Out.Flags |= F1_Pop;
    if (In.IsIndirectJump) Out.Flags |= F1_IJump;
    if (In.IsIndirectCall) Out.Flags2 |= F2_ICall;
    if (In.IsHalt)         Out.Flags2 |= F2_Halt;
    uint8_t Copy = In.Size < 8 ? In.Size : 8;
    std::memcpy(Out.Bytes, In.Bytes, Copy);
    Out.BytesLen = In.Size;
}

AnalyzedInstruction InstructionStore::Unpack(const PackedInsn& P) const {
    AnalyzedInstruction A{};
    A.Addr = P.Addr;
    A.Size = P.Size;
    A.BranchTarget = P.BranchTarget;
    A.MemoryRef = P.MemoryRef;
    A.IsCall         = (P.Flags & F1_Call)  != 0;
    A.IsJump         = (P.Flags & F1_Jump)  != 0;
    A.IsRet          = (P.Flags & F1_Ret)   != 0;
    A.IsConditional  = (P.Flags & F1_Cond)  != 0;
    A.IsNop          = (P.Flags & F1_Nop)   != 0;
    A.IsPush         = (P.Flags & F1_Push)  != 0;
    A.IsPop          = (P.Flags & F1_Pop)   != 0;
    A.IsIndirectJump = (P.Flags & F1_IJump) != 0;
    A.IsIndirectCall = (P.Flags2 & F2_ICall) != 0;
    A.IsHalt         = (P.Flags2 & F2_Halt)  != 0;
    uint8_t Copy = P.BytesLen < 8 ? P.BytesLen : 8;
    std::memcpy(A.Bytes, P.Bytes, Copy);
    if (P.MnemonicIndex < MnemonicTable.size())
        A.Mnemonic = MnemonicTable[P.MnemonicIndex];
    A.Operands = ReadString(P.OperandOffset, P.OperandLen);
    A.Comment  = ReadString(P.CommentOffset, P.CommentLen);
    return A;
}

bool InstructionStore::ReadRecord(uint64_t Offset, PackedInsn& Out) const {
    ssize_t R = safe_pread(RecordsFd, &Out, sizeof(PackedInsn), Offset);
    return R == static_cast<ssize_t>(sizeof(PackedInsn));
}

bool InstructionStore::Add(const AnalyzedInstruction& Inst) {
    QMutexLocker Locker(&Lock);
    if (AddrIndex.contains(Inst.Addr)) return true;
    PackedInsn P;
    Pack(Inst, P);
    uint64_t Off = RecordsSize;
    ssize_t W = safe_pwrite(RecordsFd, &P, sizeof(P), Off);
    if (W != static_cast<ssize_t>(sizeof(P))) return false;
    RecordsSize += sizeof(PackedInsn);
    AddrIndex.insert(Inst.Addr, Off);
    return true;
}

bool InstructionStore::Contains(Address Addr) const {
    QMutexLocker Locker(&Lock);
    return AddrIndex.contains(Addr);
}

AnalyzedInstruction InstructionStore::Get(Address Addr) const {
    QMutexLocker Locker(&Lock);
    auto It = AddrIndex.constFind(Addr);
    if (It == AddrIndex.constEnd()) return AnalyzedInstruction{};
    PackedInsn P;
    if (!ReadRecord(It.value(), P)) return AnalyzedInstruction{};
    return Unpack(P);
}

void InstructionStore::ForEach(const std::function<void(const AnalyzedInstruction&)>& Callback) const {
    QMutexLocker Locker(&Lock);
    for (auto It = AddrIndex.constBegin(); It != AddrIndex.constEnd(); ++It) {
        PackedInsn P;
        if (!ReadRecord(It.value(), P)) continue;
        Callback(Unpack(P));
    }
}

void InstructionStore::ForEachInRange(const std::vector<Address>& SortedAddrs,
                                      Address Lo, Address Hi,
                                      const std::function<void(const AnalyzedInstruction&)>& Callback) const {
    QMutexLocker Locker(&Lock);
    auto ItLo = std::lower_bound(SortedAddrs.begin(), SortedAddrs.end(), Lo);
    auto ItHi = std::lower_bound(ItLo, SortedAddrs.end(), Hi);
    for (auto It = ItLo; It != ItHi; ++It) {
        auto Found = AddrIndex.constFind(*It);
        if (Found == AddrIndex.constEnd()) continue;
        PackedInsn P;
        if (!ReadRecord(Found.value(), P)) continue;
        Callback(Unpack(P));
    }
}

}
