#pragma once

#include "AnalysisTypes.h"
#include <QRecursiveMutex>
#include <QHash>
#include <QString>
#include <functional>
#include <cstdint>
#include <vector>

namespace Fidra {

// Disk-backed, mmap-accessible packed instruction store.
//
// Records file: fixed-size PackedInsn, appended per AddInstruction, mmapped
// read-only after write. String blob file: append-only Operand/Comment.
// Mnemonic table: small in-RAM hash (mnemonic strings deduplicated across
// entire binary, typically < 500 unique).
//
// In-RAM overhead: QHash<Address, uint64_t> mapping addr → record offset.
// Peak resident RAM is bounded by MaxInstructions × ~24 bytes (~240 MiB at
// 10 M cap). The actual record + string data lives in temp files under
// $TMPDIR/fidra-insns-<pid>/ and pages in through the kernel page cache.
class InstructionStore {
public:
    InstructionStore();
    ~InstructionStore();

    bool Open();
    void Close();
    void Clear();

    bool Add(const AnalyzedInstruction& Inst);
    bool Contains(Address Addr) const;
    AnalyzedInstruction Get(Address Addr) const;
    // Fast metadata read: no operand/comment string pread. Only size, flags,
    // BranchTarget, MemoryRef, IsCall/IsJump/... — enough for CFG walks and
    // xref building without paying two extra syscalls per insn.
    struct InsnMeta {
        Address Addr;
        Address BranchTarget;
        Address MemoryRef;
        uint8_t Size;
        bool IsCall, IsJump, IsRet, IsConditional, IsNop, IsPush, IsPop,
             IsIndirectJump, IsIndirectCall, IsHalt;
    };
    bool GetMeta(Address Addr, InsnMeta& Out) const;
    // Range read of meta only (no string preads). For per-function CFG /
    // dominance / loop analysis that never reads Mnemonic or Operands.
    QList<InsnMeta> GetMetaRange(const std::vector<Address>& SortedAddrs,
                                 Address Lo, Address Hi) const;
    int Count() const;

    // Iterates every instruction. Reconstructs AnalyzedInstruction per entry.
    void ForEach(const std::function<void(const AnalyzedInstruction&)>& Callback) const;

    // Iterates only records whose Addr is in [Lo, Hi). Requires the sorted
    // address vector — pass the same SortedInsnAddrs the DB keeps.
    void ForEachInRange(const std::vector<Address>& SortedAddrs,
                        Address Lo, Address Hi,
                        const std::function<void(const AnalyzedInstruction&)>& Callback) const;

private:
    struct PackedInsn {
        uint64_t Addr;           // 8
        uint64_t BranchTarget;   // 8
        uint64_t MemoryRef;      // 8
        uint32_t OperandOffset;  // 4  — into StringsBlob
        uint16_t OperandLen;     // 2
        uint16_t MnemonicIndex;  // 2  — into MnemonicTable
        uint32_t CommentOffset;  // 4
        uint16_t CommentLen;     // 2
        uint8_t  Size;           // 1
        uint8_t  Flags;          // 1  — bits: 0 Call 1 Jump 2 Ret 3 Cond
                                 //         4 Nop 5 Push 6 Pop 7 IJmp
        uint16_t Flags2;         // 2  — bit 0 ICall, bit 1 Halt
        uint8_t  Bytes[8];       // 8  — first 8 bytes of the insn
        uint8_t  BytesLen;       // 1  — 0..15 real length; if >8, tail is
                                 //     truncated (recomputed from ReadBytes
                                 //     on demand if a caller ever needs it)
        uint8_t  _Pad[5];        // 5  — total 56
    };
    static_assert(sizeof(PackedInsn) == 56, "PackedInsn layout drift");

    enum : uint8_t {
        F1_Call   = 1 << 0,
        F1_Jump   = 1 << 1,
        F1_Ret    = 1 << 2,
        F1_Cond   = 1 << 3,
        F1_Nop    = 1 << 4,
        F1_Push   = 1 << 5,
        F1_Pop    = 1 << 6,
        F1_IJump  = 1 << 7,
    };
    enum : uint16_t {
        F2_ICall  = 1 << 0,
        F2_Halt   = 1 << 1,
    };

    uint16_t InternMnemonic(const QString& S);
    uint32_t AppendString(const QString& S, uint16_t* OutLen);
    QString ReadString(uint32_t Offset, uint16_t Len) const;

    void Pack(const AnalyzedInstruction& In, PackedInsn& Out);
    AnalyzedInstruction Unpack(const PackedInsn& P) const;
    void MetaFromPacked(const PackedInsn& P, InsnMeta& Out) const;
    bool ReadRecord(uint64_t Offset, PackedInsn& Out) const;

    mutable QRecursiveMutex Lock;
    QHash<Address, uint64_t> AddrIndex;     // addr → offset into Records file
    QString RecordsPath;
    QString StringsPath;
    int RecordsFd;
    int StringsFd;
    uint64_t RecordsSize;                    // written bytes
    uint64_t StringsSize;
    const uint8_t* RecordsMap;               // mmap read-only after growth
    uint64_t RecordsMapSize;
    const uint8_t* StringsMap;
    uint64_t StringsMapSize;

    // Mnemonic intern table — small, in RAM.
    QHash<QString, uint16_t> MnemonicIndex;
    QList<QString> MnemonicTable;

    void RemapIfGrown() const;
};

}
