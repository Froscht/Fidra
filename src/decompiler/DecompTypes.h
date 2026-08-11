#pragma once

#include <fidra/Types.h>
#include <QString>
#include <QVector>
#include <QMap>

namespace Fidra::Decomp {

enum class IrOp {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Shl, Shr, Sar,
    Not, Neg,
    Mov, Load, Store,
    Call, Ret,
    Jump, CondJump,
    Compare, Test,
    Nop, Phi,
    Cast, SignExtend, ZeroExtend,
    AddressOf, Deref,
    StackAlloc,
    Unknown
};

enum class IrType {
    Void,
    Int8, Int16, Int32, Int64,
    UInt8, UInt16, UInt32, UInt64,
    Float32, Float64,
    Pointer,
    Struct, Array,
    Unknown
};

enum class CondCode {
    Equal, NotEqual,
    SignedLess, SignedLessEqual,
    SignedGreater, SignedGreaterEqual,
    UnsignedBelow, UnsignedBelowEqual,
    UnsignedAbove, UnsignedAboveEqual,
    Zero, NotZero,
    Sign, NotSign,
    Overflow, NotOverflow,
    Always, Never
};

struct IrOperand {
    enum Kind { Reg, Imm, Mem, Temp, Stack, Global, Label, Invalid };
    Kind OpKind = Invalid;
    int RegId = -1;
    int64_t ImmValue = 0;
    int TempId = -1;
    int StackOffset = 0;
    Address GlobalAddr = 0;
    IrType Type = IrType::Unknown;
    QString Name;

    bool IsValid() const { return OpKind != Invalid; }
    bool IsReg() const { return OpKind == Reg; }
    bool IsImm() const { return OpKind == Imm; }
    bool IsTemp() const { return OpKind == Temp; }
    bool IsStack() const { return OpKind == Stack; }

    static IrOperand MakeReg(int Id, IrType T = IrType::Int64) {
        IrOperand Op;
        Op.OpKind = Reg;
        Op.RegId = Id;
        Op.Type = T;
        return Op;
    }

    static IrOperand MakeImm(int64_t Val, IrType T = IrType::Int64) {
        IrOperand Op;
        Op.OpKind = Imm;
        Op.ImmValue = Val;
        Op.Type = T;
        return Op;
    }

    static IrOperand MakeTemp(int Id, IrType T = IrType::Int64) {
        IrOperand Op;
        Op.OpKind = Temp;
        Op.TempId = Id;
        Op.Type = T;
        return Op;
    }

    static IrOperand MakeStack(int Offset, IrType T = IrType::Int64) {
        IrOperand Op;
        Op.OpKind = Stack;
        Op.StackOffset = Offset;
        Op.Type = T;
        return Op;
    }

    static IrOperand MakeGlobal(Address Addr, IrType T = IrType::Pointer) {
        IrOperand Op;
        Op.OpKind = Global;
        Op.GlobalAddr = Addr;
        Op.Type = T;
        return Op;
    }

    static IrOperand MakeLabel(Address Addr) {
        IrOperand Op;
        Op.OpKind = Label;
        Op.GlobalAddr = Addr;
        Op.Type = IrType::Void;
        return Op;
    }

    static IrOperand MakeInvalid() {
        IrOperand Op;
        Op.OpKind = Invalid;
        return Op;
    }

    bool operator==(const IrOperand& Other) const {
        if (OpKind != Other.OpKind) return false;
        switch (OpKind) {
            case Reg: return RegId == Other.RegId;
            case Imm: return ImmValue == Other.ImmValue;
            case Temp: return TempId == Other.TempId;
            case Stack: return StackOffset == Other.StackOffset;
            case Global: return GlobalAddr == Other.GlobalAddr;
            case Label: return GlobalAddr == Other.GlobalAddr;
            default: return true;
        }
    }
    bool operator!=(const IrOperand& Other) const { return !(*this == Other); }
};

struct IrInst {
    IrOp Op = IrOp::Unknown;
    IrOperand Dest;
    IrOperand Src1;
    IrOperand Src2;
    CondCode Cond = CondCode::Always;
    Address OriginalAddr = 0;
    int BasicBlockId = -1;
    Address CallTarget = 0;
    QString CallName;
};

struct IrBasicBlock {
    int Id = -1;
    Address StartAddr = 0;
    Address EndAddr = 0;
    QVector<IrInst> Instructions;
    QVector<int> Successors;
    QVector<int> Predecessors;
    bool IsEntry = false;
    bool IsExit = false;
};

struct StackVariable {
    int Offset = 0;
    QString Name;
    IrType Type = IrType::Unknown;
    int Size = 0;
    int AccessCount = 0;
};

struct IrFunction {
    QString Name;
    Address EntryAddr = 0;
    IrType ReturnType = IrType::Unknown;
    QVector<IrOperand> Parameters;
    QVector<IrBasicBlock> Blocks;
    QMap<int, StackVariable> StackVars;
    int NextTempId = 0;
    int StackFrameSize = 0;
    bool UsesFramePointer = false;
};

struct DecompOutput {
    QString PseudoC;
    QString IrDump;
    QString FunctionSignature;
    QVector<QString> LocalVars;
    int Complexity = 0;
    double TimeMs = 0.0;
};

inline QString IrTypeToString(IrType T) {
    switch (T) {
        case IrType::Void: return "void";
        case IrType::Int8: return "int8_t";
        case IrType::Int16: return "int16_t";
        case IrType::Int32: return "int32_t";
        case IrType::Int64: return "int64_t";
        case IrType::UInt8: return "uint8_t";
        case IrType::UInt16: return "uint16_t";
        case IrType::UInt32: return "uint32_t";
        case IrType::UInt64: return "uint64_t";
        case IrType::Float32: return "float";
        case IrType::Float64: return "double";
        case IrType::Pointer: return "void*";
        default: return "unknown_t";
    }
}

inline int IrTypeSize(IrType T) {
    switch (T) {
        case IrType::Int8: case IrType::UInt8: return 1;
        case IrType::Int16: case IrType::UInt16: return 2;
        case IrType::Int32: case IrType::UInt32: case IrType::Float32: return 4;
        case IrType::Int64: case IrType::UInt64: case IrType::Float64: case IrType::Pointer: return 8;
        default: return 0;
    }
}

inline IrType IrTypeFromSize(int Size, bool IsSigned = true) {
    switch (Size) {
        case 1: return IsSigned ? IrType::Int8 : IrType::UInt8;
        case 2: return IsSigned ? IrType::Int16 : IrType::UInt16;
        case 4: return IsSigned ? IrType::Int32 : IrType::UInt32;
        case 8: return IsSigned ? IrType::Int64 : IrType::UInt64;
        default: return IrType::Unknown;
    }
}

inline QString RegName64(int Id) {
    static const char* Names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    if (Id >= 0 && Id < 16) return Names[Id];
    return QString("reg%1").arg(Id);
}

}
