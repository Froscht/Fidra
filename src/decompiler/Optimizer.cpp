#include "Optimizer.h"
#include <QSet>
#include "../analysis/TypeLibrary.h"

#include <QHash>
#include <cstdint>

namespace Fidra::Decomp {

Optimizer::Optimizer() {
    EnabledPasses["DeadCodeElimination"] = true;
    EnabledPasses["CopyPropagation"] = true;
    EnabledPasses["ConstantFolding"] = true;
    EnabledPasses["StackVariableRecovery"] = true;
    EnabledPasses["ExpressionSimplification"] = true;
    EnabledPasses["ConditionRecovery"] = true;
    EnabledPasses["PrologueEpilogueCleanup"] = true;
    EnabledPasses["ConstantPropagation"] = true;
    EnabledPasses["TypeRecovery"] = true;
}

void Optimizer::SetPassEnabled(const QString& PassName, bool Enabled) {
    EnabledPasses[PassName] = Enabled;
}

bool Optimizer::IsPassEnabled(const QString& PassName) const {
    return EnabledPasses.value(PassName, false);
}

QStringList Optimizer::GetPassNames() const {
    return EnabledPasses.keys();
}

int Optimizer::GetPassCount() const {
    int Count = 0;
    for (bool V : EnabledPasses) {
        if (V) ++Count;
    }
    return Count;
}

bool Optimizer::OperandMatches(const IrOperand& A, const IrOperand& B) {
    return A == B;
}

IrFunction Optimizer::Optimize(const IrFunction& Func) {
    IrFunction Result = Func;

    if (EnabledPasses["PrologueEpilogueCleanup"]) RunPrologueEpilogueCleanup(Result);
    if (EnabledPasses["CopyPropagation"]) RunCopyPropagation(Result);
    if (EnabledPasses["ConstantPropagation"]) RunConstantPropagation(Result);
    if (EnabledPasses["ConstantFolding"]) RunConstantFolding(Result);
    if (EnabledPasses["DeadCodeElimination"]) RunDeadCodeElimination(Result);
    if (EnabledPasses["StackVariableRecovery"]) RunStackVariableRecovery(Result);
    if (EnabledPasses["TypeRecovery"]) RunTypeRecovery(Result);
    if (EnabledPasses["ExpressionSimplification"]) RunExpressionSimplification(Result);
    if (EnabledPasses["ConditionRecovery"]) RunConditionRecovery(Result);
    if (EnabledPasses["DeadCodeElimination"]) RunDeadCodeElimination(Result);
    RunParameterRecovery(Result);

    return Result;
}

// --- Register liveness helpers -------------------------------------------
// Registers 0..15 are the x86-64 GPRs; anything else (xmm, segment, raw
// capstone ids) is never tracked, so its defs are never removed.
using RegMask = uint64_t;

static constexpr RegMask AllRegs = 0xFFFF;
// Registers any call may read as arguments (SysV, Win64 and Go's ABIInternal).
static constexpr RegMask CallArgRegs =
    (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 3) | (1ull << 6) | (1ull << 7) |
    (1ull << 8) | (1ull << 9) | (1ull << 10) | (1ull << 11);

static bool IsTrackedReg(const IrOperand& Op) {
    return Op.IsReg() && Op.RegId >= 0 && Op.RegId < 16;
}

static RegMask RegBit(const IrOperand& Op) {
    if (IsTrackedReg(Op)) return 1ull << Op.RegId;
    if (Op.IsStack()) return 1ull << (Op.SpRelative ? 4 : 5);
    return 0;
}

static bool IsPureDef(IrOp Op) {
    switch (Op) {
    case IrOp::Mov: case IrOp::Add: case IrOp::Sub: case IrOp::Mul: case IrOp::Div: case IrOp::Mod:
    case IrOp::And: case IrOp::Or: case IrOp::Xor: case IrOp::Shl: case IrOp::Shr: case IrOp::Sar:
    case IrOp::Not: case IrOp::Neg: case IrOp::Load: case IrOp::Cast: case IrOp::SignExtend:
    case IrOp::ZeroExtend: case IrOp::AddressOf: case IrOp::Deref:
        return true;
    default:
        return false;
    }
}

// Dest is an address/target (a use), not a definition.
static bool DestIsUse(IrOp Op) {
    return Op == IrOp::Store || Op == IrOp::Jump || Op == IrOp::CondJump;
}

// ImplicitCallArgs: a call may read any argument register. Needed for sound
// DCE; parameter recovery turns it off since callee arity is unknown here.
static RegMask InstUses(const IrInst& Inst, bool ImplicitCallArgs = true) {
    if (Inst.Op == IrOp::Unknown) return Inst.AsmRegsRead;
    RegMask M = RegBit(Inst.Src1) | RegBit(Inst.Src2);
    if (DestIsUse(Inst.Op)) M |= RegBit(Inst.Dest);
    else if (Inst.Dest.IsStack()) M |= RegBit(Inst.Dest);
    for (const IrOperand& A : Inst.CallArgs) M |= RegBit(A);  // calls and tail jumps
    if (Inst.Op == IrOp::Call && ImplicitCallArgs && !Inst.CallArgsExact) M |= CallArgRegs;
    return M;
}

// Registers fully overwritten by Inst. 8/16-bit writes merge into the old
// value, so they do not kill it.
static RegMask InstKills(const IrInst& Inst) {
    if (Inst.Op == IrOp::Unknown) return Inst.AsmRegsKilled;
    if (Inst.Op == IrOp::Call && !Inst.Dest.IsValid()) return 1ull << 0;  // void call: rax is garbage after it
    if (DestIsUse(Inst.Op) || !IsTrackedReg(Inst.Dest)) return 0;
    if (Inst.Op == IrOp::Compare || Inst.Op == IrOp::Test) return 0;
    int Size = IrTypeSize(Inst.Dest.Type);
    if (Size == 1 || Size == 2) return 0;
    return 1ull << Inst.Dest.RegId;
}

// Index of the instruction whose flags feed the block's CondJump, if it is
// an arithmetic op (cmp/test are always kept anyway). Mirrors the code
// generator's condition lookup so DCE never removes it.
static int FlagProducerIndex(const IrBasicBlock& Block) {
    if (Block.Instructions.isEmpty() || Block.Instructions.last().Op != IrOp::CondJump) return -1;
    for (int I = Block.Instructions.size() - 2; I >= 0; --I) {
        const IrInst& Inst = Block.Instructions[I];
        switch (Inst.Op) {
        case IrOp::Compare: case IrOp::Test: case IrOp::Call: case IrOp::Unknown:
            return -1;
        case IrOp::Add: case IrOp::Sub: case IrOp::And: case IrOp::Or: case IrOp::Xor:
        case IrOp::Shl: case IrOp::Shr: case IrOp::Sar: case IrOp::Neg: case IrOp::Mul:
            if (Inst.Dest.IsValid()) return I;
            break;
        default:
            break;
        }
    }
    return -1;
}

// Backward register liveness over the CFG (GPRs only, temps are block-local).
// Registers a call overwrites under the function's convention.
static RegMask CallClobbers(CallingConv Conv) {
    switch (Conv) {
    case CallingConv::Go: return AllRegs & ~((1ull << 4) | (1ull << 5) | (1ull << 14) | (1ull << 15));
    case CallingConv::Win64: return (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 8) | (1ull << 9) | (1ull << 10) | (1ull << 11);
    default: return (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 6) | (1ull << 7) | (1ull << 8) | (1ull << 9) | (1ull << 10) | (1ull << 11);
    }
}

// ImplicitCallArgs=false is the parameter-recovery view: calls read nothing
// implicitly and overwrite the caller-saved registers.
static void ComputeLiveness(const IrFunction& Func, QVector<RegMask>& LiveIn, QVector<RegMask>& LiveOut,
                            bool ImplicitCallArgs = true) {
    const RegMask Clobbers = ImplicitCallArgs ? 0 : CallClobbers(Func.Conv);
    const int N = Func.Blocks.size();
    QVector<RegMask> ExitLive(N, 0);
    QVector<QVector<int>> Preds(N);
    for (int B = 0; B < N; ++B) {
        const IrBasicBlock& Block = Func.Blocks[B];
        for (int S : Block.Successors)
            if (S >= 0 && S < N) Preds[S].append(B);
        if (!Block.Successors.isEmpty()) continue;
        const IrInst* Last = Block.Instructions.isEmpty() ? nullptr : &Block.Instructions.last();
        if (!Last) ExitLive[B] = AllRegs;
        else if (Last->Op == IrOp::Ret) ExitLive[B] = 0;                     // ret reads rax explicitly
        else if (Last->Op == IrOp::Jump) ExitLive[B] = ImplicitCallArgs ? CallArgRegs : 0;  // tail call
        else if (Last->Op == IrOp::Call) ExitLive[B] = 0;                    // noreturn call
        else ExitLive[B] = AllRegs;                                          // unknown end
    }

    QVector<RegMask> Gen(N, 0), Kill(N, 0);
    for (int B = 0; B < N; ++B) {
        RegMask G = 0, K = 0;
        const auto& Insts = Func.Blocks[B].Instructions;
        for (int I = Insts.size() - 1; I >= 0; --I) {
            RegMask Kl = InstKills(Insts[I]);
            if (Insts[I].Op == IrOp::Call) Kl |= Clobbers;
            G &= ~Kl;
            K |= Kl;
            G |= InstUses(Insts[I], ImplicitCallArgs);
        }
        Gen[B] = G;
        Kill[B] = K;
    }

    LiveIn.fill(0, N);
    LiveOut.fill(0, N);
    QVector<int> Work;
    QVector<char> InWork(N, 1);
    for (int B = N - 1; B >= 0; --B) Work.append(B);
    while (!Work.isEmpty()) {
        int B = Work.takeLast();
        InWork[B] = 0;
        RegMask Out = ExitLive[B];
        for (int S : Func.Blocks[B].Successors)
            if (S >= 0 && S < N) Out |= LiveIn[S];
        LiveOut[B] = Out;
        RegMask In = Gen[B] | (Out & ~Kill[B]);
        if (In != LiveIn[B]) {
            LiveIn[B] = In;
            for (int P : Preds[B]) {
                if (!InWork[P]) { InWork[P] = 1; Work.append(P); }
            }
        }
    }
}

void Optimizer::RunDeadCodeElimination(IrFunction& Func) {
    const int N = Func.Blocks.size();

    for (int Round = 0; Round < 4; ++Round) {
        QVector<RegMask> LiveIn, LiveOut;
        ComputeLiveness(Func, LiveIn, LiveOut);

        // Sweep each block backwards. Temps never cross blocks.
        bool Changed = false;
        for (int B = 0; B < N; ++B) {
            IrBasicBlock& Block = Func.Blocks[B];
            const int Protected = FlagProducerIndex(Block);
            RegMask Live = LiveOut[B];
            QSet<int> LiveTemps;
            QVector<char> Keep(Block.Instructions.size(), 1);

            for (int I = Block.Instructions.size() - 1; I >= 0; --I) {
                const IrInst& Inst = Block.Instructions[I];
                if (Inst.Op == IrOp::Nop) { Keep[I] = 0; Changed = true; continue; }

                bool Removable = I != Protected && IsPureDef(Inst.Op) && Inst.Dest.IsValid();
                if (Removable) {
                    if (Inst.Dest.IsTemp()) Removable = !LiveTemps.contains(Inst.Dest.TempId);
                    else if (IsTrackedReg(Inst.Dest)) Removable = !(Live & (1ull << Inst.Dest.RegId));
                    else Removable = false;
                }
                if (Removable) { Keep[I] = 0; Changed = true; continue; }

                Live &= ~InstKills(Inst);
                if (Inst.Dest.IsTemp() && !DestIsUse(Inst.Op)) LiveTemps.remove(Inst.Dest.TempId);
                Live |= InstUses(Inst);
                if (Inst.Src1.IsTemp()) LiveTemps.insert(Inst.Src1.TempId);
                if (Inst.Src2.IsTemp()) LiveTemps.insert(Inst.Src2.TempId);
                if (DestIsUse(Inst.Op) && Inst.Dest.IsTemp()) LiveTemps.insert(Inst.Dest.TempId);
                for (const IrOperand& A : Inst.CallArgs)
                    if (A.IsTemp()) LiveTemps.insert(A.TempId);
            }

            QVector<IrInst> Kept;
            Kept.reserve(Block.Instructions.size());
            for (int I = 0; I < Block.Instructions.size(); ++I)
                if (Keep[I]) Kept.append(Block.Instructions[I]);
            Block.Instructions = Kept;
        }
        if (!Changed) break;
    }
}

// Register parameters = argument registers (in ABI order) read before being
// written on entry. Lower-numbered argument registers are included too, so
// the positions stay right when a function ignores its first argument.
void Optimizer::RunParameterRecovery(IrFunction& Func) {
    if (Func.Blocks.isEmpty() || Func.Conv == CallingConv::Cdecl32) return;
    if (Func.Proto) return;  // debug info gave the real parameters
    QVector<RegMask> LiveIn, LiveOut;
    ComputeLiveness(Func, LiveIn, LiveOut, false);
    int Entry = 0;
    for (int I = 0; I < Func.Blocks.size(); ++I)
        if (Func.Blocks[I].IsEntry) { Entry = I; break; }

    const QVector<int> Order = ArgRegisterOrder(Func.Conv);
    int Count = 0;
    for (int I = 0; I < Order.size(); ++I)
        if (LiveIn[Entry] & (1ull << Order[I])) Count = I + 1;

    QVector<IrOperand> Params;
    for (int I = 0; I < Count; ++I) Params.append(IrOperand::MakeReg(Order[I], IrType::Int64));
    for (const IrOperand& P : Func.Parameters)
        if (P.IsStack()) Params.append(P);
    Func.Parameters = Params;
}

int Optimizer::RegisterParameterCount(const IrFunction& Func) {
    if (Func.Blocks.isEmpty() || Func.Conv == CallingConv::Cdecl32) return 0;
    QVector<RegMask> LiveIn, LiveOut;
    ComputeLiveness(Func, LiveIn, LiveOut, false);
    int Entry = 0;
    for (int I = 0; I < Func.Blocks.size(); ++I)
        if (Func.Blocks[I].IsEntry) { Entry = I; break; }
    const QVector<int> Order = ArgRegisterOrder(Func.Conv);
    int Count = 0;
    for (int I = 0; I < Order.size(); ++I)
        if (LiveIn[Entry] & (1ull << Order[I])) Count = I + 1;
    return Count;
}

void Optimizer::RunCopyPropagation(IrFunction& Func) {
    for (auto& Block : Func.Blocks) {
        // Temp -> the non-temp value it was copied from, valid until that
        // value may have changed.
        QHash<int, IrOperand> TempCopies;

        auto InvalidateIf = [&](auto Pred) {
            for (auto It = TempCopies.begin(); It != TempCopies.end();) {
                if (Pred(It.value())) It = TempCopies.erase(It);
                else ++It;
            }
        };

        for (int Idx = 0; Idx < Block.Instructions.size(); ++Idx) {
            IrInst& Inst = Block.Instructions[Idx];
            // cmp/test operands are read again at the block's conditional
            // jump, so a copy is only usable if its source survives until then.
            auto SurvivesToBlockEnd = [&](const IrOperand& V) {
                if (Inst.Op != IrOp::Compare && Inst.Op != IrOp::Test) return true;
                if (!V.IsReg()) return !V.IsStack();
                for (int J = Idx + 1; J < Block.Instructions.size(); ++J) {
                    const IrInst& M = Block.Instructions[J];
                    if (M.Op == IrOp::Unknown || M.Op == IrOp::Call) return false;
                    if (!DestIsUse(M.Op) && M.Dest.IsReg() && M.Dest.RegId == V.RegId) return false;
                }
                return true;
            };
            auto Substitute = [&](IrOperand& Op) {
                if (Op.IsTemp()) {
                    auto It = TempCopies.constFind(Op.TempId);
                    if (It != TempCopies.constEnd() && SurvivesToBlockEnd(It.value())) {
                        IrType Keep = Op.Type;
                        Op = It.value();
                        if (Keep != IrType::Unknown && Op.OpKind != IrOperand::Imm) Op.Type = Keep;
                    }
                }
            };
            Substitute(Inst.Src1);
            Substitute(Inst.Src2);
            if (DestIsUse(Inst.Op)) Substitute(Inst.Dest);
            for (IrOperand& A : Inst.CallArgs) Substitute(A);

            // Effects of this instruction on recorded copies.
            if (Inst.Op == IrOp::Store || Inst.Op == IrOp::Call || Inst.Op == IrOp::Unknown) {
                InvalidateIf([](const IrOperand& V) { return V.IsStack() || V.OpKind == IrOperand::Global; });
            }
            if (Inst.Op == IrOp::Call || Inst.Op == IrOp::Unknown) {
                InvalidateIf([](const IrOperand& V) { return V.IsReg(); });
            }
            if (!DestIsUse(Inst.Op) && Inst.Dest.IsReg()) {
                const int R = Inst.Dest.RegId;
                InvalidateIf([R](const IrOperand& V) { return V.IsReg() && V.RegId == R; });
                // rsp/rbp moves change what stack slots refer to.
                if (R == 4 || R == 5) InvalidateIf([](const IrOperand& V) { return V.IsStack(); });
            }
            if (!DestIsUse(Inst.Op) && Inst.Dest.IsTemp()) {
                TempCopies.remove(Inst.Dest.TempId);
                if (Inst.Op == IrOp::Mov && !Inst.Src1.IsTemp() && Inst.Src1.IsValid() &&
                    Inst.Src1.OpKind != IrOperand::Mem) {
                    TempCopies[Inst.Dest.TempId] = Inst.Src1;
                }
            }
        }
    }
}

void Optimizer::RunConstantFolding(IrFunction& Func) {
    for (auto& Block : Func.Blocks) {
        for (int I = 0; I < Block.Instructions.size(); ++I) {
            IrInst& Inst = Block.Instructions[I];

            if (!Inst.Src1.IsImm() || !Inst.Src2.IsImm()) continue;

            int64_t A = Inst.Src1.ImmValue;
            int64_t B = Inst.Src2.ImmValue;
            int64_t Result = 0;
            bool Folded = false;

            switch (Inst.Op) {
                case IrOp::Add: Result = A + B; Folded = true; break;
                case IrOp::Sub: Result = A - B; Folded = true; break;
                case IrOp::Mul: Result = A * B; Folded = true; break;
                case IrOp::And: Result = A & B; Folded = true; break;
                case IrOp::Or:  Result = A | B; Folded = true; break;
                case IrOp::Xor: Result = A ^ B; Folded = true; break;
                case IrOp::Shl: Result = A << B; Folded = true; break;
                case IrOp::Shr: Result = static_cast<int64_t>(static_cast<uint64_t>(A) >> B); Folded = true; break;
                default: break;
            }

            if (Folded) {
                Inst.Op = IrOp::Mov;
                Inst.Src1 = IrOperand::MakeImm(Result, Inst.Dest.Type);
                Inst.Src2 = IrOperand::MakeInvalid();
            }
        }
    }
}

void Optimizer::RunStackVariableRecovery(IrFunction& Func) {
    Func.StackVars.clear();
    for (const auto& Block : Func.Blocks) {
        for (const auto& Inst : Block.Instructions) {
            auto CheckOp = [&](const IrOperand& Op, bool IsWrite) {
                if (!Op.IsStack()) return;
                int Key = StackKey(Op);
                if (!Func.StackVars.contains(Key)) {
                    StackVariable Var;
                    Var.Offset = Op.StackOffset;
                    Var.SpRelative = Op.SpRelative;
                    Var.Type = Op.Type;
                    Var.Size = IrTypeSize(Op.Type);
                    Var.AccessCount = 1;
                    Var.Name = StackVarName(Op.StackOffset, Op.SpRelative);
                    Func.StackVars[Key] = Var;
                } else {
                    StackVariable& Var = Func.StackVars[Key];
                    Var.AccessCount++;
                    if (IsWrite && Var.Type == IrType::Unknown) {
                        Var.Type = Op.Type;
                        Var.Size = IrTypeSize(Op.Type);
                    }
                }
            };

            CheckOp(Inst.Src1, false);
            CheckOp(Inst.Src2, false);
            CheckOp(Inst.Dest, Inst.Op == IrOp::Store);
        }
    }
}

void Optimizer::RunExpressionSimplification(IrFunction& Func) {
    for (auto& Block : Func.Blocks) {
        for (int I = 0; I < Block.Instructions.size(); ++I) {
            IrInst& Inst = Block.Instructions[I];

            if (Inst.Op == IrOp::Add && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Sub && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Mul && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 1) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Mul && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src1 = IrOperand::MakeImm(0, Inst.Dest.Type);
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Mul && Inst.Src2.IsImm()) {
                int64_t Val = Inst.Src2.ImmValue;
                if (Val > 0 && (Val & (Val - 1)) == 0) {
                    int Shift = 0;
                    int64_t Tmp = Val;
                    while (Tmp > 1) { Tmp >>= 1; Shift++; }
                    Inst.Op = IrOp::Shl;
                    Inst.Src2 = IrOperand::MakeImm(Shift);
                    continue;
                }
            }

            if (Inst.Op == IrOp::And && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src1 = IrOperand::MakeImm(0, Inst.Dest.Type);
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Or && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Shl && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }

            if (Inst.Op == IrOp::Shr && Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                Inst.Op = IrOp::Mov;
                Inst.Src2 = IrOperand::MakeInvalid();
                continue;
            }
        }
    }
}

void Optimizer::RunConditionRecovery(IrFunction& Func) {
    for (auto& Block : Func.Blocks) {
        for (int I = 0; I + 1 < Block.Instructions.size(); ++I) {
            IrInst& CmpInst = Block.Instructions[I];
            IrInst& JmpInst = Block.Instructions[I + 1];

            if (CmpInst.Op == IrOp::Test && JmpInst.Op == IrOp::CondJump) {
                if (OperandMatches(CmpInst.Src1, CmpInst.Src2)) {
                    if (JmpInst.Cond == CondCode::Equal || JmpInst.Cond == CondCode::Zero) {
                        CmpInst.Op = IrOp::Compare;
                        CmpInst.Src2 = IrOperand::MakeImm(0, CmpInst.Src1.Type);
                    } else if (JmpInst.Cond == CondCode::NotEqual || JmpInst.Cond == CondCode::NotZero) {
                        CmpInst.Op = IrOp::Compare;
                        CmpInst.Src2 = IrOperand::MakeImm(0, CmpInst.Src1.Type);
                    }
                }
            }
        }
    }
}

void Optimizer::RunConstantPropagation(IrFunction& Func) {
    for (int Pass = 0; Pass < 3; ++Pass) {
        bool Changed = false;

        QMap<int, QMap<int, int64_t>> BlockExitTemps;
        QMap<int, QMap<int, int64_t>> BlockExitRegs;

        for (int BlockIdx = 0; BlockIdx < Func.Blocks.size(); ++BlockIdx) {
            auto& Block = Func.Blocks[BlockIdx];
            QMap<int, int64_t> KnownTemps;
            QMap<int, int64_t> KnownRegs;

            if (Block.Predecessors.size() == 1) {
                int PredId = Block.Predecessors[0];
                if (BlockExitTemps.contains(PredId)) {
                    KnownTemps = BlockExitTemps[PredId];
                }
                if (BlockExitRegs.contains(PredId)) {
                    KnownRegs = BlockExitRegs[PredId];
                }
            }

            for (int I = 0; I < Block.Instructions.size(); ++I) {
                IrInst& Inst = Block.Instructions[I];

                for (IrOperand& A : Inst.CallArgs) {
                    if (A.IsTemp() && KnownTemps.contains(A.TempId)) {
                        A = IrOperand::MakeImm(KnownTemps[A.TempId], A.Type);
                        Changed = true;
                    } else if (A.IsReg() && KnownRegs.contains(A.RegId)) {
                        A = IrOperand::MakeImm(KnownRegs[A.RegId], A.Type);
                        Changed = true;
                    }
                }
                if (Inst.Op == IrOp::Call || Inst.Op == IrOp::Unknown) {
                    for (IrOperand& A : Inst.CallArgs) {
                        if (A.IsTemp() && KnownTemps.contains(A.TempId)) {
                            A = IrOperand::MakeImm(KnownTemps[A.TempId], A.Type);
                            Changed = true;
                        } else if (A.IsReg() && KnownRegs.contains(A.RegId)) {
                            A = IrOperand::MakeImm(KnownRegs[A.RegId], A.Type);
                            Changed = true;
                        }
                    }
                    KnownRegs.clear();
                    if (Inst.Dest.IsTemp()) {
                        KnownTemps.remove(Inst.Dest.TempId);
                    }
                    continue;
                }

                if (Inst.Op == IrOp::Load) {
                    if (Inst.Dest.IsTemp()) {
                        KnownTemps.remove(Inst.Dest.TempId);
                    } else if (Inst.Dest.IsReg()) {
                        KnownRegs.remove(Inst.Dest.RegId);
                    }
                    continue;
                }

                auto SubstituteOperand = [&](IrOperand& Op) {
                    if (Op.IsTemp() && KnownTemps.contains(Op.TempId)) {
                        Op = IrOperand::MakeImm(KnownTemps[Op.TempId], Op.Type);
                        Changed = true;
                    } else if (Op.IsReg() && KnownRegs.contains(Op.RegId)) {
                        Op = IrOperand::MakeImm(KnownRegs[Op.RegId], Op.Type);
                        Changed = true;
                    }
                };

                SubstituteOperand(Inst.Src1);
                SubstituteOperand(Inst.Src2);

                if (Inst.Dest.IsReg() && (IrTypeSize(Inst.Dest.Type) == 1 || IrTypeSize(Inst.Dest.Type) == 2)) {
                    // Partial register write: the full value is no longer a known constant.
                    KnownRegs.remove(Inst.Dest.RegId);
                    continue;
                }

                if (Inst.Op == IrOp::Mov && Inst.Src1.IsImm()) {
                    if (Inst.Dest.IsTemp()) {
                        KnownTemps[Inst.Dest.TempId] = Inst.Src1.ImmValue;
                    } else if (Inst.Dest.IsReg()) {
                        KnownRegs[Inst.Dest.RegId] = Inst.Src1.ImmValue;
                    }
                    continue;
                }

                if (Inst.Src1.IsImm() && Inst.Src2.IsImm()) {
                    int64_t A = Inst.Src1.ImmValue;
                    int64_t B = Inst.Src2.ImmValue;
                    int64_t Result = 0;
                    bool Computed = false;

                    switch (Inst.Op) {
                        case IrOp::Add: Result = A + B; Computed = true; break;
                        case IrOp::Sub: Result = A - B; Computed = true; break;
                        case IrOp::Mul: Result = A * B; Computed = true; break;
                        case IrOp::And: Result = A & B; Computed = true; break;
                        case IrOp::Or:  Result = A | B; Computed = true; break;
                        case IrOp::Xor: Result = A ^ B; Computed = true; break;
                        case IrOp::Shl: Result = A << B; Computed = true; break;
                        case IrOp::Shr: Result = static_cast<int64_t>(static_cast<uint64_t>(A) >> B); Computed = true; break;
                        case IrOp::Sar: Result = A >> B; Computed = true; break;
                        default: break;
                    }

                    if (Computed) {
                        IrType DestType = Inst.Dest.Type;
                        Inst.Op = IrOp::Mov;
                        Inst.Src1 = IrOperand::MakeImm(Result, DestType);
                        Inst.Src2 = IrOperand::MakeInvalid();
                        Changed = true;

                        if (Inst.Dest.IsTemp()) {
                            KnownTemps[Inst.Dest.TempId] = Result;
                        } else if (Inst.Dest.IsReg()) {
                            KnownRegs[Inst.Dest.RegId] = Result;
                        }
                        continue;
                    }
                }

                if (Inst.Src1.IsImm() && !Inst.Src2.IsValid()) {
                    if (Inst.Dest.IsTemp()) {
                        KnownTemps.remove(Inst.Dest.TempId);
                    } else if (Inst.Dest.IsReg()) {
                        KnownRegs.remove(Inst.Dest.RegId);
                    }
                    continue;
                }

                if (Inst.Dest.IsTemp()) {
                    KnownTemps.remove(Inst.Dest.TempId);
                } else if (Inst.Dest.IsReg()) {
                    KnownRegs.remove(Inst.Dest.RegId);
                }
            }

            BlockExitTemps[Block.Id] = KnownTemps;
            BlockExitRegs[Block.Id] = KnownRegs;
        }

        if (!Changed) break;
    }
}

void Optimizer::RunTypeRecovery(IrFunction& Func) {
    QMap<int, IrType> TempTypes;
    QMap<int, IrType> RegTypes;
    QMap<int, IrType> StackTypes;

    static const QMap<QString, QVector<IrType>> KnownSignatures = {
        {"strlen",      {IrType::Pointer}},
        {"strcpy",      {IrType::Pointer, IrType::Pointer}},
        {"strncpy",     {IrType::Pointer, IrType::Pointer, IrType::UInt64}},
        {"strcmp",       {IrType::Pointer, IrType::Pointer}},
        {"strncmp",     {IrType::Pointer, IrType::Pointer, IrType::UInt64}},
        {"strcat",      {IrType::Pointer, IrType::Pointer}},
        {"strchr",      {IrType::Pointer, IrType::Int32}},
        {"strstr",      {IrType::Pointer, IrType::Pointer}},
        {"memcpy",      {IrType::Pointer, IrType::Pointer, IrType::UInt64}},
        {"memset",      {IrType::Pointer, IrType::Int32, IrType::UInt64}},
        {"memcmp",      {IrType::Pointer, IrType::Pointer, IrType::UInt64}},
        {"memmove",     {IrType::Pointer, IrType::Pointer, IrType::UInt64}},
        {"malloc",      {IrType::UInt64}},
        {"calloc",      {IrType::UInt64, IrType::UInt64}},
        {"realloc",     {IrType::Pointer, IrType::UInt64}},
        {"free",        {IrType::Pointer}},
        {"printf",      {IrType::Pointer}},
        {"sprintf",     {IrType::Pointer, IrType::Pointer}},
        {"snprintf",    {IrType::Pointer, IrType::UInt64, IrType::Pointer}},
        {"fprintf",     {IrType::Pointer, IrType::Pointer}},
        {"fopen",       {IrType::Pointer, IrType::Pointer}},
        {"fclose",      {IrType::Pointer}},
        {"fread",       {IrType::Pointer, IrType::UInt64, IrType::UInt64, IrType::Pointer}},
        {"fwrite",      {IrType::Pointer, IrType::UInt64, IrType::UInt64, IrType::Pointer}},
        {"atoi",        {IrType::Pointer}},
        {"atol",        {IrType::Pointer}},
        {"strtol",      {IrType::Pointer, IrType::Pointer, IrType::Int32}},
        {"strtoul",     {IrType::Pointer, IrType::Pointer, IrType::Int32}},
    };

    auto PromoteType = [](IrType Existing, IrType New) -> IrType {
        if (Existing == IrType::Unknown) return New;
        if (New == IrType::Unknown) return Existing;
        if (Existing == New) return Existing;
        if (New == IrType::Pointer) return IrType::Pointer;
        if (Existing == IrType::Pointer) return IrType::Pointer;
        return Existing;
    };

    auto RecordTemp = [&](int TempId, IrType T) {
        if (TempId < 0 || T == IrType::Unknown) return;
        TempTypes[TempId] = PromoteType(TempTypes.value(TempId, IrType::Unknown), T);
    };

    auto RecordReg = [&](int RegId, IrType T) {
        if (RegId < 0 || T == IrType::Unknown) return;
        RegTypes[RegId] = PromoteType(RegTypes.value(RegId, IrType::Unknown), T);
    };

    auto RecordStack = [&](int Offset, IrType T) {
        if (T == IrType::Unknown) return;
        StackTypes[Offset] = PromoteType(StackTypes.value(Offset, IrType::Unknown), T);
    };

    auto MarkPointer = [&](const IrOperand& Op) {
        if (Op.IsTemp()) RecordTemp(Op.TempId, IrType::Pointer);
        else if (Op.IsReg()) RecordReg(Op.RegId, IrType::Pointer);
        else if (Op.IsStack()) RecordStack(StackKey(Op), IrType::Pointer);
    };

    for (const auto& Block : Func.Blocks) {
        for (int I = 0; I < Block.Instructions.size(); ++I) {
            const IrInst& Inst = Block.Instructions[I];

            if (Inst.Op == IrOp::Deref || Inst.Op == IrOp::AddressOf) {
                MarkPointer(Inst.Src1);
            }

            if (Inst.Op == IrOp::AddressOf) {
                MarkPointer(Inst.Dest);
            }

            if (Inst.Op == IrOp::Store) {
                MarkPointer(Inst.Dest);
                if (Inst.Src1.IsStack()) {
                    RecordStack(StackKey(Inst.Src1), Inst.Src1.Type);
                }
            }

            if (Inst.Op == IrOp::Load) {
                if (Inst.Src1.IsStack()) {
                    RecordStack(StackKey(Inst.Src1), Inst.Src1.Type);
                }
                if (Inst.Dest.IsTemp() && Inst.Src1.Type != IrType::Unknown) {
                    RecordTemp(Inst.Dest.TempId, Inst.Src1.Type);
                }
            }

            if (Inst.Op == IrOp::Compare || Inst.Op == IrOp::Test) {
                if (I + 1 < Block.Instructions.size()) {
                    const IrInst& Next = Block.Instructions[I + 1];
                    if (Next.Op == IrOp::CondJump) {
                        if (Inst.Src2.IsImm() && Inst.Src2.ImmValue == 0) {
                            if (Inst.Src1.IsTemp()) {
                                IrType CurrentType = TempTypes.value(Inst.Src1.TempId, IrType::Unknown);
                                if (CurrentType == IrType::Unknown) {
                                    RecordTemp(Inst.Src1.TempId, IrType::Int32);
                                }
                            }
                        }
                    }
                }
            }

            if (Inst.Op == IrOp::Call && Inst.CallProto) {
                // Argument and return types straight from the prototype.
                for (int K = 0; K < Inst.CallArgs.size() && K < Inst.CallProto->Params.size(); ++K) {
                    const IrOperand& A = Inst.CallArgs[K];
                    const IrType T = IrTypeFromCType(Inst.CallProto->Params[K].Type);
                    if (A.IsTemp()) RecordTemp(A.TempId, T);
                    else if (A.IsStack()) RecordStack(StackKey(A), T);
                }
            } else if (Inst.Op == IrOp::Call && !Inst.CallName.isEmpty()) {
                if (KnownSignatures.contains(Inst.CallName)) {
                    const auto& ParamTypes = KnownSignatures[Inst.CallName];

                    static const int ArgRegs[] = {7, 6, 2, 1, 8, 9};

                    int ArgIdx = 0;
                    for (int J = I - 1; J >= 0 && ArgIdx < ParamTypes.size(); --J) {
                        const IrInst& Prev = Block.Instructions[J];
                        if (Prev.Op == IrOp::Mov || Prev.Op == IrOp::Load) {
                            if (Prev.Dest.IsReg() && ArgIdx < 6 && Prev.Dest.RegId == ArgRegs[ArgIdx]) {
                                if (Prev.Src1.IsTemp()) {
                                    RecordTemp(Prev.Src1.TempId, ParamTypes[ArgIdx]);
                                } else if (Prev.Src1.IsStack()) {
                                    RecordStack(StackKey(Prev.Src1), ParamTypes[ArgIdx]);
                                }
                                RecordReg(Prev.Dest.RegId, ParamTypes[ArgIdx]);
                                ArgIdx++;
                            }
                        }
                        if (Prev.Op == IrOp::Call) break;
                    }

                    if (Inst.CallName == "malloc" || Inst.CallName == "calloc" ||
                        Inst.CallName == "realloc" || Inst.CallName == "strstr" ||
                        Inst.CallName == "strchr" || Inst.CallName == "strcpy" ||
                        Inst.CallName == "strncpy" || Inst.CallName == "strcat" ||
                        Inst.CallName == "memcpy" || Inst.CallName == "memmove" ||
                        Inst.CallName == "fopen") {
                        if (Inst.Dest.IsTemp()) {
                            RecordTemp(Inst.Dest.TempId, IrType::Pointer);
                        } else if (Inst.Dest.IsReg()) {
                            RecordReg(Inst.Dest.RegId, IrType::Pointer);
                        }
                    }

                    if (Inst.CallName == "strlen" || Inst.CallName == "strcmp" ||
                        Inst.CallName == "strncmp" || Inst.CallName == "memcmp" ||
                        Inst.CallName == "atoi" || Inst.CallName == "printf" ||
                        Inst.CallName == "fprintf" || Inst.CallName == "sprintf" ||
                        Inst.CallName == "snprintf") {
                        if (Inst.Dest.IsTemp()) {
                            RecordTemp(Inst.Dest.TempId, IrType::Int64);
                        } else if (Inst.Dest.IsReg()) {
                            RecordReg(Inst.Dest.RegId, IrType::Int64);
                        }
                    }
                }
            }
        }
    }

    QMap<int, QMap<int, int>> StackAccessSizes;
    for (const auto& Block : Func.Blocks) {
        for (const auto& Inst : Block.Instructions) {
            auto CheckStackConsistency = [&](const IrOperand& Op) {
                if (!Op.IsStack()) return;
                int Size = IrTypeSize(Op.Type);
                if (Size > 0) {
                    StackAccessSizes[StackKey(Op)][Size]++;
                }
            };
            CheckStackConsistency(Inst.Src1);
            CheckStackConsistency(Inst.Src2);
            CheckStackConsistency(Inst.Dest);
        }
    }

    for (auto It = StackAccessSizes.begin(); It != StackAccessSizes.end(); ++It) {
        int Offset = It.key();
        const auto& SizeMap = It.value();
        if (SizeMap.size() == 1) {
            int Size = SizeMap.begin().key();
            IrType UnifiedType = IrTypeFromSize(Size, true);
            if (UnifiedType != IrType::Unknown) {
                IrType Existing = StackTypes.value(Offset, IrType::Unknown);
                if (Existing == IrType::Unknown) {
                    StackTypes[Offset] = UnifiedType;
                }
            }
        }
    }

    for (auto& Block : Func.Blocks) {
        for (auto& Inst : Block.Instructions) {
            auto ApplyType = [&](IrOperand& Op) {
                if (Op.Type != IrType::Unknown) return;
                if (Op.IsTemp() && TempTypes.contains(Op.TempId)) {
                    Op.Type = TempTypes[Op.TempId];
                } else if (Op.IsReg() && RegTypes.contains(Op.RegId)) {
                    Op.Type = RegTypes[Op.RegId];
                } else if (Op.IsStack() && StackTypes.contains(StackKey(Op))) {
                    Op.Type = StackTypes[StackKey(Op)];
                }
            };

            ApplyType(Inst.Dest);
            ApplyType(Inst.Src1);
            ApplyType(Inst.Src2);
            for (IrOperand& A : Inst.CallArgs) ApplyType(A);
        }
    }

    for (auto It = StackTypes.begin(); It != StackTypes.end(); ++It) {
        int Offset = It.key();
        IrType InferredType = It.value();
        if (Func.StackVars.contains(Offset)) {
            auto& Var = Func.StackVars[Offset];
            if (Var.Type == IrType::Unknown) {
                Var.Type = InferredType;
                Var.Size = IrTypeSize(InferredType);
            }
        }
    }
}

void Optimizer::RunPrologueEpilogueCleanup(IrFunction& Func) {
    if (Func.Blocks.isEmpty()) return;

    auto IsRsp = [](const IrOperand& Op) { return Op.IsReg() && Op.RegId == 4; };
    auto IsRbp = [](const IrOperand& Op) { return Op.IsReg() && Op.RegId == 5; };
    auto IsRspAdjust = [&](const IrInst& Inst) {
        return (Inst.Op == IrOp::Sub || Inst.Op == IrOp::Add) && IsRsp(Inst.Dest) && IsRsp(Inst.Src1) && Inst.Src2.IsImm();
    };

    auto IsPrologue = [&](const IrInst& Inst) {
        if (IsRspAdjust(Inst)) return true;
        if (Inst.Op == IrOp::Store && IsRsp(Inst.Dest) && Inst.Src1.IsReg()) return true;  // push reg
        return IsRbp(Inst.Dest) && IsRsp(Inst.Src1) && (Inst.Op == IrOp::Mov || (Inst.Op == IrOp::Add && Inst.Src2.IsImm()));
    };
    auto IsEpilogue = [&](const IrInst& Inst) {
        if (IsRspAdjust(Inst)) return true;
        if (Inst.Op == IrOp::Load && Inst.Dest.IsReg() && IsRsp(Inst.Src1)) return true;  // pop reg
        return IsRsp(Inst.Dest) && IsRbp(Inst.Src1) && (Inst.Op == IrOp::Mov || (Inst.Op == IrOp::Add && Inst.Src2.IsImm()));
    };
    // Instructions the scheduler may interleave with the prologue/epilogue:
    // no control flow, no stack access, no rsp.
    auto TouchesStack = [&](const IrInst& Inst) {
        if (Inst.Op == IrOp::Call || Inst.Op == IrOp::Ret || Inst.Op == IrOp::Jump || Inst.Op == IrOp::CondJump ||
            Inst.Op == IrOp::Unknown)
            return true;
        for (const IrOperand* Op : {&Inst.Dest, &Inst.Src1, &Inst.Src2})
            if (IsRsp(*Op) || (Op->IsStack() && Op->SpRelative)) return true;
        return false;
    };
    auto Writes = [](const IrInst& Inst, int Reg) {
        return Inst.Op != IrOp::Store && Inst.Op != IrOp::Compare && Inst.Op != IrOp::Test &&
               Inst.Dest.IsReg() && Inst.Dest.RegId == Reg;
    };
    auto Reads = [](const IrInst& Inst, int Reg) {
        if ((Inst.Src1.IsReg() && Inst.Src1.RegId == Reg) || (Inst.Src2.IsReg() && Inst.Src2.RegId == Reg)) return true;
        if ((Inst.Op == IrOp::Store || Inst.Op == IrOp::Compare || Inst.Op == IrOp::Test) && Inst.Dest.IsReg() && Inst.Dest.RegId == Reg) return true;
        for (const IrOperand& A : Inst.CallArgs)
            if (A.IsReg() && A.RegId == Reg) return true;
        return false;
    };

    // Entry: register saves (push = sub rsp, 8 + store [rsp]), frame setup
    // (mov rbp, rsp / lea rbp, [rsp+N]) and the stack allocation, possibly
    // interleaved with unrelated register moves. A push of a register the
    // function already changed is a real store, not a save.
    {
        auto& Entry = Func.Blocks[0].Instructions;
        QVector<int> Drop;
        QSet<int> Written;
        for (int I = 0; I < Entry.size(); ++I) {
            const IrInst& Inst = Entry[I];
            if (Inst.Op == IrOp::Nop) continue;
            if (IsPrologue(Inst)) {
                if (Inst.Op == IrOp::Store && Written.contains(Inst.Src1.RegId)) break;
                if (IsRbp(Inst.Dest)) {
                    if (Written.contains(5)) break;
                    Func.UsesFramePointer = true;
                }
                Drop << I;
                continue;
            }
            if (TouchesStack(Inst)) break;
            if (Inst.Dest.IsReg() && Writes(Inst, Inst.Dest.RegId)) Written.insert(Inst.Dest.RegId);
        }
        for (int K = Drop.size() - 1; K >= 0; --K) Entry.remove(Drop[K]);
    }

    // Exits: the mirror image before the terminator — rsp restore
    // (add rsp / mov rsp, rbp / lea rsp, [rbp+N]) and pops (load reg, [rsp]).
    // A pop whose register is read afterwards is a real load and stays.
    for (auto& Block : Func.Blocks) {
        auto& Insts = Block.Instructions;
        const bool TailJump = !Insts.isEmpty() && Insts.last().Op == IrOp::Jump && Block.Successors.isEmpty();
        if (!Block.IsExit && !TailJump) continue;
        int End = static_cast<int>(Insts.size());
        while (End > 0 && (Insts[End - 1].Op == IrOp::Ret || Insts[End - 1].Op == IrOp::Jump ||
                           Insts[End - 1].Op == IrOp::Nop))
            --End;
        if (End == static_cast<int>(Insts.size())) continue;  // no ret / tail jump: not an epilogue
        QVector<int> Drop;
        for (int I = End - 1; I >= 0; --I) {
            const IrInst& Inst = Insts[I];
            if (Inst.Op == IrOp::Nop) continue;
            if (IsEpilogue(Inst)) {
                if (Inst.Op == IrOp::Load) {
                    bool UsedLater = false;
                    for (int J = I + 1; J < Insts.size() && !UsedLater; ++J)
                        if (!Drop.contains(J) && Reads(Insts[J], Inst.Dest.RegId)) UsedLater = true;
                    if (UsedLater) break;
                }
                Drop << I;
                continue;
            }
            if (TouchesStack(Inst)) break;
        }
        for (int K : Drop) Insts.remove(K);  // descending order
    }
}

}
