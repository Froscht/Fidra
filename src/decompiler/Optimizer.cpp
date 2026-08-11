#include "Optimizer.h"

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

bool Optimizer::IsDefUsed(const IrOperand& Def, const IrBasicBlock& Block, int DefIdx) {
    for (int I = DefIdx + 1; I < Block.Instructions.size(); ++I) {
        const IrInst& Inst = Block.Instructions[I];
        if (OperandMatches(Inst.Src1, Def) || OperandMatches(Inst.Src2, Def)) return true;
        if (OperandMatches(Inst.Dest, Def)) return false;
    }
    return true;
}

bool Optimizer::IsDefUsedInAnyBlock(const IrOperand& Def, const IrFunction& Func, int DefBlock, int DefIdx) {
    if (IsDefUsed(Def, Func.Blocks[DefBlock], DefIdx)) return true;
    for (int SuccId : Func.Blocks[DefBlock].Successors) {
        for (const auto& Inst : Func.Blocks[SuccId].Instructions) {
            if (OperandMatches(Inst.Src1, Def) || OperandMatches(Inst.Src2, Def)) return true;
        }
    }
    return false;
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

    return Result;
}

void Optimizer::RunDeadCodeElimination(IrFunction& Func) {
    for (auto& Block : Func.Blocks) {
        QVector<IrInst> Kept;
        for (int I = 0; I < Block.Instructions.size(); ++I) {
            const IrInst& Inst = Block.Instructions[I];

            if (Inst.Op == IrOp::Nop) continue;

            if (Inst.Op == IrOp::Store || Inst.Op == IrOp::Call || Inst.Op == IrOp::Ret ||
                Inst.Op == IrOp::Jump || Inst.Op == IrOp::CondJump || Inst.Op == IrOp::Compare ||
                Inst.Op == IrOp::Test) {
                Kept.append(Inst);
                continue;
            }

            if (!Inst.Dest.IsValid()) {
                Kept.append(Inst);
                continue;
            }

            if (Inst.Dest.IsReg() && (Inst.Dest.RegId == 4 || Inst.Dest.RegId == 5)) {
                Kept.append(Inst);
                continue;
            }

            if (IsDefUsedInAnyBlock(Inst.Dest, Func, Block.Id, I)) {
                Kept.append(Inst);
            }
        }
        Block.Instructions = Kept;
    }
}

void Optimizer::RunCopyPropagation(IrFunction& Func) {
    for (int Pass = 0; Pass < 3; ++Pass) {
        bool Changed = false;
        for (auto& Block : Func.Blocks) {
            QMap<int, IrOperand> TempCopies;
            QMap<int, IrOperand> RegCopies;

            for (int I = 0; I < Block.Instructions.size(); ++I) {
                IrInst& Inst = Block.Instructions[I];

                auto Substitute = [&](IrOperand& Op) {
                    if (Op.IsTemp() && TempCopies.contains(Op.TempId)) {
                        Op = TempCopies[Op.TempId];
                        Changed = true;
                    }
                };

                Substitute(Inst.Src1);
                Substitute(Inst.Src2);

                if (Inst.Op == IrOp::Mov && Inst.Dest.IsTemp() && !Inst.Src1.IsTemp()) {
                    TempCopies[Inst.Dest.TempId] = Inst.Src1;
                }

                if (Inst.Op == IrOp::Store || Inst.Op == IrOp::Call) {
                    RegCopies.clear();
                }

                if (Inst.Dest.IsTemp()) {
                    QVector<int> ToRemove;
                    for (auto It = TempCopies.begin(); It != TempCopies.end(); ++It) {
                        if (It.value().IsTemp() && It.value().TempId == Inst.Dest.TempId) {
                            ToRemove.append(It.key());
                        }
                    }
                    for (int Key : ToRemove) TempCopies.remove(Key);
                }
            }
        }
        if (!Changed) break;
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
                int Off = Op.StackOffset;
                if (!Func.StackVars.contains(Off)) {
                    StackVariable Var;
                    Var.Offset = Off;
                    Var.Type = Op.Type;
                    Var.Size = IrTypeSize(Op.Type);
                    Var.AccessCount = 1;
                    if (Off < 0) {
                        Var.Name = QString("Local_%1").arg(-Off, 0, 16);
                    } else if (Off >= 8) {
                        Var.Name = QString("Arg_%1").arg((Off - 16) / 8);
                    } else {
                        Var.Name = QString("Var_%1").arg(Off, 0, 16);
                    }
                    Func.StackVars[Off] = Var;
                } else {
                    Func.StackVars[Off].AccessCount++;
                    if (IsWrite && Func.StackVars[Off].Type == IrType::Unknown) {
                        Func.StackVars[Off].Type = Op.Type;
                        Func.StackVars[Off].Size = IrTypeSize(Op.Type);
                    }
                }
            };

            if (Inst.Op == IrOp::Store) CheckOp(Inst.Dest, true);
            if (Inst.Op == IrOp::Load) CheckOp(Inst.Src1, false);
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

                if (Inst.Op == IrOp::Call) {
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
        else if (Op.IsStack()) RecordStack(Op.StackOffset, IrType::Pointer);
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
                    RecordStack(Inst.Src1.StackOffset, Inst.Src1.Type);
                }
            }

            if (Inst.Op == IrOp::Load) {
                if (Inst.Src1.IsStack()) {
                    RecordStack(Inst.Src1.StackOffset, Inst.Src1.Type);
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

            if (Inst.Op == IrOp::Call && !Inst.CallName.isEmpty()) {
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
                                    RecordStack(Prev.Src1.StackOffset, ParamTypes[ArgIdx]);
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
                    StackAccessSizes[Op.StackOffset][Size]++;
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
                } else if (Op.IsStack() && StackTypes.contains(Op.StackOffset)) {
                    Op.Type = StackTypes[Op.StackOffset];
                }
            };

            ApplyType(Inst.Dest);
            ApplyType(Inst.Src1);
            ApplyType(Inst.Src2);
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

    auto& EntryBlock = Func.Blocks[0];
    QVector<IrInst> Cleaned;
    int SkipPrologue = 0;

    for (int I = 0; I < EntryBlock.Instructions.size(); ++I) {
        const IrInst& Inst = EntryBlock.Instructions[I];

        if (I < 3) {
            if (Inst.Op == IrOp::Sub && Inst.Dest.IsReg() && Inst.Dest.RegId == 4 &&
                Inst.Src1.IsReg() && Inst.Src1.RegId == 4 && Inst.Src2.IsImm()) {
                SkipPrologue++;
                continue;
            }
            if (Inst.Op == IrOp::Store && Inst.Dest.IsReg() && Inst.Dest.RegId == 4 &&
                Inst.Src1.IsReg() && Inst.Src1.RegId == 5) {
                SkipPrologue++;
                continue;
            }
            if (Inst.Op == IrOp::Mov && Inst.Dest.IsReg() && Inst.Dest.RegId == 5 &&
                Inst.Src1.IsReg() && Inst.Src1.RegId == 4) {
                Func.UsesFramePointer = true;
                SkipPrologue++;
                continue;
            }
        }
        Cleaned.append(Inst);
    }
    if (SkipPrologue > 0) EntryBlock.Instructions = Cleaned;

    for (auto& Block : Func.Blocks) {
        if (!Block.IsExit) continue;
        QVector<IrInst> CleanedExit;
        for (int I = 0; I < Block.Instructions.size(); ++I) {
            const IrInst& Inst = Block.Instructions[I];

            if (I >= Block.Instructions.size() - 4) {
                if (Inst.Op == IrOp::Mov && Inst.Dest.IsReg() && Inst.Dest.RegId == 4 &&
                    Inst.Src1.IsReg() && Inst.Src1.RegId == 5) {
                    continue;
                }
                if (Inst.Op == IrOp::Load && Inst.Dest.IsReg() && Inst.Dest.RegId == 5 &&
                    Inst.Src1.IsReg() && Inst.Src1.RegId == 4) {
                    continue;
                }
                if (Inst.Op == IrOp::Add && Inst.Dest.IsReg() && Inst.Dest.RegId == 4 &&
                    Inst.Src1.IsReg() && Inst.Src1.RegId == 4 && Inst.Src2.IsImm()) {
                    continue;
                }
            }
            CleanedExit.append(Inst);
        }
        Block.Instructions = CleanedExit;
    }
}

}
