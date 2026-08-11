#include "CodeGenerator.h"

#include <QElapsedTimer>

namespace Fidra::Decomp {

CodeGenerator::CodeGenerator()
    : IndentWidth(4)
    , ShowAddresses(false)
    , ShowTypes(true)
    , Db(nullptr)
    , CurrentFunc(nullptr)
{
}

void CodeGenerator::SetIndentWidth(int Width) {
    IndentWidth = Width;
}

void CodeGenerator::SetShowAddresses(bool Show) {
    ShowAddresses = Show;
}

void CodeGenerator::SetShowTypes(bool Show) {
    ShowTypes = Show;
}

DecompOutput CodeGenerator::Generate(const IrFunction& Func, const AnalysisDatabase* InDb) {
    QElapsedTimer Timer;
    Timer.start();

    Db = InDb;
    CurrentFunc = &Func;

    DecompOutput Out;
    Out.FunctionSignature = GenerateSignature(Func);
    Out.PseudoC = GenerateFunction(Func);
    Out.IrDump = DumpIr(Func);

    for (auto It = Func.StackVars.begin(); It != Func.StackVars.end(); ++It) {
        Out.LocalVars.append(QString("%1 %2").arg(IrTypeToString(It.value().Type), It.value().Name));
    }

    Out.Complexity = 0;
    for (const auto& Block : Func.Blocks) {
        Out.Complexity += Block.Instructions.size();
    }

    Out.TimeMs = Timer.elapsed();
    CurrentFunc = nullptr;
    Db = nullptr;

    return Out;
}

QString CodeGenerator::GenerateSignature(const IrFunction& Func) {
    QString Sig = IrTypeToString(Func.ReturnType) + " " + Func.Name + "(";
    for (int I = 0; I < Func.Parameters.size(); ++I) {
        if (I > 0) Sig += ", ";
        const auto& P = Func.Parameters[I];
        Sig += IrTypeToString(P.Type);
        if (!P.Name.isEmpty()) {
            Sig += " " + P.Name;
        } else {
            Sig += QString(" Arg%1").arg(I);
        }
    }
    Sig += ")";
    return Sig;
}

QString CodeGenerator::GenerateLocals(const IrFunction& Func) {
    QString Result;
    for (auto It = Func.StackVars.begin(); It != Func.StackVars.end(); ++It) {
        const StackVariable& Var = It.value();
        if (Var.Offset >= 8) continue;
        Result += IndentStr(1) + IrTypeToString(Var.Type) + " " + Var.Name + ";\n";
    }
    if (!Result.isEmpty()) Result += "\n";
    return Result;
}

QString CodeGenerator::GenerateFunction(const IrFunction& Func) {
    QString Result;
    Result += GenerateSignature(Func) + "\n{\n";
    Result += GenerateLocals(Func);

    QVector<ControlFlowNode> CfNodes = StructureControlFlow(Func);

    if (!CfNodes.isEmpty()) {
        Result += RenderControlFlow(CfNodes, Func, 1);
    } else {
        for (const auto& Block : Func.Blocks) {
            Result += GenerateBlock(Block, 1);
        }
    }

    Result += "}\n";
    return Result;
}

QString CodeGenerator::GenerateBlock(const IrBasicBlock& Block, int Indent) {
    QString Result;

    if (ShowAddresses && Block.StartAddr != 0) {
        Result += IndentStr(Indent) + "/* " + FormatHex(Block.StartAddr) + " */\n";
    }

    for (const auto& Inst : Block.Instructions) {
        QString Line = GenerateInst(Inst, Indent);
        if (!Line.isEmpty()) {
            Result += Line;
        }
    }

    return Result;
}

QString CodeGenerator::GenerateInst(const IrInst& Inst, int Indent) {
    QString Prefix;
    if (ShowAddresses && Inst.OriginalAddr != 0) {
        Prefix = "/* " + FormatHex(Inst.OriginalAddr) + " */ ";
    }

    switch (Inst.Op) {
    case IrOp::Mov: {
        if (!Inst.Dest.IsValid()) return "";
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + ";\n";
    }
    case IrOp::Add:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " + " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Sub:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " - " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Mul:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " * " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Div:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " / " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Mod:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " % " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::And:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " & " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Or:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " | " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Xor:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " ^ " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Shl:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " << " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Shr:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + " >> " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Sar:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = (int64_t)" + GenerateOperand(Inst.Src1) + " >> " + GenerateOperand(Inst.Src2) + ";\n";
    case IrOp::Not:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = ~" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Neg:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = -" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Load:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = *(" + IrTypeToString(Inst.Dest.Type) + "*)" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Store:
        return IndentStr(Indent) + Prefix + "*(" + IrTypeToString(Inst.Src1.Type) + "*)" + GenerateOperand(Inst.Dest) + " = " + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Call: {
        QString CallStr;
        if (!Inst.CallName.isEmpty()) {
            CallStr = Inst.CallName;
        } else if (Inst.CallTarget != 0) {
            if (Db) {
                QString FnName = Db->GetName(Inst.CallTarget);
                CallStr = FnName.isEmpty() ? FormatHex(Inst.CallTarget) : FnName;
            } else {
                CallStr = FormatHex(Inst.CallTarget);
            }
        } else {
            CallStr = GenerateOperand(Inst.Src1);
        }

        if (Inst.Dest.IsValid() && Inst.Dest.Type != IrType::Void) {
            return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + CallStr + "();\n";
        }
        return IndentStr(Indent) + Prefix + CallStr + "();\n";
    }
    case IrOp::Ret: {
        if (Inst.Src1.IsValid() && Inst.Src1.Type != IrType::Void) {
            return IndentStr(Indent) + Prefix + "return " + GenerateOperand(Inst.Src1) + ";\n";
        }
        return IndentStr(Indent) + Prefix + "return;\n";
    }
    case IrOp::Jump:
        return "";
    case IrOp::CondJump:
        return "";
    case IrOp::Compare:
        return "";
    case IrOp::Test:
        return "";
    case IrOp::Cast:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = (" + IrTypeToString(Inst.Dest.Type) + ")" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::SignExtend:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = (int64_t)(" + IrTypeToString(Inst.Src1.Type) + ")" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::ZeroExtend:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = (uint64_t)" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::AddressOf:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = &" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Deref:
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = *" + GenerateOperand(Inst.Src1) + ";\n";
    case IrOp::Nop:
    case IrOp::Phi:
    case IrOp::StackAlloc:
    case IrOp::Unknown:
        return "";
    }
    return "";
}

QString CodeGenerator::GenerateOperand(const IrOperand& Op) {
    switch (Op.OpKind) {
    case IrOperand::Reg: {
        if (CurrentFunc) {
            for (auto It = CurrentFunc->StackVars.begin(); It != CurrentFunc->StackVars.end(); ++It) {
                if (It.value().Name == Op.Name && !Op.Name.isEmpty()) return Op.Name;
            }
        }
        return RegName64(Op.RegId);
    }
    case IrOperand::Imm:
        return FormatHex(Op.ImmValue);
    case IrOperand::Temp:
        return QString("T%1").arg(Op.TempId);
    case IrOperand::Stack: {
        if (CurrentFunc && CurrentFunc->StackVars.contains(Op.StackOffset)) {
            return CurrentFunc->StackVars[Op.StackOffset].Name;
        }
        if (Op.StackOffset < 0) {
            return QString("Local_%1").arg(-Op.StackOffset, 0, 16);
        }
        if (Op.StackOffset >= 8) {
            return QString("Arg_%1").arg((Op.StackOffset - 16) / 8);
        }
        return QString("Var_%1").arg(Op.StackOffset, 0, 16);
    }
    case IrOperand::Global: {
        if (Db) {
            QString Name = Db->GetName(Op.GlobalAddr);
            if (!Name.isEmpty()) return Name;
        }
        return FormatHex(Op.GlobalAddr);
    }
    case IrOperand::Label:
        return QString("Label_%1").arg(Op.GlobalAddr, 0, 16);
    case IrOperand::Mem:
    case IrOperand::Invalid:
    default:
        return "???";
    }
}

QString CodeGenerator::GenerateCondition(CondCode Cond, const IrOperand& Lhs, const IrOperand& Rhs, bool Negated) {
    QString L = GenerateOperand(Lhs);
    QString R = GenerateOperand(Rhs);

    auto Negate = [](const QString& Op) -> QString {
        if (Op == "==") return "!=";
        if (Op == "!=") return "==";
        if (Op == "<") return ">=";
        if (Op == ">=") return "<";
        if (Op == ">") return "<=";
        if (Op == "<=") return ">";
        return "!" + Op;
    };

    QString Op;
    switch (Cond) {
    case CondCode::Equal:
    case CondCode::Zero:
        Op = "=="; break;
    case CondCode::NotEqual:
    case CondCode::NotZero:
        Op = "!="; break;
    case CondCode::SignedLess:
        Op = "<"; break;
    case CondCode::SignedLessEqual:
        Op = "<="; break;
    case CondCode::SignedGreater:
        Op = ">"; break;
    case CondCode::SignedGreaterEqual:
        Op = ">="; break;
    case CondCode::UnsignedBelow:
        Op = "<"; break;
    case CondCode::UnsignedBelowEqual:
        Op = "<="; break;
    case CondCode::UnsignedAbove:
        Op = ">"; break;
    case CondCode::UnsignedAboveEqual:
        Op = ">="; break;
    case CondCode::Sign:
        return Negated ? L + " >= 0" : L + " < 0";
    case CondCode::NotSign:
        return Negated ? L + " < 0" : L + " >= 0";
    case CondCode::Overflow:
        return Negated ? "!overflow" : "overflow";
    case CondCode::NotOverflow:
        return Negated ? "overflow" : "!overflow";
    case CondCode::Always:
        return Negated ? "false" : "true";
    case CondCode::Never:
        return Negated ? "true" : "false";
    }

    if (Negated) Op = Negate(Op);
    return L + " " + Op + " " + R;
}

QVector<CodeGenerator::ControlFlowNode> CodeGenerator::StructureControlFlow(const IrFunction& Func) {
    QVector<ControlFlowNode> Nodes;

    if (Func.Blocks.isEmpty()) return Nodes;

    QSet<int> Visited;
    QVector<int> WorkList;
    WorkList.append(0);

    while (!WorkList.isEmpty()) {
        int BlockIdx = WorkList.takeFirst();
        if (Visited.contains(BlockIdx)) continue;
        if (BlockIdx < 0 || BlockIdx >= Func.Blocks.size()) continue;
        Visited.insert(BlockIdx);

        const IrBasicBlock& Block = Func.Blocks[BlockIdx];

        if (!Block.Instructions.isEmpty()) {
            const IrInst& LastInst = Block.Instructions.last();

            if (LastInst.Op == IrOp::CondJump && Block.Successors.size() == 2) {
                int TrueBlock = Block.Successors[0];
                int FalseBlock = Block.Successors[1];

                IrOperand CmpLhs, CmpRhs;
                CondCode Cond = LastInst.Cond;

                for (int I = Block.Instructions.size() - 2; I >= 0; --I) {
                    if (Block.Instructions[I].Op == IrOp::Compare || Block.Instructions[I].Op == IrOp::Test) {
                        CmpLhs = Block.Instructions[I].Src1;
                        CmpRhs = Block.Instructions[I].Src2;
                        break;
                    }
                }

                bool TrueIsLoop = TrueBlock <= BlockIdx;
                bool FalseIsLoop = FalseBlock <= BlockIdx;

                if (TrueIsLoop || FalseIsLoop) {
                    ControlFlowNode WhileNode;
                    WhileNode.NodeType = ControlFlowNode::While;
                    WhileNode.BlockId = BlockIdx;
                    WhileNode.Cond = Cond;
                    WhileNode.Negated = FalseIsLoop;

                    int BodyBlock = FalseIsLoop ? FalseBlock : TrueBlock;
                    int ExitBlock = FalseIsLoop ? TrueBlock : FalseBlock;

                    ControlFlowNode BodyNode;
                    BodyNode.NodeType = ControlFlowNode::Sequence;
                    BodyNode.BlockId = BodyBlock;
                    WhileNode.Children.append(BodyNode);
                    Nodes.append(WhileNode);

                    if (!Visited.contains(ExitBlock)) WorkList.append(ExitBlock);
                    continue;
                }

                ControlFlowNode IfNode;
                IfNode.NodeType = ControlFlowNode::IfElse;
                IfNode.BlockId = BlockIdx;
                IfNode.Cond = Cond;
                IfNode.Negated = false;

                ControlFlowNode TrueChild;
                TrueChild.NodeType = ControlFlowNode::Sequence;
                TrueChild.BlockId = TrueBlock;
                IfNode.Children.append(TrueChild);

                ControlFlowNode FalseChild;
                FalseChild.NodeType = ControlFlowNode::Sequence;
                FalseChild.BlockId = FalseBlock;
                IfNode.ElseChildren.append(FalseChild);

                Nodes.append(IfNode);

                if (!Visited.contains(TrueBlock)) WorkList.append(TrueBlock);
                if (!Visited.contains(FalseBlock)) WorkList.append(FalseBlock);
                continue;
            }

            if (LastInst.Op == IrOp::Ret) {
                ControlFlowNode SeqNode;
                SeqNode.NodeType = ControlFlowNode::Sequence;
                SeqNode.BlockId = BlockIdx;
                Nodes.append(SeqNode);
                continue;
            }
        }

        ControlFlowNode SeqNode;
        SeqNode.NodeType = ControlFlowNode::Sequence;
        SeqNode.BlockId = BlockIdx;
        Nodes.append(SeqNode);

        for (int Succ : Block.Successors) {
            if (!Visited.contains(Succ)) WorkList.append(Succ);
        }
    }

    return Nodes;
}

QString CodeGenerator::RenderControlFlow(const QVector<ControlFlowNode>& Nodes, const IrFunction& Func, int Indent) {
    QString Result;

    for (const auto& Node : Nodes) {
        switch (Node.NodeType) {
        case ControlFlowNode::Sequence: {
            if (Node.BlockId >= 0 && Node.BlockId < Func.Blocks.size()) {
                Result += GenerateBlock(Func.Blocks[Node.BlockId], Indent);
            }
            if (!Node.Children.isEmpty()) {
                Result += RenderControlFlow(Node.Children, Func, Indent);
            }
            break;
        }
        case ControlFlowNode::IfElse: {
            IrOperand CmpLhs, CmpRhs;
            CondCode Cond = Node.Cond;

            if (Node.BlockId >= 0 && Node.BlockId < Func.Blocks.size()) {
                const auto& Block = Func.Blocks[Node.BlockId];
                for (int I = 0; I < Block.Instructions.size(); ++I) {
                    const auto& Inst = Block.Instructions[I];
                    if (Inst.Op == IrOp::Compare || Inst.Op == IrOp::Test) {
                        CmpLhs = Inst.Src1;
                        CmpRhs = Inst.Src2;
                    } else if (Inst.Op != IrOp::CondJump && Inst.Op != IrOp::Jump) {
                        QString Line = GenerateInst(Inst, Indent);
                        if (!Line.isEmpty()) Result += Line;
                    }
                }
            }

            QString CondStr = GenerateCondition(Cond, CmpLhs, CmpRhs, Node.Negated);
            Result += IndentStr(Indent) + "if (" + CondStr + ")\n";
            Result += IndentStr(Indent) + "{\n";
            Result += RenderControlFlow(Node.Children, Func, Indent + 1);
            Result += IndentStr(Indent) + "}\n";

            if (!Node.ElseChildren.isEmpty()) {
                Result += IndentStr(Indent) + "else\n";
                Result += IndentStr(Indent) + "{\n";
                Result += RenderControlFlow(Node.ElseChildren, Func, Indent + 1);
                Result += IndentStr(Indent) + "}\n";
            }
            break;
        }
        case ControlFlowNode::While: {
            IrOperand CmpLhs, CmpRhs;
            CondCode Cond = Node.Cond;

            if (Node.BlockId >= 0 && Node.BlockId < Func.Blocks.size()) {
                const auto& Block = Func.Blocks[Node.BlockId];
                for (const auto& Inst : Block.Instructions) {
                    if (Inst.Op == IrOp::Compare || Inst.Op == IrOp::Test) {
                        CmpLhs = Inst.Src1;
                        CmpRhs = Inst.Src2;
                    }
                }
            }

            QString CondStr = GenerateCondition(Cond, CmpLhs, CmpRhs, Node.Negated);
            Result += IndentStr(Indent) + "while (" + CondStr + ")\n";
            Result += IndentStr(Indent) + "{\n";
            Result += RenderControlFlow(Node.Children, Func, Indent + 1);
            Result += IndentStr(Indent) + "}\n";
            break;
        }
        case ControlFlowNode::DoWhile: {
            Result += IndentStr(Indent) + "do\n";
            Result += IndentStr(Indent) + "{\n";
            Result += RenderControlFlow(Node.Children, Func, Indent + 1);
            Result += IndentStr(Indent) + "} while (...);\n";
            break;
        }
        case ControlFlowNode::Return: {
            if (Node.BlockId >= 0 && Node.BlockId < Func.Blocks.size()) {
                Result += GenerateBlock(Func.Blocks[Node.BlockId], Indent);
            }
            break;
        }
        case ControlFlowNode::Goto: {
            Result += IndentStr(Indent) + "goto " + FormatHex(Node.TargetAddr) + ";\n";
            break;
        }
        case ControlFlowNode::Break: {
            Result += IndentStr(Indent) + "break;\n";
            break;
        }
        case ControlFlowNode::Continue: {
            Result += IndentStr(Indent) + "continue;\n";
            break;
        }
        case ControlFlowNode::Switch:
            break;
        }
    }

    return Result;
}

QString CodeGenerator::IndentStr(int Level) {
    return QString(Level * IndentWidth, ' ');
}

QString CodeGenerator::FormatHex(int64_t Val) {
    if (Val >= -9 && Val <= 9) return QString::number(Val);
    if (Val < 0) return QString("-0x%1").arg(-Val, 0, 16);
    return QString("0x%1").arg(Val, 0, 16);
}

QString CodeGenerator::DumpIr(const IrFunction& Func) {
    QString Result;
    Result += "; Function: " + Func.Name + "\n";
    Result += "; Entry: " + FormatHex(Func.EntryAddr) + "\n";
    Result += "; Stack frame: " + QString::number(Func.StackFrameSize) + " bytes\n";
    Result += "; Frame pointer: " + (Func.UsesFramePointer ? QString("yes") : QString("no")) + "\n\n";

    auto OpStr = [](IrOp Op) -> QString {
        switch (Op) {
        case IrOp::Add: return "add";
        case IrOp::Sub: return "sub";
        case IrOp::Mul: return "mul";
        case IrOp::Div: return "div";
        case IrOp::Mod: return "mod";
        case IrOp::And: return "and";
        case IrOp::Or: return "or";
        case IrOp::Xor: return "xor";
        case IrOp::Shl: return "shl";
        case IrOp::Shr: return "shr";
        case IrOp::Sar: return "sar";
        case IrOp::Not: return "not";
        case IrOp::Neg: return "neg";
        case IrOp::Mov: return "mov";
        case IrOp::Load: return "load";
        case IrOp::Store: return "store";
        case IrOp::Call: return "call";
        case IrOp::Ret: return "ret";
        case IrOp::Jump: return "jmp";
        case IrOp::CondJump: return "cjmp";
        case IrOp::Compare: return "cmp";
        case IrOp::Test: return "test";
        case IrOp::Nop: return "nop";
        case IrOp::Phi: return "phi";
        case IrOp::Cast: return "cast";
        case IrOp::SignExtend: return "sext";
        case IrOp::ZeroExtend: return "zext";
        case IrOp::AddressOf: return "lea";
        case IrOp::Deref: return "deref";
        case IrOp::StackAlloc: return "alloca";
        case IrOp::Unknown: return "???";
        }
        return "???";
    };

    for (const auto& Block : Func.Blocks) {
        Result += QString("BB%1").arg(Block.Id);
        if (Block.IsEntry) Result += " [entry]";
        if (Block.IsExit) Result += " [exit]";
        Result += ":\n";

        for (const auto& Inst : Block.Instructions) {
            Result += "  " + OpStr(Inst.Op);
            if (Inst.Dest.IsValid()) Result += " " + GenerateOperand(Inst.Dest);
            if (Inst.Src1.IsValid()) Result += ", " + GenerateOperand(Inst.Src1);
            if (Inst.Src2.IsValid()) Result += ", " + GenerateOperand(Inst.Src2);
            if (Inst.Op == IrOp::Call && Inst.CallTarget != 0) {
                Result += " ; target=" + FormatHex(Inst.CallTarget);
            }
            Result += "\n";
        }

        if (!Block.Successors.isEmpty()) {
            Result += "  -> ";
            for (int I = 0; I < Block.Successors.size(); ++I) {
                if (I > 0) Result += ", ";
                Result += QString("BB%1").arg(Block.Successors[I]);
            }
            Result += "\n";
        }
        Result += "\n";
    }

    return Result;
}

}
