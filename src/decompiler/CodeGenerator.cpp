#include "CodeGenerator.h"
#include "../analysis/TypeLibrary.h"

#include <QElapsedTimer>
#include <QStringList>
#include <QHash>
#include <utility>
#include <algorithm>

namespace Fidra::Decomp {

// True when Expr has a binary operator outside parentheses, i.e. it must be
// wrapped before being used as an operand.
static bool IsIdentifier(const QString& S) {
    if (S.isEmpty() || S[0].isDigit()) return false;
    for (QChar C : S) {
        if (!C.isLetterOrNumber() && C != '_' && C != '.') return false;
    }
    return true;
}

static bool NeedsParens(const QString& Expr) {
    int Depth = 0;
    for (QChar C : Expr) {
        if (C == '(') ++Depth;
        else if (C == ')') --Depth;
        else if (C == ' ' && Depth == 0) return true;
    }
    return false;
}


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

DecompOutput CodeGenerator::Generate(const IrFunction& InFunc, const AnalysisDatabase* InDb) {
    QElapsedTimer Timer;
    Timer.start();

    // Debug info names stack slots. rsp-relative slot X lies at CFA + X -
    // delta - 8 (delta = prologue rsp displacement, 8 = return address);
    // rbp-relative slot Y at CFA + Y + FramePointerCfa (-16 after push rbp;
    // mov rbp, rsp).
    IrFunction Func = InFunc;
    if (!Func.DebugLocals.isEmpty()) {
        QSet<QString> Used;
        for (auto It = Func.StackVars.begin(); It != Func.StackVars.end(); ++It) {
            StackVariable& Var = It.value();
            int64_t Cfa = 0;
            if (Var.SpRelative) {
                if (Func.PrologueRspDelta < 0) continue;
                Cfa = Var.Offset - Func.PrologueRspDelta - 8;
            } else if (Func.FramePointerCfa != IrFunction::UnknownFrame) {
                Cfa = Var.Offset + Func.FramePointerCfa;
            } else {
                if (!Func.UsesFramePointer) continue;
                Cfa = Var.Offset - 16;
            }
            auto Dbg = Func.DebugLocals.constFind(Cfa);
            if (Dbg == Func.DebugLocals.constEnd() || Used.contains(Dbg->first)) continue;
            Used.insert(Dbg->first);
            Var.Name = Dbg->first;
            Var.CType = Dbg->second;
        }
    }

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
    if (Func.Proto) {
        // Source prototype from debug info; the register each parameter
        // arrives in is noted since the body still names registers.
        const FuncPrototype& P = *Func.Proto;
        QStringList Parts;
        for (int I = 0; I < P.Params.size(); ++I) {
            const FuncParam& Prm = P.Params[I];
            QString Decl = Prm.Type + " " + Prm.Name;
            if (I < Func.Parameters.size() && Func.Parameters[I].IsValid())
                Decl += " /* " + GenerateOperand(Func.Parameters[I]) + " */";
            Parts << Decl;
        }
        if (P.Variadic) Parts << "...";
        const QString Ret = P.ReturnType + " ";
        return (P.NoReturn ? "noreturn " : "") + Ret + Func.Name + "(" + (Parts.isEmpty() ? "void" : Parts.join(", ")) + ")";
    }
    QString Sig = IrTypeToString(Func.ReturnType) + " " + Func.Name + "(";
    for (int I = 0; I < Func.Parameters.size(); ++I) {
        if (I > 0) Sig += ", ";
        const auto& P = Func.Parameters[I];
        Sig += IrTypeToString(P.Type);
        if (!P.Name.isEmpty()) {
            Sig += " " + P.Name;
        } else if (P.IsReg() || P.IsStack()) {
            // Same spelling the body uses for this location.
            Sig += " " + GenerateOperand(P);
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
        if (!Var.SpRelative && Var.Offset >= 16) continue;
        // A parameter's spill slot is already declared by the signature.
        if (Func.Proto && std::any_of(Func.Proto->Params.begin(), Func.Proto->Params.end(),
                                      [&](const FuncParam& P) { return P.Name == Var.Name; })) continue;
        if (!Var.CType.isEmpty()) {
            // "char[256]" declares as "char buf[256]".
            const int Bracket = Var.CType.indexOf('[');
            const QString Decl = Bracket > 0 ? Var.CType.left(Bracket).trimmed() + " " + Var.Name + Var.CType.mid(Bracket)
                                             : Var.CType + " " + Var.Name;
            Result += IndentStr(1) + Decl + ";\n";
            continue;
        }
        Result += IndentStr(1) + IrTypeToString(Var.Type) + " " + Var.Name + ";\n";
    }
    if (!Result.isEmpty()) Result += "\n";
    return Result;
}

QString CodeGenerator::GenerateFunction(const IrFunction& Func) {
    QString Result;
    Result += GenerateSignature(Func) + "\n{\n";
    Result += GenerateLocals(Func);

    ComputeInlining(Func);
    Result += RenderControlFlow(StructureControlFlow(Func), Func, 1);
    InlineExpr.clear();
    InlinableDefs.clear();

    Result += "}\n";
    return Result;
}

QString CodeGenerator::GenerateBlock(const IrBasicBlock& Block, int Indent) {
    QString Result;

    if (ShowAddresses && Block.StartAddr != 0) {
        Result += IndentStr(Indent) + "/* " + FormatHex(Block.StartAddr) + " */\n";
    }

    for (int I = 0; I < Block.Instructions.size(); ++I) {
        const IrInst& Inst = Block.Instructions[I];
        if (InlinableDefs.contains(InlineKey(Block.Id, I))) {
            InlineExpr[Inst.Dest.TempId] = GenerateExpr(Inst);
            continue;
        }
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

    auto Assign = [&]() {
        return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + GenerateExpr(Inst) + ";\n";
    };

    switch (Inst.Op) {
    case IrOp::Mov:
        if (!Inst.Dest.IsValid()) return "";
        return Assign();
    case IrOp::Add: case IrOp::Sub: case IrOp::Mul: case IrOp::Div: case IrOp::Mod:
    case IrOp::And: case IrOp::Or: case IrOp::Xor: case IrOp::Shl: case IrOp::Shr: case IrOp::Sar:
    case IrOp::Not: case IrOp::Neg: case IrOp::Load: case IrOp::Cast: case IrOp::SignExtend:
    case IrOp::ZeroExtend: case IrOp::AddressOf: case IrOp::Deref:
        if (!Inst.Dest.IsValid()) return "";
        return Assign();
    case IrOp::Store:
        return IndentStr(Indent) + Prefix + MemoryRef(Inst.Dest, Inst.Src1.Type != IrType::Unknown ? Inst.Src1.Type : Inst.Dest.Type) +
               " = " + GenerateOperand(Inst.Src1) + ";\n";
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

        // Calls bind tighter than unary * and casts: wrap any non-identifier callee.
        if (Inst.CallTarget == 0 && Inst.CallName.isEmpty() && !IsIdentifier(CallStr)) CallStr = "(" + CallStr + ")";
        const QString Args = GenerateCallArgs(Inst);
        if (Inst.Dest.IsValid() && Inst.Dest.Type != IrType::Void) {
            return IndentStr(Indent) + Prefix + GenerateOperand(Inst.Dest) + " = " + CallStr + "(" + Args + ");\n";
        }
        return IndentStr(Indent) + Prefix + CallStr + "(" + Args + ");\n";
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
    case IrOp::Unknown:
        if (Inst.AsmText.isEmpty()) return "";
        return IndentStr(Indent) + Prefix + "__asm(\"" + Inst.AsmText + "\");\n";
    case IrOp::Nop:
    case IrOp::Phi:
    case IrOp::StackAlloc:
        return "";
    }
    return "";
}

// Argument list of a call. Pointer-to-char parameters whose value is a
// constant address of a string print as a string literal.
QString CodeGenerator::GenerateCallArgs(const IrInst& Inst) {
    QStringList Parts;
    for (int K = 0; K < Inst.CallArgs.size(); ++K) {
        const IrOperand& A = Inst.CallArgs[K];
        if (Inst.CallProto && K < Inst.CallProto->Params.size()) {
            const QString& T = Inst.CallProto->Params[K].Type;
            const bool Wide = T.contains("wchar_t") || T.contains("WCHAR") || T.contains("WSTR") || T.contains("OLECHAR");
            const bool Narrow = (T.contains("char") && T.contains('*')) || T == "LPCSTR" || T == "LPSTR";
            if (Wide || Narrow) {
                const QString Lit = StringLiteralAt(A, Wide);
                if (!Lit.isEmpty()) { Parts << Lit; continue; }
            }
        }
        if (!A.IsValid()) { Parts << "/* xmm */"; continue; }  // float argument: register not modeled
        // An inlined expression needs no parentheses of its own here.
        auto Inl = A.IsTemp() ? InlineExpr.constFind(A.TempId) : InlineExpr.constEnd();
        Parts << (Inl != InlineExpr.constEnd() ? Inl.value() : GenerateOperand(A));
    }
    return Parts.join(", ");
}

QString CodeGenerator::StringLiteralAt(const IrOperand& Op, bool Wide) const {
    if (!Db) return {};
    IrOperand V = Op;
    for (int Depth = 0; Depth < 4 && V.IsTemp(); ++Depth) {
        auto It = TempDefs.constFind(V.TempId);
        if (It == TempDefs.constEnd() || (It->Op != IrOp::Mov && It->Op != IrOp::AddressOf)) return {};
        V = It->Src1;
    }
    Address Addr = 0;
    if (V.IsImm()) Addr = static_cast<Address>(V.ImmValue);
    else if (V.OpKind == IrOperand::Global) Addr = V.GlobalAddr;
    if (Addr == 0) return {};

    const QByteArray Raw = Db->ReadBytes(Addr, 512);
    QString Text;
    bool Terminated = false;
    const int Step = Wide ? 2 : 1;
    for (int I = 0; I + Step <= Raw.size(); I += Step) {
        uint32_t C = static_cast<uint8_t>(Raw[I]);
        if (Wide) C |= static_cast<uint32_t>(static_cast<uint8_t>(Raw[I + 1])) << 8;
        if (C == 0) { Terminated = true; break; }
        if (C == '\n') Text += "\\n";
        else if (C == '\r') Text += "\\r";
        else if (C == '\t') Text += "\\t";
        else if (C == '"') Text += "\\\"";
        else if (C == '\\') Text += "\\\\";
        else if (C >= 0x20 && C < 0x7f) Text += QChar(C);
        else if (C >= 0x80 && !Wide) Text += QString("\\x%1").arg(C, 2, 16, QChar('0'));
        else if (C >= 0xa0 && Wide) Text += QChar(C);
        else return {};  // control bytes: not text
    }
    if (!Terminated) return {};
    return (Wide ? "L\"" : "\"") + Text + "\"";
}

// Right-hand side of an assignment-style instruction.
QString CodeGenerator::GenerateExpr(const IrInst& Inst) {
    auto Bin = [&](const char* Op) {
        // "x + -8" reads better as "x - 8".
        if (Inst.Src2.IsImm() && Inst.Src2.ImmValue < 0 && (Inst.Op == IrOp::Add || Inst.Op == IrOp::Sub)) {
            const char* Flipped = Inst.Op == IrOp::Add ? " - " : " + ";
            return GenerateOperand(Inst.Src1) + Flipped + FormatHex(-Inst.Src2.ImmValue);
        }
        return GenerateOperand(Inst.Src1) + " " + Op + " " + GenerateOperand(Inst.Src2);
    };
    switch (Inst.Op) {
    case IrOp::Mov: return GenerateOperand(Inst.Src1);
    case IrOp::Add: return Bin("+");
    case IrOp::Sub: return Bin("-");
    case IrOp::Mul: return Bin("*");
    case IrOp::Div: return Bin("/");
    case IrOp::Mod: return Bin("%");
    case IrOp::And: return Bin("&");
    case IrOp::Or: return Bin("|");
    case IrOp::Xor: return Bin("^");
    case IrOp::Shl: return Bin("<<");
    case IrOp::Shr: return Bin(">>");
    case IrOp::Sar: return "(int64_t)" + GenerateOperand(Inst.Src1) + " >> " + GenerateOperand(Inst.Src2);
    case IrOp::Not: return "~" + GenerateOperand(Inst.Src1);
    case IrOp::Neg: return "-" + GenerateOperand(Inst.Src1);
    case IrOp::Load: return MemoryRef(Inst.Src1, Inst.Dest.Type != IrType::Unknown ? Inst.Dest.Type : Inst.Src1.Type);
    case IrOp::Cast: return "(" + IrTypeToString(Inst.Dest.Type) + ")" + GenerateOperand(Inst.Src1);
    case IrOp::SignExtend: return "(int64_t)(" + IrTypeToString(Inst.Src1.Type) + ")" + GenerateOperand(Inst.Src1);
    case IrOp::ZeroExtend: return "(uint64_t)" + GenerateOperand(Inst.Src1);
    case IrOp::AddressOf:
        if (Inst.Src1.OpKind == IrOperand::Global) {
            QString Name = Db ? Db->GetName(Inst.Src1.GlobalAddr) : QString();
            if (!Name.isEmpty()) return "&" + Name;
            // Address of a string the analysis found: show the literal.
            if (Db && Db->HasString(Inst.Src1.GlobalAddr)) {
                const QString Lit = StringLiteralAt(Inst.Src1, Db->GetString(Inst.Src1.GlobalAddr).IsWide);
                if (!Lit.isEmpty()) return Lit;
            }
            return FormatHex(Inst.Src1.GlobalAddr);
        }
        if (Inst.Src1.IsStack()) {
            // Arrays decay to a pointer: buf, not &buf.
            if (CurrentFunc) {
                auto It = CurrentFunc->StackVars.constFind(StackKey(Inst.Src1));
                if (It != CurrentFunc->StackVars.constEnd() && It.value().CType.endsWith(']')) return It.value().Name;
            }
            return "&" + GenerateOperand(Inst.Src1);
        }
        return GenerateOperand(Inst.Src1);
    case IrOp::Deref: return "*" + GenerateOperand(Inst.Src1);
    default: return "???";
    }
}

// Lvalue/rvalue text for a memory access through Addr.
QString CodeGenerator::MemoryRef(const IrOperand& Addr, IrType Type) {
    if (Addr.IsStack()) return GenerateOperand(Addr);
    if (Addr.OpKind == IrOperand::Global && Addr.Name.isEmpty() && Db) {
        QString Name = Db->GetName(Addr.GlobalAddr);
        if (!Name.isEmpty()) return Name;
    }
    QString Ptr = GenerateOperand(Addr);
    if (NeedsParens(Ptr)) Ptr = "(" + Ptr + ")";
    QString TypeName = Type == IrType::Unknown ? QString("int64_t") : IrTypeToString(Type);
    return "*(" + TypeName + "*)" + Ptr;
}

quint64 CodeGenerator::InlineKey(int BlockId, int InstIdx) {
    return (static_cast<quint64>(static_cast<quint32>(BlockId)) << 32) | static_cast<quint32>(InstIdx);
}

// A temp defined by a pure op and used exactly once later in the same block
// is printed inline at its use, as long as nothing in between can change the
// values it reads.
void CodeGenerator::ComputeInlining(const IrFunction& Func) {
    InlineExpr.clear();
    InlinableDefs.clear();
    TempDefs.clear();

    QHash<int, int> UseCount;
    auto CountUse = [&](const IrOperand& Op) { if (Op.IsTemp()) UseCount[Op.TempId]++; };
    for (const auto& Block : Func.Blocks) {
        for (const auto& Inst : Block.Instructions) {
            CountUse(Inst.Src1);
            CountUse(Inst.Src2);
            if (Inst.Op == IrOp::Store || Inst.Op == IrOp::Jump) CountUse(Inst.Dest);
            for (const IrOperand& A : Inst.CallArgs) CountUse(A);
            if (Inst.Dest.IsTemp() && Inst.Op != IrOp::Store && Inst.Op != IrOp::Jump) TempDefs.insert(Inst.Dest.TempId, Inst);
        }
    }

    auto UsesTemp = [](const IrInst& Inst, int T) {
        auto Is = [T](const IrOperand& Op) { return Op.IsTemp() && Op.TempId == T; };
        if (Is(Inst.Src1) || Is(Inst.Src2) || ((Inst.Op == IrOp::Store || Inst.Op == IrOp::Jump) && Is(Inst.Dest))) return true;
        for (const IrOperand& A : Inst.CallArgs)
            if (Is(A)) return true;
        return false;
    };

    for (const auto& Block : Func.Blocks) {
        const auto& Insts = Block.Instructions;
        for (int I = 0; I < Insts.size(); ++I) {
            const IrInst& Def = Insts[I];
            if (!Def.Dest.IsTemp() || UseCount.value(Def.Dest.TempId) != 1) continue;
            switch (Def.Op) {
            case IrOp::Mov: case IrOp::Add: case IrOp::Sub: case IrOp::Mul: case IrOp::And: case IrOp::Or:
            case IrOp::Xor: case IrOp::Shl: case IrOp::Shr: case IrOp::Sar: case IrOp::Not: case IrOp::Neg:
            case IrOp::Load: case IrOp::Cast: case IrOp::SignExtend: case IrOp::ZeroExtend: case IrOp::AddressOf:
                break;
            default:
                continue;
            }

            QVector<IrOperand> Reads{Def.Src1, Def.Src2};
            const bool ReadsMemory = Def.Op == IrOp::Load;
            bool Safe = true;
            int UseIdx = -1;
            for (int J = I + 1; J < Insts.size() && Safe; ++J) {
                const IrInst& Mid = Insts[J];
                if (UseIdx < 0 && UsesTemp(Mid, Def.Dest.TempId)) {
                    UseIdx = J;
                    // A cmp/test operand is printed at the block's conditional
                    // jump: the expression must stay valid until then.
                    if (Mid.Op != IrOp::Compare && Mid.Op != IrOp::Test) break;
                    continue;
                }
                if (Mid.Op == IrOp::CondJump) break;
                if (Mid.Op == IrOp::Call || Mid.Op == IrOp::Unknown) { Safe = false; break; }
                if (ReadsMemory && Mid.Op == IrOp::Store) { Safe = false; break; }
                bool DefinesDest = Mid.Op != IrOp::Store && Mid.Op != IrOp::Jump && Mid.Op != IrOp::CondJump &&
                                   Mid.Op != IrOp::Compare && Mid.Op != IrOp::Test;
                if (DefinesDest && Mid.Dest.IsValid()) {
                    for (const IrOperand& R : Reads) {
                        if (!R.IsValid()) continue;
                        if (R == Mid.Dest) { Safe = false; break; }
                        // Stack slots depend on rsp/rbp.
                        if (R.IsStack() && Mid.Dest.IsReg() && (Mid.Dest.RegId == 4 || Mid.Dest.RegId == 5)) { Safe = false; break; }
                    }
                    if (Mid.Dest.IsReg() && (Mid.Dest.RegId == 4 || Mid.Dest.RegId == 5) && ReadsMemory &&
                        Def.Src1.IsStack()) { Safe = false; break; }
                }
            }
            if (Safe && UseIdx > I) InlinableDefs.insert(InlineKey(Block.Id, I));
        }
    }
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
    case IrOperand::Temp: {
        auto It = InlineExpr.constFind(Op.TempId);
        if (It != InlineExpr.constEnd()) {
            const QString& E = It.value();
            return NeedsParens(E) ? "(" + E + ")" : E;
        }
        return QString("T%1").arg(Op.TempId);
    }
    case IrOperand::Stack: {
        if (CurrentFunc) {
            auto It = CurrentFunc->StackVars.constFind(StackKey(Op));
            if (It != CurrentFunc->StackVars.constEnd()) return It.value().Name;
        }
        return StackVarName(Op.StackOffset, Op.SpRelative);
    }
    case IrOperand::Global: {
        if (!Op.Name.isEmpty()) return Op.Name;
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

// Functions above this many blocks skip region structuring and are emitted
// as straight-line blocks with labels/gotos (still exact, just less pretty).
static constexpr int MaxStructuredBlocks = 4000;
// Nesting limit for region recursion; deeper regions are split off via goto.
static constexpr int MaxStructureDepth = 96;

static QString FormatCondition(CondCode Cond, const QString& L, const QString& R, bool Negated) {
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
    case CondCode::UnsignedBelow:
        Op = "<"; break;
    case CondCode::SignedLessEqual:
    case CondCode::UnsignedBelowEqual:
        Op = "<="; break;
    case CondCode::SignedGreater:
    case CondCode::UnsignedAbove:
        Op = ">"; break;
    case CondCode::SignedGreaterEqual:
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
    case CondCode::Parity:
        return Negated ? "!parity(" + L + ")" : "parity(" + L + ")";
    case CondCode::NotParity:
        return Negated ? "parity(" + L + ")" : "!parity(" + L + ")";
    case CondCode::Always:
        return Negated ? "false" : "true";
    case CondCode::Never:
        return Negated ? "true" : "false";
    }

    if (Negated) Op = Negate(Op);
    return L + " " + Op + " " + R;
}

QString CodeGenerator::GenerateCondition(CondCode Cond, const IrOperand& Lhs, const IrOperand& Rhs, bool Negated) {
    return FormatCondition(Cond, GenerateOperand(Lhs), GenerateOperand(Rhs), Negated);
}

QString CodeGenerator::BlockLabel(int BlockId) const {
    if (CurrentFunc && BlockId >= 0 && BlockId < CurrentFunc->Blocks.size())
        return QString("label_%1").arg(CurrentFunc->Blocks[BlockId].StartAddr, 0, 16);
    return QString("label_bb%1").arg(BlockId);
}

void CodeGenerator::ComputeCfgInfo(const IrFunction& Func) {
    const int N = Func.Blocks.size();
    Succs.assign(N, {});
    PostIdom.assign(N, -1);
    LoopFollow.assign(N, -1);
    IsLoopHeader.assign(N, 0);
    Emitted.assign(N, 0);
    LabelRendered.assign(N, 0);
    GotoTargets.clear();
    PendingBlocks.clear();
    LoopStack.clear();

    EntryBlock = 0;
    for (int I = 0; I < N; ++I) {
        if (Func.Blocks[I].IsEntry) { EntryBlock = I; break; }
    }

    QVector<QVector<int>> Preds(N);
    for (int I = 0; I < N; ++I) {
        for (int S : Func.Blocks[I].Successors) {
            if (S < 0 || S >= N || Succs[I].contains(S)) continue;
            Succs[I].append(S);
            Preds[S].append(I);
        }
    }

    if (N == 0 || N > MaxStructuredBlocks) return;

    // Forward DFS from entry: reverse post-order + back edges (loop headers).
    QVector<int> Rpo(N, -1);
    QVector<char> State(N, 0);
    QVector<QVector<int>> Latches(N);
    {
        QVector<int> PostOrder;
        QVector<QPair<int, int>> Stack;
        Stack.append({EntryBlock, 0});
        State[EntryBlock] = 1;
        while (!Stack.isEmpty()) {
            auto& Top = Stack.last();
            int Node = Top.first;
            if (Top.second < Succs[Node].size()) {
                int S = Succs[Node][Top.second++];
                if (State[S] == 0) {
                    State[S] = 1;
                    Stack.append({S, 0});
                } else if (State[S] == 1) {
                    IsLoopHeader[S] = 1;
                    Latches[S].append(Node);
                }
            } else {
                State[Node] = 2;
                PostOrder.append(Node);
                Stack.removeLast();
            }
        }
        for (int I = 0; I < PostOrder.size(); ++I)
            Rpo[PostOrder[I]] = PostOrder.size() - 1 - I;
    }

    // Natural loop bodies -> pick the loop follow (where `break` goes).
    QVector<char> InBody(N, 0);
    for (int H = 0; H < N; ++H) {
        if (!IsLoopHeader[H]) continue;
        QVector<int> Body{H};
        InBody[H] = 1;
        QVector<int> Work;
        for (int L : Latches[H]) {
            if (!InBody[L]) { InBody[L] = 1; Body.append(L); Work.append(L); }
        }
        while (!Work.isEmpty()) {
            int X = Work.takeLast();
            for (int P : Preds[X]) {
                if (!InBody[P] && Rpo[P] >= 0) { InBody[P] = 1; Body.append(P); Work.append(P); }
            }
        }
        int Best = -1;
        for (int S : Succs[H]) {
            if (!InBody[S] && (Best < 0 || Rpo[S] < Rpo[Best])) Best = S;
        }
        if (Best < 0) {
            for (int B : Body) {
                for (int S : Succs[B]) {
                    if (!InBody[S] && Rpo[S] >= 0 && (Best < 0 || Rpo[S] < Rpo[Best])) Best = S;
                }
            }
        }
        LoopFollow[H] = Best;
        for (int B : Body) InBody[B] = 0;
    }

    // Immediate post-dominators (Cooper/Harvey/Kennedy on the reverse CFG,
    // with a virtual exit node N joined to every block without successors).
    const int Exit = N;
    QVector<int> PoNum(N + 1, -1);
    QVector<int> Order;
    {
        QVector<char> Seen(N + 1, 0);
        QVector<int> ExitSuccs;
        for (int I = 0; I < N; ++I)
            if (Succs[I].isEmpty()) ExitSuccs.append(I);
        auto RevSuccs = [&](int X) -> const QVector<int>& { return X == Exit ? ExitSuccs : Preds[X]; };
        QVector<QPair<int, int>> Stack;
        Stack.append({Exit, 0});
        Seen[Exit] = 1;
        int Counter = 0;
        while (!Stack.isEmpty()) {
            auto& Top = Stack.last();
            const QVector<int>& Next = RevSuccs(Top.first);
            if (Top.second < Next.size()) {
                int S = Next[Top.second++];
                if (!Seen[S]) { Seen[S] = 1; Stack.append({S, 0}); }
            } else {
                PoNum[Top.first] = Counter++;
                Order.append(Top.first);
                Stack.removeLast();
            }
        }
    }
    QVector<int> Idom(N + 1, -1);
    Idom[Exit] = Exit;
    auto Intersect = [&](int A, int B) {
        while (A != B) {
            while (PoNum[A] < PoNum[B]) A = Idom[A];
            while (PoNum[B] < PoNum[A]) B = Idom[B];
        }
        return A;
    };
    bool Changed = true;
    while (Changed) {
        Changed = false;
        for (int I = Order.size() - 1; I >= 0; --I) {
            int B = Order[I];
            if (B == Exit) continue;
            int NewIdom = -1;
            auto Consider = [&](int P) {
                if (Idom[P] == -1) return;
                NewIdom = (NewIdom == -1) ? P : Intersect(P, NewIdom);
            };
            if (Succs[B].isEmpty()) Consider(Exit);
            for (int S : Succs[B]) Consider(S);
            if (NewIdom != -1 && Idom[B] != NewIdom) { Idom[B] = NewIdom; Changed = true; }
        }
    }
    for (int I = 0; I < N; ++I)
        PostIdom[I] = (Idom[I] == Exit) ? -1 : Idom[I];
}

void CodeGenerator::SplitCondSuccessors(const IrBasicBlock& Block, int& TrueBlock, int& FalseBlock) const {
    const QVector<int>& S = Succs[Block.Id];
    TrueBlock = S[0];
    FalseBlock = S[1];
    const IrInst& Last = Block.Instructions.last();
    if (Last.Dest.OpKind == IrOperand::Label && CurrentFunc) {
        if (CurrentFunc->Blocks[S[1]].StartAddr == Last.Dest.GlobalAddr) {
            TrueBlock = S[1];
            FalseBlock = S[0];
        }
    }
}

bool CodeGenerator::FindCondition(const IrBasicBlock& Block, IrOperand& Lhs, IrOperand& Rhs, bool& IsTest) const {
    for (int I = Block.Instructions.size() - 2; I >= 0; --I) {
        const IrInst& Inst = Block.Instructions[I];
        switch (Inst.Op) {
        case IrOp::Compare:
            Lhs = Inst.Src1; Rhs = Inst.Src2; IsTest = false;
            return true;
        case IrOp::Test:
            Lhs = Inst.Src1; Rhs = Inst.Src2; IsTest = true;
            return true;
        case IrOp::Add: case IrOp::Sub: case IrOp::And: case IrOp::Or: case IrOp::Xor:
        case IrOp::Shl: case IrOp::Shr: case IrOp::Sar: case IrOp::Neg: case IrOp::Mul:
            // Flags come from the arithmetic result itself.
            if (!Inst.Dest.IsValid()) break;
            Lhs = Inst.Dest; Rhs = Inst.Dest; IsTest = true;
            return true;
        case IrOp::Call:
        case IrOp::Unknown:
            return false;
        default:
            break;
        }
    }
    return false;
}

QString CodeGenerator::RenderCondition(int BlockId, bool Negated) {
    const IrBasicBlock& Block = CurrentFunc->Blocks[BlockId];
    CondCode Cond = Block.Instructions.last().Cond;
    IrOperand Lhs, Rhs;
    bool IsTest = false;
    if (!FindCondition(Block, Lhs, Rhs, IsTest)) {
        QString Flags = QString("flags_%1").arg(Block.Instructions.last().OriginalAddr, 0, 16);
        return FormatCondition(Cond, Flags, "0", Negated);
    }
    if (!IsTest) return GenerateCondition(Cond, Lhs, Rhs, Negated);
    // test a, b sets flags from (a & b); compare that against zero.
    QString L = (Lhs == Rhs) ? GenerateOperand(Lhs)
                             : "(" + GenerateOperand(Lhs) + " & " + GenerateOperand(Rhs) + ")";
    return FormatCondition(Cond, L, "0", Negated);
}

// True when control never falls off the end of Nodes.
bool CodeGenerator::EndsInTransfer(const QVector<ControlFlowNode>& Nodes) const {
    if (Nodes.isEmpty()) return false;
    const ControlFlowNode& Last = Nodes.last();
    switch (Last.NodeType) {
    case ControlFlowNode::Goto: case ControlFlowNode::Break: case ControlFlowNode::Continue:
    case ControlFlowNode::TailCall:
        return true;
    case ControlFlowNode::Block: {
        const auto& Insts = CurrentFunc->Blocks[Last.BlockId].Instructions;
        return !Insts.isEmpty() && Insts.last().Op == IrOp::Ret;
    }
    case ControlFlowNode::IfElse:
        return !Last.ElseChildren.isEmpty() && EndsInTransfer(Last.Children) && EndsInTransfer(Last.ElseChildren);
    default:
        return false;
    }
}

void CodeGenerator::AppendGoto(QVector<ControlFlowNode>& Nodes, int Target) {
    ControlFlowNode G;
    G.NodeType = ControlFlowNode::Goto;
    G.TargetBlock = Target;
    Nodes.append(G);
    GotoTargets.insert(Target);
    if (!Emitted[Target]) PendingBlocks.append(Target);
}

QVector<CodeGenerator::ControlFlowNode> CodeGenerator::StructureRegion(int Entry, int Stop, int Depth, bool EnteringLoop) {
    QVector<ControlFlowNode> Nodes;
    int Cur = Entry;
    bool First = true;

    while (Cur != -1) {
        if (Cur == Stop) break;
        bool AtLoopEntry = First && EnteringLoop;
        First = false;

        if (!AtLoopEntry && !LoopStack.isEmpty()) {
            const LoopContext& Inner = LoopStack.last();
            if (Cur == Inner.Header) {
                ControlFlowNode C; C.NodeType = ControlFlowNode::Continue; Nodes.append(C);
                break;
            }
            if (Cur == Inner.Exit) {
                ControlFlowNode B; B.NodeType = ControlFlowNode::Break; Nodes.append(B);
                break;
            }
            bool OuterTarget = false;
            for (int I = 0; I < LoopStack.size() - 1; ++I) {
                if (Cur == LoopStack[I].Header || Cur == LoopStack[I].Exit) { OuterTarget = true; break; }
            }
            if (OuterTarget) { AppendGoto(Nodes, Cur); break; }
        }

        if (Emitted[Cur] || Depth > MaxStructureDepth) {
            AppendGoto(Nodes, Cur);
            break;
        }

        if (IsLoopHeader[Cur] && !AtLoopEntry) {
            ControlFlowNode L;
            L.NodeType = ControlFlowNode::Loop;
            L.BlockId = Cur;
            LoopStack.append({Cur, LoopFollow[Cur]});
            L.Children = StructureRegion(Cur, -1, Depth + 1, true);
            LoopStack.removeLast();
            Nodes.append(L);
            Cur = LoopFollow[Cur];
            continue;
        }

        Emitted[Cur] = 1;
        ControlFlowNode BlockNode;
        BlockNode.NodeType = ControlFlowNode::Block;
        BlockNode.BlockId = Cur;
        Nodes.append(BlockNode);

        const IrBasicBlock& Block = CurrentFunc->Blocks[Cur];
        const QVector<int>& S = Succs[Cur];
        const IrInst* Last = Block.Instructions.isEmpty() ? nullptr : &Block.Instructions.last();

        if (Last && Last->Op == IrOp::Ret) break;

        if (S.size() == 2 && Last && Last->Op == IrOp::CondJump) {
            int TrueBlock, FalseBlock;
            SplitCondSuccessors(Block, TrueBlock, FalseBlock);
            int Merge = PostIdom[Cur];

            ControlFlowNode If;
            If.NodeType = ControlFlowNode::IfElse;
            If.BlockId = Cur;
            If.Children = StructureRegion(TrueBlock, Merge, Depth + 1, false);
            If.ElseChildren = StructureRegion(FalseBlock, Merge, Depth + 1, false);
            if (If.Children.isEmpty() && !If.ElseChildren.isEmpty()) {
                std::swap(If.Children, If.ElseChildren);
                If.Negated = true;
            }
            if (!If.Children.isEmpty()) Nodes.append(If);
            Cur = Merge;
            continue;
        }

        if (S.size() == 1) {
            Cur = S[0];
            continue;
        }

        if (S.isEmpty()) {
            if (Last && Last->Op == IrOp::Jump) {
                ControlFlowNode T;
                T.NodeType = ControlFlowNode::TailCall;
                T.BlockId = Cur;
                if (Last->Dest.OpKind == IrOperand::Label) T.TargetAddr = Last->Dest.GlobalAddr;
                Nodes.append(T);
            }
            break;
        }

        // Jump table: a computed goto to labelled case regions, each ending in
        // its own transfer or a goto to the switch's merge point.
        ControlFlowNode Sw;
        Sw.NodeType = ControlFlowNode::Switch;
        Sw.BlockId = Cur;
        const int Merge = PostIdom[Cur];
        QVector<int> Cases = S;
        std::sort(Cases.begin(), Cases.end(), [&](int A, int B) {
            return CurrentFunc->Blocks[A].StartAddr < CurrentFunc->Blocks[B].StartAddr;
        });
        for (int Target : Cases) GotoTargets.insert(Target);
        if (Merge >= 0) GotoTargets.insert(Merge);
        for (int Target : Cases) {
            if (Target == Merge || Emitted[Target]) continue;
            QVector<ControlFlowNode> Body = StructureRegion(Target, Merge, Depth + 1, false);
            const bool FallsThrough = !EndsInTransfer(Body);
            Sw.Children += Body;
            if (FallsThrough && Merge >= 0) AppendGoto(Sw.Children, Merge);
        }
        Nodes.append(Sw);
        Cur = Merge;
        continue;
    }

    return Nodes;
}

QVector<CodeGenerator::ControlFlowNode> CodeGenerator::StructureFlat(const IrFunction& Func) {
    QVector<ControlFlowNode> Nodes;
    const int N = Func.Blocks.size();
    for (int I = 0; I < N; ++I) Emitted[I] = 1;

    for (int I = 0; I < N; ++I) {
        ControlFlowNode BlockNode;
        BlockNode.NodeType = ControlFlowNode::Block;
        BlockNode.BlockId = I;
        Nodes.append(BlockNode);

        const IrBasicBlock& Block = Func.Blocks[I];
        const QVector<int>& S = Succs[I];
        const IrInst* Last = Block.Instructions.isEmpty() ? nullptr : &Block.Instructions.last();
        if (Last && Last->Op == IrOp::Ret) continue;

        if (S.size() == 2 && Last && Last->Op == IrOp::CondJump) {
            int TrueBlock, FalseBlock;
            SplitCondSuccessors(Block, TrueBlock, FalseBlock);
            ControlFlowNode If;
            If.NodeType = ControlFlowNode::IfElse;
            If.BlockId = I;
            AppendGoto(If.Children, TrueBlock);
            Nodes.append(If);
            if (FalseBlock != I + 1) AppendGoto(Nodes, FalseBlock);
        } else if (S.size() == 1) {
            if (S[0] != I + 1) AppendGoto(Nodes, S[0]);
        } else if (S.isEmpty()) {
            if (Last && Last->Op == IrOp::Jump) {
                ControlFlowNode T;
                T.NodeType = ControlFlowNode::TailCall;
                T.BlockId = I;
                if (Last->Dest.OpKind == IrOperand::Label) T.TargetAddr = Last->Dest.GlobalAddr;
                Nodes.append(T);
            }
        } else {
            ControlFlowNode Sw;
            Sw.NodeType = ControlFlowNode::Switch;
            Sw.BlockId = I;
            for (int Target : S) GotoTargets.insert(Target);
            Nodes.append(Sw);
        }
    }
    return Nodes;
}

QVector<CodeGenerator::ControlFlowNode> CodeGenerator::StructureControlFlow(const IrFunction& Func) {
    ComputeCfgInfo(Func);
    if (Func.Blocks.isEmpty()) return {};
    if (Func.Blocks.size() > MaxStructuredBlocks) return StructureFlat(Func);

    QVector<ControlFlowNode> Nodes = StructureRegion(EntryBlock, -1, 0, false);
    // Regions split off by goto (depth limit, irreducible flow) go after the
    // main body, each behind its label.
    while (!PendingBlocks.isEmpty()) {
        int B = PendingBlocks.takeFirst();
        if (Emitted[B]) continue;
        Nodes += StructureRegion(B, -1, 0, false);
    }
    return Nodes;
}

QString CodeGenerator::RenderControlFlow(const QVector<ControlFlowNode>& Nodes, const IrFunction& Func, int Indent) {
    QString Result;

    auto RenderLabel = [&](int BlockId) {
        if (BlockId < 0 || !GotoTargets.contains(BlockId) || LabelRendered[BlockId]) return;
        LabelRendered[BlockId] = 1;
        Result += IndentStr(qMax(0, Indent - 1)) + BlockLabel(BlockId) + ":\n";
    };

    for (const auto& Node : Nodes) {
        switch (Node.NodeType) {
        case ControlFlowNode::Block:
            RenderLabel(Node.BlockId);
            Result += GenerateBlock(Func.Blocks[Node.BlockId], Indent);
            break;
        case ControlFlowNode::IfElse: {
            Result += IndentStr(Indent) + "if (" + RenderCondition(Node.BlockId, Node.Negated) + ")\n";
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
        case ControlFlowNode::Loop: {
            RenderLabel(Node.BlockId);
            QVector<ControlFlowNode> Body = Node.Children;
            QString Header = "while (true)";
            // header == "if (c) break;" (or "if (c) {...} else break;") with no
            // other statements turns into a plain while loop.
            if (Body.size() >= 2 && Body[0].NodeType == ControlFlowNode::Block &&
                Body[0].BlockId == Node.BlockId && Body[1].NodeType == ControlFlowNode::IfElse &&
                Body[1].BlockId == Node.BlockId &&
                GenerateBlock(Func.Blocks[Node.BlockId], 0).isEmpty()) {
                const ControlFlowNode& If = Body[1];
                auto IsBreak = [](const QVector<ControlFlowNode>& V) {
                    return V.size() == 1 && V[0].NodeType == ControlFlowNode::Break;
                };
                if (IsBreak(If.Children) && If.ElseChildren.isEmpty()) {
                    Header = "while (" + RenderCondition(Node.BlockId, !If.Negated) + ")";
                    Body = Body.mid(2);
                } else if (IsBreak(If.ElseChildren)) {
                    Header = "while (" + RenderCondition(Node.BlockId, If.Negated) + ")";
                    QVector<ControlFlowNode> NewBody = If.Children;
                    NewBody += Body.mid(2);
                    Body = NewBody;
                }
            }
            if (!Body.isEmpty() && Body.last().NodeType == ControlFlowNode::Continue) Body.removeLast();
            Result += IndentStr(Indent) + Header + "\n";
            Result += IndentStr(Indent) + "{\n";
            Result += RenderControlFlow(Body, Func, Indent + 1);
            Result += IndentStr(Indent) + "}\n";
            break;
        }
        case ControlFlowNode::Goto:
            Result += IndentStr(Indent) + "goto " + BlockLabel(Node.TargetBlock) + ";\n";
            break;
        case ControlFlowNode::Break:
            Result += IndentStr(Indent) + "break;\n";
            break;
        case ControlFlowNode::Continue:
            Result += IndentStr(Indent) + "continue;\n";
            break;
        case ControlFlowNode::TailCall: {
            QString Target;
            if (Node.TargetAddr != 0) {
                QString Name = Db ? Db->GetName(Node.TargetAddr) : QString();
                Target = Name.isEmpty() ? QString("sub_%1").arg(Node.TargetAddr, 0, 16) : Name;
            } else {
                QString Ptr = GenerateOperand(Func.Blocks[Node.BlockId].Instructions.last().Dest);
                Target = "((int64_t (*)())" + (NeedsParens(Ptr) ? "(" + Ptr + ")" : Ptr) + ")";
            }
            Result += IndentStr(Indent) + "return " + Target + "(" + GenerateCallArgs(Func.Blocks[Node.BlockId].Instructions.last()) + ");\n";
            break;
        }
        case ControlFlowNode::Switch: {
            const IrInst& Last = Func.Blocks[Node.BlockId].Instructions.last();
            QStringList Labels;
            for (int S : Succs[Node.BlockId]) Labels.append(BlockLabel(S));
            Result += IndentStr(Indent) + "goto *(" + GenerateOperand(Last.Dest) + "); // jump table: " + Labels.join(", ") + "\n";
            Result += RenderControlFlow(Node.Children, Func, Indent);
            break;
        }
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
            if (Inst.Op == IrOp::Call && !Inst.CallArgs.isEmpty()) {
                QStringList Args;
                for (const IrOperand& A : Inst.CallArgs) Args << GenerateOperand(A);
                Result += " (" + Args.join(", ") + ")";
            }
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
