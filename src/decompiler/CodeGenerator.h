#pragma once

#include "DecompTypes.h"
#include "../analysis/AnalysisDatabase.h"
#include <QTextStream>
#include <QSet>
#include <QHash>

namespace Fidra::Decomp {

class CodeGenerator {
public:
    CodeGenerator();

    DecompOutput Generate(const IrFunction& Func, const AnalysisDatabase* Db = nullptr);

    void SetIndentWidth(int Width);
    void SetShowAddresses(bool Show);
    void SetShowTypes(bool Show);

private:
    struct ControlFlowNode {
        // Block: emit the statements of BlockId.
        // IfElse: condition taken from BlockId's compare/test + CondJump.
        // Loop: endless loop whose header is BlockId; exits via Break/Return/Goto.
        // Goto / TailCall / Switch: explicit transfers to TargetBlock / TargetAddr.
        enum Type { Block, IfElse, Loop, Goto, Break, Continue, TailCall, Switch };
        Type NodeType = Block;
        int BlockId = -1;
        int TargetBlock = -1;
        bool Negated = false;
        QVector<ControlFlowNode> Children;
        QVector<ControlFlowNode> ElseChildren;
        Address TargetAddr = 0;
    };

    struct LoopContext {
        int Header = -1;
        int Exit = -1;
    };

    QString GenerateFunction(const IrFunction& Func);
    QString GenerateBlock(const IrBasicBlock& Block, int Indent);
    QString GenerateInst(const IrInst& Inst, int Indent);
    QString GenerateOperand(const IrOperand& Op);
    QString GenerateExpr(const IrInst& Inst);
    QString MemoryRef(const IrOperand& Addr, IrType Type);
    void ComputeInlining(const IrFunction& Func);
    static quint64 InlineKey(int BlockId, int InstIdx);
    QString GenerateCondition(CondCode Cond, const IrOperand& Lhs, const IrOperand& Rhs, bool Negated = false);
    QString GenerateSignature(const IrFunction& Func);
    QString GenerateLocals(const IrFunction& Func);
    QString IndentStr(int Level);
    QString FormatHex(int64_t Val);
    QString DumpIr(const IrFunction& Func);
    QString GenerateCallArgs(const IrInst& Inst);
    QString StringLiteralAt(const IrOperand& Op, bool Wide) const;

    QVector<ControlFlowNode> StructureControlFlow(const IrFunction& Func);
    QVector<ControlFlowNode> StructureRegion(int Entry, int Stop, int Depth, bool EnteringLoop);
    QVector<ControlFlowNode> StructureFlat(const IrFunction& Func);
    void ComputeCfgInfo(const IrFunction& Func);
    void AppendGoto(QVector<ControlFlowNode>& Nodes, int Target);
    bool EndsInTransfer(const QVector<ControlFlowNode>& Nodes) const;
    void SplitCondSuccessors(const IrBasicBlock& Block, int& TrueBlock, int& FalseBlock) const;
    bool FindCondition(const IrBasicBlock& Block, IrOperand& Lhs, IrOperand& Rhs, bool& IsTest) const;
    QString RenderControlFlow(const QVector<ControlFlowNode>& Nodes, const IrFunction& Func, int Indent);
    QString RenderCondition(int BlockId, bool Negated);
    QString BlockLabel(int BlockId) const;

    // Per-function CFG state used while structuring.
    QVector<QVector<int>> Succs;
    QVector<int> PostIdom;
    QVector<int> LoopFollow;
    QVector<char> IsLoopHeader;
    QVector<char> Emitted;
    QVector<char> LabelRendered;
    QSet<int> GotoTargets;
    QVector<int> PendingBlocks;
    QVector<LoopContext> LoopStack;
    int EntryBlock = 0;

    // Temps printed inline at their single use instead of as statements.
    QSet<quint64> InlinableDefs;
    QHash<int, QString> InlineExpr;
    // Defining instruction of every temp (temp ids are unique per function).
    QHash<int, IrInst> TempDefs;

    int IndentWidth;
    bool ShowAddresses;
    bool ShowTypes;
    const AnalysisDatabase* Db;
    const IrFunction* CurrentFunc;
};

}
