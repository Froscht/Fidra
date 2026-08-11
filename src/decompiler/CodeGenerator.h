#pragma once

#include "DecompTypes.h"
#include "../analysis/AnalysisDatabase.h"
#include <QTextStream>

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
        enum Type { Sequence, IfElse, While, DoWhile, Switch, Goto, Return, Break, Continue };
        Type NodeType = Sequence;
        int BlockId = -1;
        CondCode Cond = CondCode::Always;
        bool Negated = false;
        QVector<ControlFlowNode> Children;
        QVector<ControlFlowNode> ElseChildren;
        Address TargetAddr = 0;
    };

    QString GenerateFunction(const IrFunction& Func);
    QString GenerateBlock(const IrBasicBlock& Block, int Indent);
    QString GenerateInst(const IrInst& Inst, int Indent);
    QString GenerateOperand(const IrOperand& Op);
    QString GenerateCondition(CondCode Cond, const IrOperand& Lhs, const IrOperand& Rhs, bool Negated = false);
    QString GenerateSignature(const IrFunction& Func);
    QString GenerateLocals(const IrFunction& Func);
    QString IndentStr(int Level);
    QString FormatHex(int64_t Val);
    QString DumpIr(const IrFunction& Func);

    QVector<ControlFlowNode> StructureControlFlow(const IrFunction& Func);
    QString RenderControlFlow(const QVector<ControlFlowNode>& Nodes, const IrFunction& Func, int Indent);

    int IndentWidth;
    bool ShowAddresses;
    bool ShowTypes;
    const AnalysisDatabase* Db;
    const IrFunction* CurrentFunc;
};

}
