#pragma once

#include "DecompTypes.h"
#include <QSet>

namespace Fidra::Decomp {

class Optimizer {
public:
    Optimizer();

    IrFunction Optimize(const IrFunction& Func);
    // Register parameters of a freshly lifted function (argument registers
    // read before being written), as RunParameterRecovery counts them.
    static int RegisterParameterCount(const IrFunction& Func);

    void SetPassEnabled(const QString& PassName, bool Enabled);
    bool IsPassEnabled(const QString& PassName) const;
    QStringList GetPassNames() const;
    int GetPassCount() const;

private:
    void RunDeadCodeElimination(IrFunction& Func);
    void RunCopyPropagation(IrFunction& Func);
    void RunConstantFolding(IrFunction& Func);
    void RunStackVariableRecovery(IrFunction& Func);
    void RunExpressionSimplification(IrFunction& Func);
    void RunConditionRecovery(IrFunction& Func);
    void RunPrologueEpilogueCleanup(IrFunction& Func);
    void RunConstantPropagation(IrFunction& Func);
    void RunTypeRecovery(IrFunction& Func);
    void RunParameterRecovery(IrFunction& Func);

    bool OperandMatches(const IrOperand& A, const IrOperand& B);

    QMap<QString, bool> EnabledPasses;
};

}
