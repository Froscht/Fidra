#pragma once

#include "DecompTypes.h"
#include "../analysis/AnalysisTypes.h"
#include "../analysis/AnalysisDatabase.h"
#include <capstone/capstone.h>

namespace Fidra::Decomp {

class Lifter {
public:
    Lifter();
    ~Lifter();

    IrFunction LiftFunction(const AnalyzedFunction& Func, const AnalysisDatabase* Db);

private:
    int AllocTemp(IrType Type = IrType::Int64);
    IrOperand LiftRegister(x86_reg Reg);
    IrType RegType(x86_reg Reg);
    int MapCsReg(x86_reg Reg);
    IrType MemAccessType(uint8_t Size);
    IrOperand LiftMemOperand(const cs_x86_op& Op, IrBasicBlock& Block);
    void LiftInstruction(cs_insn* Insn, const cs_detail* Detail, IrBasicBlock& Block);
    CondCode MapCondCode(unsigned int CsId);
    void BuildBlockGraph(IrFunction& Func, const AnalyzedFunction& SrcFunc);

    int NextTemp;
    bool Is64Bit;
    const AnalysisDatabase* CurrentDb;
    csh CsHandle;
    bool CsValid;
};

}
