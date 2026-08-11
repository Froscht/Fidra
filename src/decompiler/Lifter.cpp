#include "Lifter.h"
#include <QSet>
#include <cstring>

namespace Fidra::Decomp {

Lifter::Lifter()
    : NextTemp(0)
    , Is64Bit(true)
    , CurrentDb(nullptr)
    , CsHandle(0)
    , CsValid(false)
{
}

Lifter::~Lifter() {
    if (CsValid) {
        cs_close(&CsHandle);
    }
}

int Lifter::AllocTemp(IrType Type) {
    Q_UNUSED(Type);
    return NextTemp++;
}

int Lifter::MapCsReg(x86_reg Reg) {
    switch (Reg) {
        case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: return 0;
        case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: return 1;
        case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: return 2;
        case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: return 3;
        case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 4;
        case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 5;
        case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 6;
        case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 7;
        case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return 8;
        case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return 9;
        case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
        case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
        case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
        case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
        case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
        case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
        default: return -1;
    }
}

IrType Lifter::RegType(x86_reg Reg) {
    switch (Reg) {
        case X86_REG_RAX: case X86_REG_RCX: case X86_REG_RDX: case X86_REG_RBX:
        case X86_REG_RSP: case X86_REG_RBP: case X86_REG_RSI: case X86_REG_RDI:
        case X86_REG_R8: case X86_REG_R9: case X86_REG_R10: case X86_REG_R11:
        case X86_REG_R12: case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
            return IrType::Int64;
        case X86_REG_EAX: case X86_REG_ECX: case X86_REG_EDX: case X86_REG_EBX:
        case X86_REG_ESP: case X86_REG_EBP: case X86_REG_ESI: case X86_REG_EDI:
        case X86_REG_R8D: case X86_REG_R9D: case X86_REG_R10D: case X86_REG_R11D:
        case X86_REG_R12D: case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
            return IrType::Int32;
        case X86_REG_AX: case X86_REG_CX: case X86_REG_DX: case X86_REG_BX:
        case X86_REG_SP: case X86_REG_BP: case X86_REG_SI: case X86_REG_DI:
        case X86_REG_R8W: case X86_REG_R9W: case X86_REG_R10W: case X86_REG_R11W:
        case X86_REG_R12W: case X86_REG_R13W: case X86_REG_R14W: case X86_REG_R15W:
            return IrType::Int16;
        case X86_REG_AL: case X86_REG_CL: case X86_REG_DL: case X86_REG_BL:
        case X86_REG_AH: case X86_REG_CH: case X86_REG_DH: case X86_REG_BH:
        case X86_REG_SPL: case X86_REG_BPL: case X86_REG_SIL: case X86_REG_DIL:
        case X86_REG_R8B: case X86_REG_R9B: case X86_REG_R10B: case X86_REG_R11B:
        case X86_REG_R12B: case X86_REG_R13B: case X86_REG_R14B: case X86_REG_R15B:
            return IrType::Int8;
        default:
            return IrType::Int64;
    }
}

IrOperand Lifter::LiftRegister(x86_reg Reg) {
    int Id = MapCsReg(Reg);
    if (Id < 0) {
        return IrOperand::MakeReg(Reg, RegType(Reg));
    }
    return IrOperand::MakeReg(Id, RegType(Reg));
}

IrType Lifter::MemAccessType(uint8_t Size) {
    return IrTypeFromSize(Size);
}

IrOperand Lifter::LiftMemOperand(const cs_x86_op& Op, IrBasicBlock& Block) {
    const x86_op_mem& Mem = Op.mem;
    int BaseReg = MapCsReg(static_cast<x86_reg>(Mem.base));
    int IndexReg = MapCsReg(static_cast<x86_reg>(Mem.index));
    int64_t Disp = Mem.disp;
    int Scale = Mem.scale;

    if (BaseReg == 5 && IndexReg < 0 && Disp != 0) {
        IrType AccessType = MemAccessType(Op.size);
        return IrOperand::MakeStack(static_cast<int>(Disp), AccessType);
    }

    if (BaseReg == 4 && IndexReg < 0 && Disp != 0) {
        IrType AccessType = MemAccessType(Op.size);
        return IrOperand::MakeStack(static_cast<int>(Disp), AccessType);
    }

    IrOperand Result = IrOperand::MakeInvalid();
    IrType AccessType = MemAccessType(Op.size);

    if (BaseReg < 0 && IndexReg < 0) {
        Result = IrOperand::MakeGlobal(static_cast<Address>(Disp), AccessType);
        return Result;
    }

    int AddrTemp = AllocTemp(IrType::Pointer);
    IrOperand AddrOp = IrOperand::MakeTemp(AddrTemp, IrType::Pointer);

    if (BaseReg >= 0 && IndexReg < 0) {
        if (Disp != 0) {
            IrInst AddInst;
            AddInst.Op = IrOp::Add;
            AddInst.Dest = AddrOp;
            AddInst.Src1 = IrOperand::MakeReg(BaseReg, IrType::Int64);
            AddInst.Src2 = IrOperand::MakeImm(Disp);
            Block.Instructions.append(AddInst);
        } else {
            IrInst MovInst;
            MovInst.Op = IrOp::Mov;
            MovInst.Dest = AddrOp;
            MovInst.Src1 = IrOperand::MakeReg(BaseReg, IrType::Int64);
            Block.Instructions.append(MovInst);
        }
    } else if (BaseReg >= 0 && IndexReg >= 0) {
        int ScaledTemp = AllocTemp(IrType::Pointer);
        IrOperand ScaledOp = IrOperand::MakeTemp(ScaledTemp, IrType::Pointer);

        if (Scale > 1) {
            IrInst MulInst;
            MulInst.Op = IrOp::Mul;
            MulInst.Dest = ScaledOp;
            MulInst.Src1 = IrOperand::MakeReg(IndexReg, IrType::Int64);
            MulInst.Src2 = IrOperand::MakeImm(Scale);
            Block.Instructions.append(MulInst);
        } else {
            IrInst MovInst;
            MovInst.Op = IrOp::Mov;
            MovInst.Dest = ScaledOp;
            MovInst.Src1 = IrOperand::MakeReg(IndexReg, IrType::Int64);
            Block.Instructions.append(MovInst);
        }

        IrInst AddInst;
        AddInst.Op = IrOp::Add;
        AddInst.Dest = AddrOp;
        AddInst.Src1 = IrOperand::MakeReg(BaseReg, IrType::Int64);
        AddInst.Src2 = ScaledOp;
        Block.Instructions.append(AddInst);

        if (Disp != 0) {
            int FinalTemp = AllocTemp(IrType::Pointer);
            IrOperand FinalOp = IrOperand::MakeTemp(FinalTemp, IrType::Pointer);
            IrInst DispInst;
            DispInst.Op = IrOp::Add;
            DispInst.Dest = FinalOp;
            DispInst.Src1 = AddrOp;
            DispInst.Src2 = IrOperand::MakeImm(Disp);
            Block.Instructions.append(DispInst);
            AddrOp = FinalOp;
        }
    } else if (IndexReg >= 0) {
        if (Scale > 1) {
            IrInst MulInst;
            MulInst.Op = IrOp::Mul;
            MulInst.Dest = AddrOp;
            MulInst.Src1 = IrOperand::MakeReg(IndexReg, IrType::Int64);
            MulInst.Src2 = IrOperand::MakeImm(Scale);
            Block.Instructions.append(MulInst);
        } else {
            IrInst MovInst;
            MovInst.Op = IrOp::Mov;
            MovInst.Dest = AddrOp;
            MovInst.Src1 = IrOperand::MakeReg(IndexReg, IrType::Int64);
            Block.Instructions.append(MovInst);
        }
        if (Disp != 0) {
            int DispTemp = AllocTemp(IrType::Pointer);
            IrOperand DispOp = IrOperand::MakeTemp(DispTemp, IrType::Pointer);
            IrInst DispInst;
            DispInst.Op = IrOp::Add;
            DispInst.Dest = DispOp;
            DispInst.Src1 = AddrOp;
            DispInst.Src2 = IrOperand::MakeImm(Disp);
            Block.Instructions.append(DispInst);
            AddrOp = DispOp;
        }
    }

    AddrOp.Type = AccessType;
    return AddrOp;
}

CondCode Lifter::MapCondCode(unsigned int CsId) {
    switch (CsId) {
        case X86_INS_JE: return CondCode::Equal;
        case X86_INS_JNE: return CondCode::NotEqual;
        case X86_INS_JL: return CondCode::SignedLess;
        case X86_INS_JLE: return CondCode::SignedLessEqual;
        case X86_INS_JG: return CondCode::SignedGreater;
        case X86_INS_JGE: return CondCode::SignedGreaterEqual;
        case X86_INS_JB: return CondCode::UnsignedBelow;
        case X86_INS_JBE: return CondCode::UnsignedBelowEqual;
        case X86_INS_JA: return CondCode::UnsignedAbove;
        case X86_INS_JAE: return CondCode::UnsignedAboveEqual;
        case X86_INS_JS: return CondCode::Sign;
        case X86_INS_JNS: return CondCode::NotSign;
        case X86_INS_JO: return CondCode::Overflow;
        case X86_INS_JNO: return CondCode::NotOverflow;
        default: return CondCode::Always;
    }
}

void Lifter::LiftInstruction(cs_insn* Insn, const cs_detail* Detail, IrBasicBlock& Block) {
    const cs_x86& X86 = Detail->x86;
    unsigned int Id = Insn->id;

    auto GetOp = [&](int Idx) -> const cs_x86_op& {
        return X86.operands[Idx];
    };

    auto LiftOp = [&](int Idx) -> IrOperand {
        if (Idx >= X86.op_count) return IrOperand::MakeInvalid();
        const cs_x86_op& Op = GetOp(Idx);
        switch (Op.type) {
            case X86_OP_REG:
                return LiftRegister(Op.reg);
            case X86_OP_IMM:
                return IrOperand::MakeImm(Op.imm, MemAccessType(Op.size));
            case X86_OP_MEM: {
                IrOperand MemOp = LiftMemOperand(Op, Block);
                return MemOp;
            }
            default:
                return IrOperand::MakeInvalid();
        }
    };

    auto IsMemOp = [&](int Idx) -> bool {
        if (Idx >= X86.op_count) return false;
        return GetOp(Idx).type == X86_OP_MEM;
    };

    auto EmitBinOp = [&](IrOp IrOpCode) {
        if (X86.op_count < 2) return;
        IrInst Inst;
        Inst.Op = IrOpCode;
        Inst.OriginalAddr = Insn->address;
        Inst.BasicBlockId = Block.Id;

        if (IsMemOp(0)) {
            IrOperand AddrOp = LiftOp(0);
            int LoadTemp = AllocTemp(AddrOp.Type);
            IrOperand LoadResult = IrOperand::MakeTemp(LoadTemp, AddrOp.Type);
            IrInst LoadInst;
            LoadInst.Op = IrOp::Load;
            LoadInst.Dest = LoadResult;
            LoadInst.Src1 = AddrOp;
            LoadInst.OriginalAddr = Insn->address;
            Block.Instructions.append(LoadInst);

            int ResultTemp = AllocTemp(AddrOp.Type);
            IrOperand ResultOp = IrOperand::MakeTemp(ResultTemp, AddrOp.Type);
            Inst.Dest = ResultOp;
            Inst.Src1 = LoadResult;
            Inst.Src2 = LiftOp(1);
            Block.Instructions.append(Inst);

            IrInst StoreInst;
            StoreInst.Op = IrOp::Store;
            StoreInst.Dest = AddrOp;
            StoreInst.Src1 = ResultOp;
            StoreInst.OriginalAddr = Insn->address;
            Block.Instructions.append(StoreInst);
        } else {
            Inst.Dest = LiftOp(0);
            if (IsMemOp(1)) {
                IrOperand AddrOp = LiftOp(1);
                int LoadTemp = AllocTemp(AddrOp.Type);
                IrOperand LoadResult = IrOperand::MakeTemp(LoadTemp, AddrOp.Type);
                IrInst LoadInst;
                LoadInst.Op = IrOp::Load;
                LoadInst.Dest = LoadResult;
                LoadInst.Src1 = AddrOp;
                LoadInst.OriginalAddr = Insn->address;
                Block.Instructions.append(LoadInst);
                Inst.Src1 = Inst.Dest;
                Inst.Src2 = LoadResult;
            } else {
                Inst.Src1 = Inst.Dest;
                Inst.Src2 = LiftOp(1);
            }
            Block.Instructions.append(Inst);
        }
    };

    switch (Id) {
        case X86_INS_NOP:
        case X86_INS_ENDBR64:
        case X86_INS_ENDBR32:
        case X86_INS_INT3: {
            IrInst Inst;
            Inst.Op = IrOp::Nop;
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_MOV:
        case X86_INS_MOVABS:
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
        case X86_INS_CMOVA: case X86_INS_CMOVAE: case X86_INS_CMOVB: case X86_INS_CMOVBE:
        case X86_INS_CMOVE: case X86_INS_CMOVNE: case X86_INS_CMOVG: case X86_INS_CMOVGE:
        case X86_INS_CMOVL: case X86_INS_CMOVLE: case X86_INS_CMOVS: case X86_INS_CMOVNS: {
            if (X86.op_count < 2) break;
            IrInst Inst;
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;

            if (Id == X86_INS_MOVZX) Inst.Op = IrOp::ZeroExtend;
            else if (Id == X86_INS_MOVSX || Id == X86_INS_MOVSXD) Inst.Op = IrOp::SignExtend;
            else Inst.Op = IrOp::Mov;

            IrOperand Src = LiftOp(1);
            if (IsMemOp(1)) {
                int LoadTemp = AllocTemp(Src.Type);
                IrOperand LoadResult = IrOperand::MakeTemp(LoadTemp, Src.Type);
                IrInst LoadInst;
                LoadInst.Op = IrOp::Load;
                LoadInst.Dest = LoadResult;
                LoadInst.Src1 = Src;
                LoadInst.OriginalAddr = Insn->address;
                Block.Instructions.append(LoadInst);
                Src = LoadResult;
            }

            if (IsMemOp(0)) {
                IrOperand AddrOp = LiftOp(0);
                IrInst StoreInst;
                StoreInst.Op = IrOp::Store;
                StoreInst.Dest = AddrOp;
                StoreInst.Src1 = Src;
                StoreInst.OriginalAddr = Insn->address;
                Block.Instructions.append(StoreInst);
            } else {
                Inst.Dest = LiftOp(0);
                Inst.Src1 = Src;
                Block.Instructions.append(Inst);
            }
            break;
        }

        case X86_INS_LEA: {
            if (X86.op_count < 2) break;
            IrInst Inst;
            Inst.Op = IrOp::AddressOf;
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            Inst.Dest = LiftOp(0);

            const cs_x86_op& MemSrc = GetOp(1);
            if (MemSrc.type == X86_OP_MEM) {
                const x86_op_mem& Mem = MemSrc.mem;
                int BaseReg = MapCsReg(static_cast<x86_reg>(Mem.base));
                int IndexReg = MapCsReg(static_cast<x86_reg>(Mem.index));

                if (BaseReg == X86_REG_INVALID && IndexReg == X86_REG_INVALID) {
                    Inst.Op = IrOp::Mov;
                    Inst.Src1 = IrOperand::MakeImm(Mem.disp);
                } else if (BaseReg >= 0 && IndexReg < 0 && Mem.disp != 0) {
                    Inst.Op = IrOp::Add;
                    Inst.Src1 = IrOperand::MakeReg(BaseReg, IrType::Int64);
                    Inst.Src2 = IrOperand::MakeImm(Mem.disp);
                } else if (BaseReg >= 0 && IndexReg < 0) {
                    Inst.Op = IrOp::Mov;
                    Inst.Src1 = IrOperand::MakeReg(BaseReg, IrType::Int64);
                } else {
                    IrOperand AddrOp = LiftMemOperand(MemSrc, Block);
                    Inst.Op = IrOp::Mov;
                    Inst.Src1 = AddrOp;
                }
            }
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_ADD: EmitBinOp(IrOp::Add); break;
        case X86_INS_SUB: EmitBinOp(IrOp::Sub); break;
        case X86_INS_AND: EmitBinOp(IrOp::And); break;
        case X86_INS_OR:  EmitBinOp(IrOp::Or); break;

        case X86_INS_XOR: {
            if (X86.op_count >= 2 && GetOp(0).type == X86_OP_REG && GetOp(1).type == X86_OP_REG &&
                GetOp(0).reg == GetOp(1).reg) {
                IrInst Inst;
                Inst.Op = IrOp::Mov;
                Inst.Dest = LiftOp(0);
                Inst.Src1 = IrOperand::MakeImm(0, Inst.Dest.Type);
                Inst.OriginalAddr = Insn->address;
                Inst.BasicBlockId = Block.Id;
                Block.Instructions.append(Inst);
            } else {
                EmitBinOp(IrOp::Xor);
            }
            break;
        }

        case X86_INS_SHL: case X86_INS_SAL: EmitBinOp(IrOp::Shl); break;
        case X86_INS_SHR: EmitBinOp(IrOp::Shr); break;
        case X86_INS_SAR: EmitBinOp(IrOp::Sar); break;

        case X86_INS_IMUL: {
            if (X86.op_count == 1) {
                IrInst Inst;
                Inst.Op = IrOp::Mul;
                Inst.Dest = IrOperand::MakeReg(0, IrType::Int64);
                Inst.Src1 = IrOperand::MakeReg(0, IrType::Int64);
                Inst.Src2 = LiftOp(0);
                Inst.OriginalAddr = Insn->address;
                Block.Instructions.append(Inst);
            } else if (X86.op_count == 2) {
                EmitBinOp(IrOp::Mul);
            } else if (X86.op_count == 3) {
                IrInst Inst;
                Inst.Op = IrOp::Mul;
                Inst.Dest = LiftOp(0);
                Inst.Src1 = LiftOp(1);
                Inst.Src2 = LiftOp(2);
                Inst.OriginalAddr = Insn->address;
                Block.Instructions.append(Inst);
            }
            break;
        }

        case X86_INS_IDIV:
        case X86_INS_DIV: {
            IrInst Inst;
            Inst.Op = IrOp::Div;
            Inst.Dest = IrOperand::MakeReg(0, IrType::Int64);
            Inst.Src1 = IrOperand::MakeReg(0, IrType::Int64);
            Inst.Src2 = LiftOp(0);
            Inst.OriginalAddr = Insn->address;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_NEG: {
            IrInst Inst;
            Inst.Op = IrOp::Neg;
            Inst.Dest = LiftOp(0);
            Inst.Src1 = Inst.Dest;
            Inst.OriginalAddr = Insn->address;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_NOT: {
            IrInst Inst;
            Inst.Op = IrOp::Not;
            Inst.Dest = LiftOp(0);
            Inst.Src1 = Inst.Dest;
            Inst.OriginalAddr = Insn->address;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_INC: {
            IrInst Inst;
            Inst.Op = IrOp::Add;
            Inst.Dest = LiftOp(0);
            Inst.Src1 = Inst.Dest;
            Inst.Src2 = IrOperand::MakeImm(1);
            Inst.OriginalAddr = Insn->address;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_DEC: {
            IrInst Inst;
            Inst.Op = IrOp::Sub;
            Inst.Dest = LiftOp(0);
            Inst.Src1 = Inst.Dest;
            Inst.Src2 = IrOperand::MakeImm(1);
            Inst.OriginalAddr = Insn->address;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_PUSH: {
            IrInst SubInst;
            SubInst.Op = IrOp::Sub;
            SubInst.Dest = IrOperand::MakeReg(4, IrType::Int64);
            SubInst.Src1 = IrOperand::MakeReg(4, IrType::Int64);
            SubInst.Src2 = IrOperand::MakeImm(Is64Bit ? 8 : 4);
            SubInst.OriginalAddr = Insn->address;
            Block.Instructions.append(SubInst);

            IrInst StoreInst;
            StoreInst.Op = IrOp::Store;
            StoreInst.Dest = IrOperand::MakeReg(4, IrType::Pointer);
            StoreInst.Src1 = LiftOp(0);
            StoreInst.OriginalAddr = Insn->address;
            Block.Instructions.append(StoreInst);
            break;
        }

        case X86_INS_POP: {
            IrInst LoadInst;
            LoadInst.Op = IrOp::Load;
            LoadInst.Dest = LiftOp(0);
            LoadInst.Src1 = IrOperand::MakeReg(4, IrType::Pointer);
            LoadInst.OriginalAddr = Insn->address;
            Block.Instructions.append(LoadInst);

            IrInst AddInst;
            AddInst.Op = IrOp::Add;
            AddInst.Dest = IrOperand::MakeReg(4, IrType::Int64);
            AddInst.Src1 = IrOperand::MakeReg(4, IrType::Int64);
            AddInst.Src2 = IrOperand::MakeImm(Is64Bit ? 8 : 4);
            AddInst.OriginalAddr = Insn->address;
            Block.Instructions.append(AddInst);
            break;
        }

        case X86_INS_CMP: {
            if (X86.op_count < 2) break;
            IrInst Inst;
            Inst.Op = IrOp::Compare;
            Inst.Src1 = LiftOp(0);
            Inst.Src2 = LiftOp(1);
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;

            if (IsMemOp(0)) {
                IrOperand AddrOp = Inst.Src1;
                int LoadTemp = AllocTemp(AddrOp.Type);
                IrOperand LoadResult = IrOperand::MakeTemp(LoadTemp, AddrOp.Type);
                IrInst LoadInst;
                LoadInst.Op = IrOp::Load;
                LoadInst.Dest = LoadResult;
                LoadInst.Src1 = AddrOp;
                Block.Instructions.append(LoadInst);
                Inst.Src1 = LoadResult;
            }
            if (IsMemOp(1)) {
                IrOperand AddrOp = Inst.Src2;
                int LoadTemp = AllocTemp(AddrOp.Type);
                IrOperand LoadResult = IrOperand::MakeTemp(LoadTemp, AddrOp.Type);
                IrInst LoadInst;
                LoadInst.Op = IrOp::Load;
                LoadInst.Dest = LoadResult;
                LoadInst.Src1 = AddrOp;
                Block.Instructions.append(LoadInst);
                Inst.Src2 = LoadResult;
            }
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_TEST: {
            if (X86.op_count < 2) break;
            IrInst Inst;
            Inst.Op = IrOp::Test;
            Inst.Src1 = LiftOp(0);
            Inst.Src2 = LiftOp(1);
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_CALL: {
            IrInst Inst;
            Inst.Op = IrOp::Call;
            Inst.Dest = IrOperand::MakeReg(0, IrType::Int64);
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;

            if (X86.op_count > 0 && GetOp(0).type == X86_OP_IMM) {
                Inst.CallTarget = static_cast<Address>(GetOp(0).imm);
                if (CurrentDb) {
                    QString FuncName = CurrentDb->GetName(Inst.CallTarget);
                    if (!FuncName.isEmpty()) {
                        Inst.CallName = FuncName;
                    }
                }
            } else {
                Inst.Src1 = LiftOp(0);
            }
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ: {
            IrInst Inst;
            Inst.Op = IrOp::Ret;
            Inst.Src1 = IrOperand::MakeReg(0, IrType::Int64);
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_JMP: {
            IrInst Inst;
            Inst.Op = IrOp::Jump;
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            if (X86.op_count > 0 && GetOp(0).type == X86_OP_IMM) {
                Inst.Dest = IrOperand::MakeLabel(static_cast<Address>(GetOp(0).imm));
            } else {
                Inst.Dest = LiftOp(0);
            }
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_JE: case X86_INS_JNE:
        case X86_INS_JL: case X86_INS_JLE: case X86_INS_JG: case X86_INS_JGE:
        case X86_INS_JB: case X86_INS_JBE: case X86_INS_JA: case X86_INS_JAE:
        case X86_INS_JS: case X86_INS_JNS: case X86_INS_JO: case X86_INS_JNO:
        case X86_INS_JCXZ: case X86_INS_JECXZ: case X86_INS_JRCXZ: case X86_INS_JP: case X86_INS_JNP: {
            IrInst Inst;
            Inst.Op = IrOp::CondJump;
            Inst.Cond = MapCondCode(Id);
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            if (X86.op_count > 0 && GetOp(0).type == X86_OP_IMM) {
                Inst.Dest = IrOperand::MakeLabel(static_cast<Address>(GetOp(0).imm));
            }
            Block.Instructions.append(Inst);
            break;
        }

        default: {
            IrInst Inst;
            Inst.Op = IrOp::Unknown;
            Inst.OriginalAddr = Insn->address;
            Inst.BasicBlockId = Block.Id;
            Block.Instructions.append(Inst);
            break;
        }
    }
}

void Lifter::BuildBlockGraph(IrFunction& Func, const AnalyzedFunction& SrcFunc) {
    QMap<Address, int> AddrToBlockId;
    for (int I = 0; I < SrcFunc.Blocks.size(); ++I) {
        AddrToBlockId[SrcFunc.Blocks[I].Start] = I;
    }

    for (int I = 0; I < Func.Blocks.size(); ++I) {
        if (I >= SrcFunc.Blocks.size()) break;
        const BasicBlock& SrcBlock = SrcFunc.Blocks[I];

        for (Address Succ : SrcBlock.Successors) {
            if (AddrToBlockId.contains(Succ)) {
                int SuccId = AddrToBlockId[Succ];
                if (!Func.Blocks[I].Successors.contains(SuccId)) {
                    Func.Blocks[I].Successors.append(SuccId);
                }
                if (!Func.Blocks[SuccId].Predecessors.contains(I)) {
                    Func.Blocks[SuccId].Predecessors.append(I);
                }
            }
        }
    }
}

IrFunction Lifter::LiftFunction(const AnalyzedFunction& Func, const AnalysisDatabase* Db) {
    CurrentDb = Db;
    NextTemp = 0;

    BinaryInfo BinInfo = Db->GetBinaryInfo();
    Is64Bit = BinInfo.Is64Bit;

    if (CsValid) {
        cs_close(&CsHandle);
        CsValid = false;
    }

    cs_mode Mode = Is64Bit ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, Mode, &CsHandle) != CS_ERR_OK) {
        return IrFunction{};
    }
    CsValid = true;
    cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

    IrFunction Result;
    Result.Name = Func.Name;
    Result.EntryAddr = Func.Start;
    Result.StackFrameSize = Func.StackFrameSize;
    Result.ReturnType = IrType::Int64;
    Result.NextTempId = 0;

    if (Func.Blocks.isEmpty()) {
        IrBasicBlock SingleBlock;
        SingleBlock.Id = 0;
        SingleBlock.StartAddr = Func.Start;
        SingleBlock.EndAddr = Func.End;
        SingleBlock.IsEntry = true;
        SingleBlock.IsExit = true;

        QList<AnalyzedInstruction> Instructions = Db->GetInstructions(Func.Start, Func.End);
        for (const AnalyzedInstruction& AInst : Instructions) {
            cs_insn* CsInsn = nullptr;
            size_t Count = cs_disasm(CsHandle, AInst.Bytes, AInst.Size, AInst.Addr, 1, &CsInsn);
            if (Count > 0) {
                LiftInstruction(CsInsn, CsInsn->detail, SingleBlock);
                cs_free(CsInsn, Count);
            }
        }

        Result.Blocks.append(SingleBlock);
    } else {
        for (int I = 0; I < Func.Blocks.size(); ++I) {
            const BasicBlock& SrcBlock = Func.Blocks[I];
            IrBasicBlock IrBlock;
            IrBlock.Id = I;
            IrBlock.StartAddr = SrcBlock.Start;
            IrBlock.EndAddr = SrcBlock.End;
            IrBlock.IsEntry = (SrcBlock.Start == Func.Start);
            IrBlock.IsExit = false;

            QList<AnalyzedInstruction> Instructions = Db->GetInstructions(SrcBlock.Start, SrcBlock.End);
            for (const AnalyzedInstruction& AInst : Instructions) {
                cs_insn* CsInsn = nullptr;
                size_t Count = cs_disasm(CsHandle, AInst.Bytes, AInst.Size, AInst.Addr, 1, &CsInsn);
                if (Count > 0) {
                    LiftInstruction(CsInsn, CsInsn->detail, IrBlock);
                    cs_free(CsInsn, Count);
                }
            }

            if (!IrBlock.Instructions.isEmpty()) {
                const IrInst& LastInst = IrBlock.Instructions.last();
                if (LastInst.Op == IrOp::Ret) {
                    IrBlock.IsExit = true;
                }
            }

            Result.Blocks.append(IrBlock);
        }

        BuildBlockGraph(Result, Func);
    }

    Result.NextTempId = NextTemp;

    bool HasFrameSetup = false;
    if (!Result.Blocks.isEmpty()) {
        const auto& FirstBlock = Result.Blocks[0];
        for (const auto& Inst : FirstBlock.Instructions) {
            if (Inst.Op == IrOp::Mov && Inst.Dest.IsReg() && Inst.Dest.RegId == 5 &&
                Inst.Src1.IsReg() && Inst.Src1.RegId == 4) {
                HasFrameSetup = true;
                break;
            }
        }
    }
    Result.UsesFramePointer = HasFrameSetup;

    if (Func.StackFrameSize > 0) {
        for (const auto& Block : Result.Blocks) {
            for (const auto& Inst : Block.Instructions) {
                if (Inst.Op == IrOp::Store && Inst.Dest.IsStack()) {
                    int Off = Inst.Dest.StackOffset;
                    if (!Result.StackVars.contains(Off)) {
                        StackVariable Var;
                        Var.Offset = Off;
                        Var.Name = QString("Var_%1").arg(Off < 0 ? QString("N%1").arg(-Off) : QString::number(Off));
                        Var.Type = Inst.Dest.Type;
                        Var.Size = IrTypeSize(Inst.Dest.Type);
                        Var.AccessCount = 1;
                        Result.StackVars[Off] = Var;
                    } else {
                        Result.StackVars[Off].AccessCount++;
                    }
                }
                if (Inst.Op == IrOp::Load && Inst.Src1.IsStack()) {
                    int Off = Inst.Src1.StackOffset;
                    if (!Result.StackVars.contains(Off)) {
                        StackVariable Var;
                        Var.Offset = Off;
                        Var.Name = QString("Var_%1").arg(Off < 0 ? QString("N%1").arg(-Off) : QString::number(Off));
                        Var.Type = Inst.Src1.Type;
                        Var.Size = IrTypeSize(Inst.Src1.Type);
                        Var.AccessCount = 1;
                        Result.StackVars[Off] = Var;
                    } else {
                        Result.StackVars[Off].AccessCount++;
                    }
                }
            }
        }
    }

    int ParamRegs[] = {7, 6, 2, 1, 8, 9};
    if (Is64Bit) {
        for (int I = 0; I < 6 && I < Func.ArgCount; ++I) {
            Result.Parameters.append(IrOperand::MakeReg(ParamRegs[I], IrType::Int64));
        }
        if (Func.ArgCount > 6) {
            for (int I = 6; I < Func.ArgCount; ++I) {
                Result.Parameters.append(IrOperand::MakeStack(16 + (I - 6) * 8, IrType::Int64));
            }
        }
    }

    return Result;
}

}
