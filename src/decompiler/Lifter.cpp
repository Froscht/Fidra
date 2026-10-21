#include "Lifter.h"
#include "../analysis/TypeLibrary.h"
#include "Optimizer.h"
#include <QHash>
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

    if (BaseReg == 4 && IndexReg < 0) {
        IrType AccessType = MemAccessType(Op.size);
        return IrOperand::MakeStack(static_cast<int>(Disp), AccessType, true);
    }

    IrOperand Result = IrOperand::MakeInvalid();
    IrType AccessType = MemAccessType(Op.size);

    if (Mem.base == X86_REG_RIP || Mem.base == X86_REG_EIP) {
        return IrOperand::MakeGlobal(CurrentInsnEnd + static_cast<Address>(Disp), AccessType);
    }

    if (BaseReg < 0 && IndexReg < 0) {
        Result = IrOperand::MakeGlobal(static_cast<Address>(Disp), AccessType);
        if (Mem.segment == X86_REG_FS || Mem.segment == X86_REG_GS) {
            Result.Name = QString("%1:0x%2").arg(Mem.segment == X86_REG_FS ? "fs" : "gs").arg(Disp, 0, 16);
        }
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
        case X86_INS_JP: return CondCode::Parity;
        case X86_INS_JNP: return CondCode::NotParity;
        case X86_INS_JCXZ: case X86_INS_JECXZ: case X86_INS_JRCXZ: return CondCode::Equal;
        default: return CondCode::Always;
    }
}

void Lifter::LiftInstruction(cs_insn* Insn, const cs_detail* Detail, IrBasicBlock& Block) {
    const cs_x86& X86 = Detail->x86;
    unsigned int Id = Insn->id;
    CurrentInsnEnd = Insn->address + Insn->size;

    // Instructions the IR cannot model exactly are kept verbatim.
    auto EmitAsm = [&]() {
        IrInst Inst;
        Inst.Op = IrOp::Unknown;
        Inst.OriginalAddr = Insn->address;
        Inst.BasicBlockId = Block.Id;
        Inst.AsmText = QString::fromUtf8(Insn->mnemonic);
        if (Insn->op_str[0]) Inst.AsmText += " " + QString::fromUtf8(Insn->op_str);
        cs_regs Read, Written;
        uint8_t ReadCount = 0, WriteCount = 0;
        if (cs_regs_access(CsHandle, Insn, Read, &ReadCount, Written, &WriteCount) == CS_ERR_OK) {
            Inst.AsmRegsRead = 0;
            for (uint8_t I = 0; I < ReadCount; ++I) {
                int R = MapCsReg(static_cast<x86_reg>(Read[I]));
                if (R >= 0) Inst.AsmRegsRead |= 1u << R;
            }
            for (uint8_t I = 0; I < WriteCount; ++I) {
                x86_reg Reg = static_cast<x86_reg>(Written[I]);
                int R = MapCsReg(Reg);
                // Only 64/32-bit writes replace the whole register.
                IrType T = RegType(Reg);
                if (R >= 0 && (T == IrType::Int64 || T == IrType::Int32)) Inst.AsmRegsKilled |= 1u << R;
            }
        }
        Block.Instructions.append(Inst);
    };

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

    auto LiftValue = [&](int Idx) -> IrOperand {
        IrOperand Op = LiftOp(Idx);
        if (!IsMemOp(Idx)) return Op;
        IrOperand LoadResult = IrOperand::MakeTemp(AllocTemp(Op.Type), Op.Type);
        IrInst LoadInst;
        LoadInst.Op = IrOp::Load;
        LoadInst.Dest = LoadResult;
        LoadInst.Src1 = Op;
        LoadInst.OriginalAddr = Insn->address;
        LoadInst.BasicBlockId = Block.Id;
        Block.Instructions.append(LoadInst);
        return LoadResult;
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
        case X86_INS_MOVSXD: {
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

                if (Mem.base == X86_REG_RIP || Mem.base == X86_REG_EIP) {
                    Inst.Op = IrOp::AddressOf;
                    Inst.Src1 = IrOperand::MakeGlobal(CurrentInsnEnd + static_cast<Address>(Mem.disp));
                } else if (BaseReg < 0 && IndexReg < 0) {
                    Inst.Op = IrOp::Mov;
                    Inst.Src1 = IrOperand::MakeImm(Mem.disp);
                } else if ((BaseReg == 4 || BaseReg == 5) && IndexReg < 0 && Inst.Dest.IsReg() &&
                           Inst.Dest.RegId != 4 && Inst.Dest.RegId != 5) {
                    // Address of a stack slot (buffer, out-parameter): &var.
                    // Frame setup (lea rbp, [rsp+N]) stays arithmetic.
                    Inst.Op = IrOp::AddressOf;
                    Inst.Src1 = IrOperand::MakeStack(static_cast<int>(Mem.disp), IrType::Unknown, BaseReg == 4);
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

        case X86_INS_LEAVE: {
            // leave == mov rsp, rbp; pop rbp
            IrInst Mov;
            Mov.Op = IrOp::Mov;
            Mov.Dest = IrOperand::MakeReg(4, IrType::Int64);
            Mov.Src1 = IrOperand::MakeReg(5, IrType::Int64);
            Mov.OriginalAddr = Insn->address;
            Mov.BasicBlockId = Block.Id;
            Block.Instructions.append(Mov);
            IrInst Pop;
            Pop.Op = IrOp::Load;
            Pop.Dest = IrOperand::MakeReg(5, IrType::Int64);
            Pop.Src1 = IrOperand::MakeReg(4, IrType::Pointer);
            Pop.OriginalAddr = Insn->address;
            Pop.BasicBlockId = Block.Id;
            Block.Instructions.append(Pop);
            IrInst Add;
            Add.Op = IrOp::Add;
            Add.Dest = IrOperand::MakeReg(4, IrType::Int64);
            Add.Src1 = IrOperand::MakeReg(4, IrType::Int64);
            Add.Src2 = IrOperand::MakeImm(Is64Bit ? 8 : 4);
            Add.OriginalAddr = Insn->address;
            Add.BasicBlockId = Block.Id;
            Block.Instructions.append(Add);
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
            Inst.Src1 = LiftValue(0);
            Inst.Src2 = LiftValue(1);
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
                // call [mem] calls through the pointer stored there.
                Inst.Src1 = LiftValue(0);
                // call [__imp_X] (IAT / GOT slot): the slot's name is the callee.
                // LiftValue loaded the slot into a temp just before.
                if (CurrentDb && GetOp(0).type == X86_OP_MEM && !Block.Instructions.isEmpty()) {
                    const IrInst& Ld = Block.Instructions.last();
                    if (Ld.Op == IrOp::Load && Ld.Dest == Inst.Src1 && Ld.Src1.OpKind == IrOperand::Global) {
                        const QString SlotName = CurrentDb->GetName(Ld.Src1.GlobalAddr);
                        if (TypeLibrary::Instance().Find(SlotName)) Inst.CallName = SlotName;
                    }
                }
            }
            if (auto Proto = FindPrototype(Inst.CallTarget, Inst.CallName)) {
                Inst.CallProto = Proto;
                if (Proto->ReturnsVoid()) Inst.Dest = IrOperand::MakeInvalid();
                else Inst.Dest.Type = IrTypeFromCType(Proto->ReturnType);
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
                Inst.Dest = LiftValue(0);
            }
            Block.Instructions.append(Inst);
            break;
        }

        case X86_INS_JE: case X86_INS_JNE:
        case X86_INS_JL: case X86_INS_JLE: case X86_INS_JG: case X86_INS_JGE:
        case X86_INS_JB: case X86_INS_JBE: case X86_INS_JA: case X86_INS_JAE:
        case X86_INS_JS: case X86_INS_JNS: case X86_INS_JO: case X86_INS_JNO:
        case X86_INS_JCXZ: case X86_INS_JECXZ: case X86_INS_JRCXZ: case X86_INS_JP: case X86_INS_JNP: {
            if (Id == X86_INS_JCXZ || Id == X86_INS_JECXZ || Id == X86_INS_JRCXZ) {
                // jrcxz tests rcx directly instead of flags.
                IrInst Cmp;
                Cmp.Op = IrOp::Compare;
                Cmp.Src1 = IrOperand::MakeReg(1, Id == X86_INS_JRCXZ ? IrType::Int64 : (Id == X86_INS_JECXZ ? IrType::Int32 : IrType::Int16));
                Cmp.Src2 = IrOperand::MakeImm(0);
                Cmp.OriginalAddr = Insn->address;
                Cmp.BasicBlockId = Block.Id;
                Block.Instructions.append(Cmp);
            }
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

        default:
            EmitAsm();
            break;
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

        // Nothing after a call that never returns executes: cut the block
        // there and drop its fall-through edge.
        auto& Insts = Func.Blocks[I].Instructions;
        bool EndsNoReturn = false;
        for (int J = 0; J < Insts.size(); ++J) {
            if (Insts[J].Op == IrOp::Call && IsNoReturnCall(Insts[J])) {
                Insts.resize(J + 1);
                EndsNoReturn = true;
                break;
            }
        }
        if (EndsNoReturn) continue;

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
    CalleeArity.clear();
    DebugProtos.clear();

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
                // Analysis blocks can run past a ret/jmp into unrelated code
                // (e.g. a morestack stub); nothing after a terminator executes.
                if (!IrBlock.Instructions.isEmpty() &&
                    (IrBlock.Instructions.last().Op == IrOp::Ret || IrBlock.Instructions.last().Op == IrOp::Jump)) {
                    break;
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
                    int Off = StackKey(Inst.Dest);
                    if (!Result.StackVars.contains(Off)) {
                        StackVariable Var;
                        Var.Offset = Inst.Dest.StackOffset;
                        Var.SpRelative = Inst.Dest.SpRelative;
                        Var.Name = StackVarName(Inst.Dest.StackOffset, Inst.Dest.SpRelative);
                        Var.Type = Inst.Dest.Type;
                        Var.Size = IrTypeSize(Inst.Dest.Type);
                        Var.AccessCount = 1;
                        Result.StackVars[Off] = Var;
                    } else {
                        Result.StackVars[Off].AccessCount++;
                    }
                }
                if (Inst.Op == IrOp::Load && Inst.Src1.IsStack()) {
                    int Off = StackKey(Inst.Src1);
                    if (!Result.StackVars.contains(Off)) {
                        StackVariable Var;
                        Var.Offset = Inst.Src1.StackOffset;
                        Var.SpRelative = Inst.Src1.SpRelative;
                        Var.Name = StackVarName(Inst.Src1.StackOffset, Inst.Src1.SpRelative);
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

    // Calling convention from the binary: Go's register ABI, Win64 for PE
    // (has .pdata/.rdata), SysV otherwise.
    if (!Is64Bit) {
        Result.Conv = CallingConv::Cdecl32;
    } else if (BinInfo.Compiler.startsWith("Go") && !Func.Name.startsWith("sub_")) {
        // Every Go function is named from pclntab; unnamed code in a Go
        // binary is cgo/C and uses SysV.
        Result.Conv = CallingConv::Go;
    } else {
        Result.Conv = CallingConv::SysV;
        for (const Segment& Seg : BinInfo.Segments) {
            if (Seg.Name == ".pdata" || Seg.Name == ".rdata") { Result.Conv = CallingConv::Win64; break; }
        }
    }

    // Initial guess from the analysis; the optimizer refines register
    // parameters from liveness.
    const QVector<int> ParamRegs = ArgRegisterOrder(Result.Conv);
    if (Is64Bit) {
        for (int I = 0; I < ParamRegs.size() && I < Func.ArgCount; ++I) {
            Result.Parameters.append(IrOperand::MakeReg(ParamRegs[I], IrType::Int64));
        }
        if (Result.Conv == CallingConv::SysV && Func.ArgCount > 6) {
            for (int I = 6; I < Func.ArgCount; ++I) {
                Result.Parameters.append(IrOperand::MakeStack(16 + (I - 6) * 8, IrType::Int64));
            }
        }
    }

    // Debug info: source prototype and stack variable names.
    if (auto Dbg = Db->GetDebugFunction(Func.Start)) {
        Result.Proto = std::make_shared<const FuncPrototype>(Dbg->Proto);
        Result.ReturnType = IrTypeFromCType(Dbg->Proto.ReturnType);
        for (const DebugVariable& V : Dbg->Locals)
            if (V.Base == DebugVariable::FrameBase::Cfa) Result.DebugLocals.insert(V.CfaOffset, {V.Name, V.Type});
        if (Is64Bit && Result.Conv != CallingConv::Go) {
            Result.Parameters.clear();
            int IntUsed = 0;
            for (int P = 0; P < Dbg->Proto.Params.size(); ++P) {
                const IrType T = IrTypeFromCType(Dbg->Proto.Params[P].Type);
                const bool IsFloat = T == IrType::Float32 || T == IrType::Float64;
                const int Slot = Result.Conv == CallingConv::Win64 ? P : (IsFloat ? -1 : IntUsed++);
                if (IsFloat || Slot < 0) Result.Parameters.append(IrOperand::MakeInvalid());
                else if (Slot < ParamRegs.size()) Result.Parameters.append(IrOperand::MakeReg(ParamRegs[Slot], T));
                else Result.Parameters.append(IrOperand::MakeStack(16 + (Slot - static_cast<int>(ParamRegs.size())) * 8, T));
            }
        }
        if (Dbg->Proto.ReturnsVoid()) {
            for (IrBasicBlock& B : Result.Blocks)
                for (IrInst& Inst : B.Instructions)
                    if (Inst.Op == IrOp::Ret) Inst.Src1 = IrOperand::MakeInvalid();
        }
    }

    // rsp displacement of the entry prologue (pushes, sub rsp) before the first call.
    if (!Result.Blocks.isEmpty()) {
        int Delta = 0;
        bool Known = true;
        for (const IrInst& Inst : Result.Blocks[0].Instructions) {
            if (Inst.Op == IrOp::Call || Inst.Op == IrOp::Ret || Inst.Op == IrOp::Jump) break;
            // Frame pointer setup: mov rbp, rsp / lea rbp, [rsp+N].
            if (Inst.Dest.IsReg() && Inst.Dest.RegId == 5 && Inst.Src1.IsReg() && Inst.Src1.RegId == 4 &&
                Result.FramePointerCfa == IrFunction::UnknownFrame) {
                if (Inst.Op == IrOp::Mov) Result.FramePointerCfa = -8 - Delta;
                else if (Inst.Op == IrOp::Add && Inst.Src2.IsImm()) Result.FramePointerCfa = -8 - Delta + static_cast<int>(Inst.Src2.ImmValue);
                continue;
            }
            if (!Inst.Dest.IsReg() || Inst.Dest.RegId != 4 || Inst.Op == IrOp::Store) continue;
            if (Inst.Op == IrOp::Sub && Inst.Src1.IsReg() && Inst.Src1.RegId == 4 && Inst.Src2.IsImm()) Delta += static_cast<int>(Inst.Src2.ImmValue);
            else if (Inst.Op == IrOp::Add && Inst.Src1.IsReg() && Inst.Src1.RegId == 4 && Inst.Src2.IsImm()) Delta -= static_cast<int>(Inst.Src2.ImmValue);
            else { Known = false; break; }
        }
        Result.PrologueRspDelta = Known ? Delta : -1;
        if (!Known) Result.FramePointerCfa = IrFunction::UnknownFrame;
    }

    // PDB locals are relative to rsp after the prologue (CFA = rsp + delta + 8)
    // or to the frame pointer (CFA = rbp - FramePointerCfa).
    if (auto Dbg = Db->GetDebugFunction(Func.Start)) {
        for (const DebugVariable& V : Dbg->Locals) {
            if (V.Base == DebugVariable::FrameBase::SpAfterPrologue && Result.PrologueRspDelta >= 0)
                Result.DebugLocals.insert(V.CfaOffset - Result.PrologueRspDelta - 8, {V.Name, V.Type});
            else if (V.Base == DebugVariable::FrameBase::FramePointer && Result.FramePointerCfa != IrFunction::UnknownFrame)
                Result.DebugLocals.insert(V.CfaOffset + Result.FramePointerCfa, {V.Name, V.Type});
        }
    }

    PinConditionOperands(Result);
    BindCallArguments(Result);
    Result.NextTempId = NextTemp;
    return Result;
}

// A conditional jump tests the flags of an earlier cmp/test/arithmetic op.
// When a register that op read is overwritten before the jump (e.g.
// "cmp edi, 1; lea rdi, [str]; jle"), the condition must use the old value:
// copy it into a temp at the flag-setting point.
void Lifter::PinConditionOperands(IrFunction& Func) {
    for (IrBasicBlock& Block : Func.Blocks) {
        auto& Insts = Block.Instructions;
        if (Insts.size() < 2 || Insts.last().Op != IrOp::CondJump) continue;

        int F = -1;
        bool Arith = false;
        for (int I = Insts.size() - 2; I >= 0 && F < 0; --I) {
            switch (Insts[I].Op) {
            case IrOp::Compare: case IrOp::Test: F = I; break;
            case IrOp::Add: case IrOp::Sub: case IrOp::And: case IrOp::Or: case IrOp::Xor:
            case IrOp::Shl: case IrOp::Shr: case IrOp::Sar: case IrOp::Neg: case IrOp::Mul:
                if (Insts[I].Dest.IsValid()) { F = I; Arith = true; }
                break;
            case IrOp::Call: case IrOp::Unknown: I = -1; break;
            default: break;
            }
        }
        if (F < 0) continue;

        auto Overwritten = [&](const IrOperand& Op) {
            if (!Op.IsReg()) return false;
            for (int J = F + 1; J < Insts.size() - 1; ++J) {
                const IrInst& M = Insts[J];
                if (M.Op == IrOp::Unknown && (M.AsmRegsKilled & (1u << Op.RegId))) return true;
                if (M.Dest.IsReg() && M.Dest.RegId == Op.RegId && M.Op != IrOp::Store && M.Op != IrOp::Jump &&
                    M.Op != IrOp::CondJump && M.Op != IrOp::Compare && M.Op != IrOp::Test) return true;
            }
            return false;
        };

        if (Arith) {
            const IrOperand Res = Insts[F].Dest;
            if (!Overwritten(Res)) continue;
            IrInst Copy;
            Copy.Op = IrOp::Mov;
            Copy.Dest = IrOperand::MakeTemp(AllocTemp(Res.Type), Res.Type);
            Copy.Src1 = Res;
            Copy.OriginalAddr = Insts[F].OriginalAddr;
            Copy.BasicBlockId = Block.Id;
            IrInst Tst = Copy;
            Tst.Op = IrOp::Test;
            Tst.Src1 = Copy.Dest;
            Tst.Src2 = Copy.Dest;
            Tst.Dest = IrOperand::MakeInvalid();
            Insts.insert(F + 1, Tst);
            Insts.insert(F + 1, Copy);
            continue;
        }

        IrInst& Cmp = Insts[F];
        QVector<IrInst> Copies;
        for (IrOperand* Op : {&Cmp.Src1, &Cmp.Src2}) {
            if (!Overwritten(*Op)) continue;
            IrInst Copy;
            Copy.Op = IrOp::Mov;
            Copy.Dest = IrOperand::MakeTemp(AllocTemp(Op->Type), Op->Type);
            Copy.Src1 = *Op;
            Copy.OriginalAddr = Cmp.OriginalAddr;
            Copy.BasicBlockId = Block.Id;
            *Op = Copy.Dest;
            Copies.append(Copy);
        }
        for (int K = Copies.size() - 1; K >= 0; --K) Insts.insert(F, Copies[K]);
    }
}

// Prototype of a callee: its own debug info first (exact, also for static
// functions), then the type library by name.
std::shared_ptr<const FuncPrototype> Lifter::FindPrototype(Address Target, const QString& Name) {
    if (CurrentDb && Target != 0) {
        auto It = DebugProtos.constFind(Target);
        if (It == DebugProtos.constEnd()) {
            std::shared_ptr<const FuncPrototype> P;
            if (auto Dbg = CurrentDb->GetDebugFunction(Target)) P = std::make_shared<const FuncPrototype>(Dbg->Proto);
            It = DebugProtos.insert(Target, P);
        }
        if (It.value()) return It.value();
    }
    const FuncPrototype* Lib = TypeLibrary::Instance().Find(Name);
    // The library outlives every decompilation: alias without ownership.
    return Lib ? std::shared_ptr<const FuncPrototype>(std::shared_ptr<const FuncPrototype>(), Lib) : nullptr;
}

bool Lifter::IsNoReturnCall(const IrInst& Inst) const {
    if (Inst.CallProto && Inst.CallProto->NoReturn) return true;
    if (CurrentDb && Inst.CallTarget != 0 && CurrentDb->HasFunction(Inst.CallTarget))
        return CurrentDb->GetFunction(Inst.CallTarget).IsNoReturn;
    return false;
}

namespace {

// Registers (bit = reg id) an instruction reads, for argument binding.
uint32_t ReadRegs(const IrInst& Inst) {
    if (Inst.Op == IrOp::Unknown) return Inst.AsmRegsRead;
    uint32_t M = 0;
    auto Add = [&M](const IrOperand& Op) {
        if (Op.IsReg() && Op.RegId >= 0 && Op.RegId < 16) M |= 1u << Op.RegId;
        if (Op.IsStack()) M |= 1u << (Op.SpRelative ? 4 : 5);
    };
    Add(Inst.Src1);
    Add(Inst.Src2);
    if (Inst.Op == IrOp::Store || Inst.Op == IrOp::Jump || Inst.Op == IrOp::CondJump || Inst.Dest.IsStack()) Add(Inst.Dest);
    for (const IrOperand& A : Inst.CallArgs) Add(A);
    return M;
}

bool IsPureValueDef(IrOp Op) {
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

// Number of arguments a printf/scanf-style format string consumes from the
// integer argument registers (floating-point values travel in xmm).
int CountFormatArgs(const QByteArray& Fmt, bool IsScanf) {
    int Count = 0;
    for (int I = 0; I < Fmt.size(); ++I) {
        if (Fmt[I] != '%') continue;
        ++I;
        if (I < Fmt.size() && Fmt[I] == '%') continue;
        bool Suppressed = false;
        bool IsFloat = false;
        for (; I < Fmt.size(); ++I) {
            const char C = Fmt[I];
            if (C == '*') { if (IsScanf) Suppressed = true; else ++Count; continue; }
            if (std::strchr("-+ #0123456789.'hlLqjztI$", C)) continue;
            if (std::strchr("fFeEgGaA", C)) IsFloat = !IsScanf;
            if (C == '[' && IsScanf) { while (I + 1 < Fmt.size() && Fmt[I + 1] != ']') ++I; ++I; }
            break;
        }
        if (!Suppressed && !IsFloat) ++Count;
    }
    return Count;
}

}

// Ties each call to its argument values. For argument register R the last
// full write to R before the call (in the same block, with no read of R or
// other call in between) becomes a temp passed as the argument; the
// register's value is dead after the call anyway (caller-saved). Without
// such a write the register itself is the argument (e.g. a pass-through
// parameter).
void Lifter::BindCallArguments(IrFunction& Func) {
    if (Func.Conv == CallingConv::Cdecl32 || Func.Conv == CallingConv::Go) return;
    const QVector<int> Order = ArgRegisterOrder(Func.Conv);

    for (IrBasicBlock& Block : Func.Blocks) {
        auto& Insts = Block.Instructions;
        for (int I = 0; I < Insts.size(); ++I) {
            // A jump out of the function at the end of an exit block is a tail call.
            const bool TailJump = Insts[I].Op == IrOp::Jump && I == Insts.size() - 1 && Block.Successors.isEmpty() &&
                                  Insts[I].Dest.OpKind == IrOperand::Label && CurrentDb;
            if (Insts[I].Op != IrOp::Call && !TailJump) continue;
            Address Target = Insts[I].CallTarget;
            if (TailJump) {
                Target = Insts[I].Dest.GlobalAddr;
                if (Target == Func.EntryAddr) continue;  // self loop, not a call
                Insts[I].CallProto = FindPrototype(Target, CurrentDb->GetName(Target));
            }
            const FuncPrototype* Proto = Insts[I].CallProto.get();
            int Arity = -1;
            bool Exact = false;
            if (Proto) {
                Arity = static_cast<int>(Proto->Params.size());
                Exact = !Proto->Variadic;
            } else if (CurrentDb && Target != 0 && CurrentDb->HasFunction(Target)) {
                const AnalyzedFunction Callee = CurrentDb->GetFunction(Target);
                int N = Callee.ArgCount;
                if (ResolveCalleeArity && !Callee.IsImported && !Callee.IsThunk) {
                    auto It = CalleeArity.constFind(Callee.Start);
                    if (It == CalleeArity.constEnd()) {
                        Lifter Sub;
                        Sub.ResolveCalleeArity = false;
                        It = CalleeArity.insert(Callee.Start, Optimizer::RegisterParameterCount(Sub.LiftFunction(Callee, CurrentDb)));
                    }
                    N = It.value();  // liveness beats the analysis' text heuristic
                }
                if (N > 0) Arity = N;
            }
            if (Arity < 0) continue;

            QVector<IrOperand> Args;
            QHash<int, IrOperand> DefSource;  // arg index -> the def's source operand
            auto BindArg = [&](int K) {
                const int R = Order[K];
                const uint32_t Bit = 1u << R;
                for (int J = I - 1; J >= 0; --J) {
                    IrInst& D = Insts[J];
                    if (D.Op == IrOp::Call) break;
                    const bool WritesR = D.Op == IrOp::Unknown ? (D.AsmRegsKilled & Bit) != 0
                                                               : (D.Dest.IsReg() && D.Dest.RegId == R &&
                                                                  D.Op != IrOp::Store && D.Op != IrOp::Jump &&
                                                                  D.Op != IrOp::CondJump && D.Op != IrOp::Compare &&
                                                                  D.Op != IrOp::Test);
                    if (WritesR) {
                        const int Size = IrTypeSize(D.Dest.Type);
                        if (D.Op != IrOp::Unknown && IsPureValueDef(D.Op) && Size != 1 && Size != 2) {
                            const IrType T = D.Dest.Type;
                            const int Temp = AllocTemp(T);
                            D.Dest = IrOperand::MakeTemp(Temp, T);
                            if (D.Op == IrOp::Mov || D.Op == IrOp::AddressOf) DefSource.insert(Args.size(), D.Src1);
                            Args.append(IrOperand::MakeTemp(Temp, T));
                            return;
                        }
                        break;
                    }
                    if (ReadRegs(D) & Bit) break;
                }
                Args.append(IrOperand::MakeReg(R, IrType::Int64));
            };

            // Arguments past the registers go to the outgoing stack area:
            // Win64 at [rsp+0x20] (after the 32-byte home space), SysV at [rsp].
            const int StackBase = Func.Conv == CallingConv::Win64 ? 0x20 : 0;
            auto BindStackArg = [&](int K) {
                const int Off = StackBase + (K - static_cast<int>(Order.size())) * 8;
                for (int J = I - 1; J >= 0; --J) {
                    IrInst& D = Insts[J];
                    if (D.Op == IrOp::Call || D.Op == IrOp::Unknown) break;
                    if (D.Dest.IsReg() && D.Dest.RegId == 4 && D.Op != IrOp::Store) break;  // rsp moved
                    if (D.Op == IrOp::Store && D.Dest.IsStack() && D.Dest.SpRelative && D.Dest.StackOffset == Off) {
                        // The outgoing argument slot is scratch: turn the store into the argument value.
                        const IrType T = D.Src1.Type != IrType::Unknown ? D.Src1.Type : D.Dest.Type;
                        const int Temp = AllocTemp(T);
                        D.Op = IrOp::Mov;
                        D.Dest = IrOperand::MakeTemp(Temp, T);
                        Args.append(IrOperand::MakeTemp(Temp, T));
                        return;
                    }
                    if ((D.Src1.IsStack() && D.Src1.SpRelative && D.Src1.StackOffset == Off) ||
                        (D.Src2.IsStack() && D.Src2.SpRelative && D.Src2.StackOffset == Off)) break;
                }
                Args.append(IrOperand::MakeStack(Off, IrType::Int64, true));
            };

            // Parameter P -> location. SysV hands integers and floats out from
            // separate register sequences; Win64 uses position P for either.
            // Float values live in xmm registers the IR does not model: they
            // get an invalid placeholder.
            int IntUsed = 0, StackUsed = 0;
            auto BindParam = [&](int Position, bool IsFloat) {
                if (Func.Conv == CallingConv::Win64) {
                    if (Position >= Order.size()) BindStackArg(Position);
                    else if (IsFloat) Args.append(IrOperand::MakeInvalid());
                    else BindArg(Position);
                    return;
                }
                if (IsFloat) { Args.append(IrOperand::MakeInvalid()); return; }
                if (IntUsed < Order.size()) BindArg(IntUsed++);
                else BindStackArg(static_cast<int>(Order.size()) + StackUsed++);
            };
            auto ParamIsFloat = [&](int P) {
                if (!Proto || P >= Proto->Params.size()) return false;
                const IrType T = IrTypeFromCType(Proto->Params[P].Type);
                return T == IrType::Float32 || T == IrType::Float64;
            };
            for (int P = 0; P < std::min(Arity, 16); ++P) BindParam(P, ParamIsFloat(P));

            // printf-style: the constant format string says how many more.
            const int FmtIdx = Proto ? Proto->FormatParam() : -1;
            if (FmtIdx >= 0 && FmtIdx < Args.size() && CurrentDb) {
                IrOperand Src = DefSource.value(FmtIdx, Args[FmtIdx]);
                Address FmtAddr = 0;
                if (Src.IsImm()) FmtAddr = static_cast<Address>(Src.ImmValue);
                else if (Src.OpKind == IrOperand::Global) FmtAddr = Src.GlobalAddr;
                const QByteArray Raw = FmtAddr ? CurrentDb->ReadBytes(FmtAddr, 1024) : QByteArray();
                const int Nul = Raw.indexOf('\0');
                if (Nul >= 0) {
                    const int Extra = CountFormatArgs(Raw.left(Nul), Insts[I].CallName.contains("scanf"));
                    for (int P = Arity; P < std::min(Arity + Extra, 16); ++P) BindParam(P, false);
                    Exact = true;
                }
            }

            Insts[I].CallArgs = Args;
            Insts[I].CallArgsExact = Exact;
        }
    }
}

IrType IrTypeFromCType(const QString& CType) {
    QString T = CType.simplified();
    if (T.contains('*')) return IrType::Pointer;
    for (const char* Q : {"const ", "volatile ", "struct ", "enum "}) T.remove(QLatin1String(Q));
    T = T.trimmed();
    if (T == "void") return IrType::Void;
    static const QHash<QString, IrType> Known = {
        {"char", IrType::Int8}, {"signed char", IrType::Int8}, {"unsigned char", IrType::UInt8},
        {"BYTE", IrType::UInt8}, {"UCHAR", IrType::UInt8}, {"BOOLEAN", IrType::UInt8}, {"uint8_t", IrType::UInt8},
        {"CHAR", IrType::Int8}, {"int8_t", IrType::Int8},
        {"short", IrType::Int16}, {"SHORT", IrType::Int16}, {"int16_t", IrType::Int16},
        {"unsigned short", IrType::UInt16}, {"WORD", IrType::UInt16}, {"USHORT", IrType::UInt16},
        {"uint16_t", IrType::UInt16}, {"wchar_t", IrType::UInt16}, {"WCHAR", IrType::UInt16}, {"ATOM", IrType::UInt16},
        {"int", IrType::Int32}, {"INT", IrType::Int32}, {"BOOL", IrType::Int32}, {"LONG", IrType::Int32},
        {"int32_t", IrType::Int32}, {"NTSTATUS", IrType::Int32}, {"HRESULT", IrType::Int32}, {"LSTATUS", IrType::Int32},
        {"pid_t", IrType::Int32}, {"key_t", IrType::Int32},
        {"unsigned", IrType::UInt32}, {"unsigned int", IrType::UInt32}, {"DWORD", IrType::UInt32},
        {"UINT", IrType::UInt32}, {"ULONG", IrType::UInt32}, {"uint32_t", IrType::UInt32}, {"mode_t", IrType::UInt32},
        {"uid_t", IrType::UInt32}, {"gid_t", IrType::UInt32}, {"socklen_t", IrType::UInt32}, {"in_addr_t", IrType::UInt32},
        {"long", IrType::Int64}, {"long long", IrType::Int64}, {"ssize_t", IrType::Int64}, {"off_t", IrType::Int64},
        {"time_t", IrType::Int64}, {"clock_t", IrType::Int64}, {"intptr_t", IrType::Int64}, {"intmax_t", IrType::Int64},
        {"int64_t", IrType::Int64}, {"LONG_PTR", IrType::Int64}, {"LONGLONG", IrType::Int64}, {"INT_PTR", IrType::Int64},
        {"LRESULT", IrType::Int64}, {"LPARAM", IrType::Int64},
        {"unsigned long", IrType::UInt64}, {"unsigned long long", IrType::UInt64}, {"size_t", IrType::UInt64},
        {"uintptr_t", IrType::UInt64}, {"uint64_t", IrType::UInt64}, {"SIZE_T", IrType::UInt64},
        {"ULONG_PTR", IrType::UInt64}, {"DWORD_PTR", IrType::UInt64}, {"DWORD64", IrType::UInt64},
        {"ULONGLONG", IrType::UInt64}, {"WPARAM", IrType::UInt64}, {"SOCKET", IrType::UInt64},
        {"float", IrType::Float32}, {"double", IrType::Float64},
    };
    auto It = Known.constFind(T);
    if (It != Known.constEnd()) return It.value();
    // Win32 handle and pointer typedefs: HANDLE, HWND, LPVOID, PDWORD, FARPROC, BSTR, FILE, va_list, ...
    if (T.size() > 1 && (T[0] == 'H' || T.startsWith("LP") || (T[0] == 'P' && T[1].isUpper()))) return IrType::Pointer;
    if (T == "FARPROC" || T == "BSTR" || T == "SC_HANDLE" || T == "va_list") return IrType::Pointer;
    return IrType::Int64;
}

}
