#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/ua.hpp>

// Subset of IDA x86 mnemonic (itype) enum — enough to compile ported code.
enum {
    NN_null = 0,
    NN_mov, NN_movsx, NN_movzx,
    NN_lea, NN_push, NN_pop,
    NN_add, NN_sub, NN_and, NN_or, NN_xor, NN_not, NN_neg,
    NN_shl, NN_shr, NN_sar, NN_rol, NN_ror,
    NN_cmp, NN_test,
    NN_call, NN_callfi, NN_callni,
    NN_ret, NN_retn, NN_retf,
    NN_jmp, NN_jmpfi, NN_jmpni, NN_jmpshort,
    NN_ja, NN_jae, NN_jb, NN_jbe, NN_jc, NN_jcxz, NN_jecxz,
    NN_je, NN_jz, NN_jne, NN_jnz,
    NN_jg, NN_jge, NN_jl, NN_jle,
    NN_jna, NN_jnae, NN_jnb, NN_jnbe,
    NN_jnc, NN_jng, NN_jnge, NN_jnl, NN_jnle,
    NN_jno, NN_jnp, NN_jns, NN_jo, NN_jp, NN_jpe, NN_jpo, NN_js,
    NN_syscall, NN_sysenter, NN_sysret, NN_sysexit,
    NN_int, NN_int3, NN_into, NN_iret, NN_iretd, NN_iretq,
    NN_hlt, NN_nop,
    NN_last
};
