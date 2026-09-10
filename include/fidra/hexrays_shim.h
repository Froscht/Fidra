#pragma once

// Hexrays SDK shim — TIER 2, COMPILE-ONLY.
// Ported chain code (vuln/) references cfunc_t / ctree_t / hexrays_failure_t.
// Fidra has no Hex-Rays. These stubs let the code compile; runtime calls that
// need decompilation return failure so callers hit their existing error paths.
// Bridge to Fidra's own decompiler (src/decompiler) or libdecomp lives in
// src/analysis/HexraysShim.cpp — off until wired.

#include "ida_shim.h"
#include <string>
#include <vector>
#include <memory>

// Hexrays ctree item type ids (subset — only referenced values enumerated)
enum ctype_t {
    cot_empty = 0,
    cot_comma, cot_asg, cot_asgbor, cot_asgxor, cot_asgband,
    cot_asgadd, cot_asgsub, cot_asgmul, cot_asgsshr, cot_asgushr,
    cot_asgshl, cot_asgsdiv, cot_asgudiv, cot_asgsmod, cot_asgumod,
    cot_tern, cot_lor, cot_land, cot_bor, cot_xor, cot_band,
    cot_eq, cot_ne, cot_sge, cot_uge, cot_sle, cot_ule,
    cot_sgt, cot_ugt, cot_slt, cot_ult, cot_sshr, cot_ushr, cot_shl,
    cot_add, cot_sub, cot_mul, cot_sdiv, cot_udiv, cot_smod, cot_umod,
    cot_fadd, cot_fsub, cot_fmul, cot_fdiv,
    cot_fneg, cot_neg, cot_cast, cot_lnot, cot_bnot, cot_ptr, cot_ref,
    cot_postinc, cot_postdec, cot_preinc, cot_predec,
    cot_call, cot_idx, cot_memref, cot_memptr, cot_num, cot_fnum, cot_str,
    cot_obj, cot_var, cot_insn, cot_sizeof, cot_helper, cot_type,
    cit_empty = 70,
    cit_block, cit_expr, cit_if, cit_for, cit_while,
    cit_do, cit_switch, cit_break, cit_continue, cit_return, cit_goto, cit_asm,
};

enum cvisitor_flags {
    CV_FAST     = 0x0001,
    CV_PRUNE    = 0x0002,
    CV_PARENTS  = 0x0004,
    CV_POST     = 0x0008,
    CV_RESTART  = 0x0010,
    CV_INSNS    = 0x0020,
};

struct hexrays_failure_t {
    int code = 0;
    ea_t errea = BADADDR;
    std::string desc;
    std::string str() const { return desc; }
};

// vd_failure_t — hexrays exception type
struct vd_failure_t : public hexrays_failure_t {
    std::string hf_desc() const { return desc; }
};

struct lvar_t {
    std::string name;
    std::string type;
    int width = 0;
    bool is_arg_var = false;
    bool is_result_var = false;
    ea_t defea = BADADDR;
};
using lvars_t = std::vector<lvar_t>;

struct citem_t {
    ctype_t op = cot_empty;
    ea_t ea = BADADDR;
    int label_num = -1;
    int index = -1;
    bool is_expr() const { return op < cit_empty; }
    bool is_insn() const { return op >= cit_empty; }
};

struct cexpr_t : citem_t {
    uint64_t n_value = 0;
    ea_t obj_ea = BADADDR;
    std::string helper;
    std::string obj_name;
    std::vector<cexpr_t> args;
    cexpr_t* x = nullptr;
    cexpr_t* y = nullptr;
    cexpr_t* z = nullptr;
    int v_idx = -1;
    int m = -1;         // member index (cot_memref/memptr)
    int ptrsize = 0;    // pointer size (cot_memptr)
    std::string type_str;

    bool is_call_object_of(const char* /*name*/) const { return false; }
    bool is_call_object_of(citem_t* /*item*/) const { return false; }
    bool is_call_object_of(const citem_t* /*item*/) const { return false; }
    // Values array — cot_num / cswitch value list.
    std::vector<uint64_t> values;
};

struct cinsn_t : citem_t {
    cexpr_t* expr = nullptr;
    std::vector<cinsn_t> body;
    struct cif_t* cif = nullptr;
    struct cfor_t* cfor = nullptr;
    struct cwhile_t* cwhile = nullptr;
    struct cdo_t* cdo = nullptr;
    struct cswitch_t* cswitch = nullptr;
    struct creturn_t* creturn = nullptr;
    struct cgoto_t* cgoto = nullptr;
    struct casm_t* casm = nullptr;
};

struct cif_t     : cinsn_t { cinsn_t ithen; cinsn_t ielse; };
struct cfor_t    : cinsn_t { cexpr_t init; cexpr_t cond; cexpr_t step; };
struct cwhile_t  : cinsn_t {};
struct cdo_t     : cinsn_t {};
struct ccase_t   : cinsn_t { std::vector<uint64_t> values; };
struct cswitch_t : cinsn_t { cexpr_t* expr = nullptr; std::vector<ccase_t> cases; ea_t minval = 0; ea_t maxval = 0; };
struct creturn_t : cinsn_t { cexpr_t* expr = nullptr; };
struct cgoto_t   : cinsn_t { int label_num = -1; };
struct casm_t    : cinsn_t { std::vector<ea_t> ea_list; };

class cfunc_t {
public:
    ea_t start_ea = BADADDR;
    lvars_t lvars;
    std::vector<std::string> warnings;
    std::string pseudocode;
    strvec_t pseudocode_lines;

    lvars_t* get_lvars() { return &lvars; }
    const lvars_t* get_lvars() const { return &lvars; }
    const std::vector<std::string>& get_warnings() const { return warnings; }
    std::string print_func() const { return pseudocode; }
    const strvec_t& get_pseudocode() const { return pseudocode_lines; }

    cinsn_t body;

    bool save_user_cmts() { return true; }
    bool set_user_cmt(ea_t /*ea*/, const char* /*cmt*/) { return true; }
    void build_c_tree() {}
    void refresh_func_ctext() {}
};


using cfuncptr_t = std::shared_ptr<cfunc_t>;

class ctree_visitor_t {
public:
    int flags = 0;
    std::vector<citem_t*> parents;
    ctree_visitor_t(int f = 0) : flags(f) {}
    virtual ~ctree_visitor_t() = default;
    virtual int visit_expr(cexpr_t* /*expr*/) { return 0; }
    virtual int visit_insn(cinsn_t* /*insn*/) { return 0; }
    citem_t* parent_expr() { return parents.empty() ? nullptr : parents.back(); }
    citem_t* parent_item() { return parents.empty() ? nullptr : parents.back(); }
    int apply_to(citem_t* /*root*/, citem_t* /*parent*/ = nullptr) { return 0; }
    int apply_to_exprs(citem_t* /*root*/, citem_t* /*parent*/ = nullptr) { return 0; }
};

class ctree_parentee_t : public ctree_visitor_t {
public:
    ctree_parentee_t(int f = 0) : ctree_visitor_t(f | CV_PARENTS) {}
    std::vector<citem_t*> parents;
    citem_t* parent_expr() { return parents.empty() ? nullptr : parents.back(); }
    citem_t* parent_item() { return parents.empty() ? nullptr : parents.back(); }
};

// Decompile entry — stubs return nullptr and set failure so callers degrade.
cfuncptr_t decompile(func_t* pfn, hexrays_failure_t* hf = nullptr, int flags = 0);
cfuncptr_t decompile(ea_t ea, hexrays_failure_t* hf = nullptr, int flags = 0);
inline cfuncptr_t decompile_func(func_t* pfn, hexrays_failure_t* hf = nullptr, int flags = 0) { return decompile(pfn, hf, flags); }

// Hexrays hook events (subset — code compiles, runtime no-op)
enum hexrays_event_t {
    hxe_flowchart, hxe_stkpnts, hxe_prolog, hxe_microcode, hxe_preoptimized,
    hxe_locopt, hxe_prealloc, hxe_glbopt, hxe_structural, hxe_maturity,
    hxe_interr, hxe_combine, hxe_print_func, hxe_func_printed, hxe_resolve_stkaddrs,
};

// libdecomp / hexrays init helpers (no-ops for now)
inline bool init_hexrays_plugin(int /*flags*/ = 0) { return false; }
inline void term_hexrays_plugin() {}

// ---- Microcode (hex-rays low-level IR) stubs ----

enum mopcode_t {
    m_nop = 0, m_stx, m_ldx, m_ldc, m_mov, m_neg, m_lnot, m_bnot, m_xds, m_xdu,
    m_low, m_high, m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod, m_or,
    m_and, m_xor, m_shl, m_shr, m_sar, m_cfadd, m_ofadd, m_cfshl, m_cfshr,
    m_sets, m_seto, m_setp, m_setnz, m_setz, m_setae, m_setb, m_seta, m_setbe,
    m_setg, m_setge, m_setl, m_setle, m_jcnd, m_jnz, m_jz, m_jae, m_jb, m_ja,
    m_jbe, m_jg, m_jge, m_jl, m_jle, m_jtbl, m_ijmp, m_goto, m_call, m_icall,
    m_ret, m_push, m_pop, m_und, m_ext, m_f2i, m_f2u, m_i2f, m_u2f, m_f2f,
    m_fneg, m_fadd, m_fsub, m_fmul, m_fdiv,
};

enum mopt_t {
    mop_z = 0, mop_r, mop_n, mop_str, mop_d, mop_S, mop_v, mop_b,
    mop_f, mop_l, mop_a, mop_h, mop_c, mop_fn, mop_p, mop_sc,
};

struct mop_t {
    mopt_t t = mop_z;
    uint32_t size = 0;
    uint64_t nnn = 0;
    int r = 0;
    ea_t g = BADADDR;    // global operand ea (mop_v)
    ea_t v = BADADDR;    // stack var
    void* fn = nullptr;  // function operand
    bool is_reg() const { return t == mop_r; }
    bool is_reg(int) const { return t == mop_r; }
    bool is_const() const { return t == mop_n; }
    bool is_glbaddr() const { return t == mop_v; }
    uint64_t value() const { return nnn; }
    bool operator==(const mop_t& o) const { return t == o.t && nnn == o.nnn && size == o.size; }
};

// Microcode helpers
class mlist_t {
public:
    void clear() {}
    bool empty() const { return true; }
    size_t size() const { return 0; }
    void add(const mop_t&) {}
    bool has_common(const mlist_t&) const { return false; }
};

class mba_t;
// decompile_func for microcode: keep only cfuncptr_t alias (line 169). mba_t*
// form is unused — chain code paths that need microcode all sit behind
// gen_microcode() below, which returns nullptr and short-circuits callers.

struct minsn_t {
    mopcode_t opcode = m_nop;
    ea_t ea = BADADDR;
    mop_t l;
    mop_t r;
    mop_t d;
    struct minsn_t* next = nullptr;
    struct minsn_t* prev = nullptr;
};

struct mblock_t {
    int serial = 0;
    ea_t start = BADADDR;
    ea_t end = BADADDR;
    minsn_t* head = nullptr;
    minsn_t* tail = nullptr;
    struct mblock_t* nextb = nullptr;
    struct mblock_t* prevb = nullptr;
};

class mba_t {
public:
    ea_t entry_ea = BADADDR;
    int qty = 0;
    std::vector<mblock_t*> blocks;
    mblock_t* get_mblock(int /*n*/) { return nullptr; }
    bool build_graph() { return false; }
    void term() {}
};

enum mba_maturity_t {
    MMAT_ZERO = 0, MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS,
    MMAT_GLBOPT1, MMAT_GLBOPT2, MMAT_GLBOPT3, MMAT_LVARS,
};

struct mba_ranges_t {
    ea_t start = 0;
    ea_t end = 0;
};

inline mba_t* gen_microcode(const mba_ranges_t& /*range*/, hexrays_failure_t* hf = nullptr,
                            void* /*retlist*/ = nullptr, int /*decomp_flags*/ = 0,
                            mba_maturity_t /*reqmat*/ = MMAT_ZERO) {
    if (hf) { hf->code = -1; hf->desc = "Fidra: microcode shim - not implemented"; }
    return nullptr;
}

// cif_t / cfor_t / cwhile_t etc are defined earlier as cinsn_t subclasses.

// Type-info helper
class til_t {};
inline til_t* get_idati() { return nullptr; }

