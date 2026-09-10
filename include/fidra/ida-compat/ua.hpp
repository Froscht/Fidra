#pragma once
#include <fidra/ida_shim.h>

// IDA insn_t / op_t shim (stub — decode_insn returns 0 = failure, callers degrade)

enum optype_t {
    o_void      = 0,
    o_reg       = 1,
    o_mem       = 2,
    o_phrase    = 3,
    o_displ     = 4,
    o_imm       = 5,
    o_far       = 6,
    o_near      = 7,
    o_idpspec0  = 8,
    o_idpspec1  = 9,
    o_idpspec2  = 10,
    o_idpspec3  = 11,
    o_idpspec4  = 12,
    o_idpspec5  = 13,
};

struct op_t {
    uint8_t  n = 0;
    optype_t type = o_void;
    uint8_t  offb = 0;
    uint8_t  offo = 0;
    uint8_t  flags = 0;
    uint8_t  dtype = 0;
    uint16_t reg = 0;
    uint64_t value = 0;
    ea_t     addr = 0;
    uint64_t specval = 0;
    int8_t   specflag1 = 0;
    int8_t   specflag2 = 0;
    int8_t   specflag3 = 0;
    int8_t   specflag4 = 0;

    bool shown() const { return true; }
    bool is_reg(int r) const { return type == o_reg && reg == r; }
};

constexpr int UA_MAXOP = 8;

struct insn_t {
    ea_t     ea = BADADDR;
    ea_t     cs = 0;
    ea_t     ip = 0;
    uint16_t itype = 0;
    uint16_t size = 0;
    uint16_t auxpref = 0;
    uint8_t  segpref = 0;
    uint8_t  insnpref = 0;
    op_t     ops[UA_MAXOP];
    ea_t*    cswitch = nullptr;

    op_t& operator[](int i) { return ops[i]; }
    const op_t& operator[](int i) const { return ops[i]; }
};

// Decode primitives — stub: fail, callers handle.
inline int decode_insn(insn_t* out, ea_t /*ea*/) {
    if (out) *out = insn_t{};
    return 0;
}

inline bool print_insn_mnem(char* /*buf*/, size_t /*size*/, ea_t /*ea*/) { return false; }
inline ea_t next_head(ea_t ea, ea_t /*maxea*/) { return ea + 1; }
inline ea_t prev_head(ea_t ea, ea_t /*minea*/) { return ea == 0 ? BADADDR : ea - 1; }
inline ea_t get_item_end(ea_t ea) { return ea + 1; }
inline asize_t get_item_size(ea_t /*ea*/) { return 1; }
