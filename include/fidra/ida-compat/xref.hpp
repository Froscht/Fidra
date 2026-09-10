#pragma once
#include <fidra/ida_shim.h>

// xref flags (subset)
constexpr int XREF_ALL   = 0x00;
constexpr int XREF_FAR   = 0x01;
constexpr int XREF_USER  = 0x20;
constexpr int XREF_TAIL  = 0x40;
constexpr int XREF_BASE  = 0x80;

// Convenience wrappers for older IDA APIs.
inline ea_t get_first_cref_from(ea_t /*from*/) { return BADADDR; }
inline ea_t get_next_cref_from(ea_t /*from*/, ea_t /*current*/) { return BADADDR; }
inline ea_t get_first_cref_to(ea_t /*to*/) { return BADADDR; }
inline ea_t get_next_cref_to(ea_t /*to*/, ea_t /*current*/) { return BADADDR; }
inline ea_t get_first_dref_from(ea_t /*from*/) { return BADADDR; }
inline ea_t get_next_dref_from(ea_t /*from*/, ea_t /*current*/) { return BADADDR; }
inline ea_t get_first_dref_to(ea_t /*to*/) { return BADADDR; }
inline ea_t get_next_dref_to(ea_t /*to*/, ea_t /*current*/) { return BADADDR; }
