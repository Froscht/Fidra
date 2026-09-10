#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <cstddef>

// Entry point (exports) table — empty in shim (real impl lives in IdaShim.cpp).
size_t get_entry_qty();
uval_t get_entry_ordinal(size_t idx);
inline ea_t get_entry(uval_t /*ord*/) { return BADADDR; }
inline ssize_t get_entry_name(qstring* out, uval_t /*ord*/) {
    if (out) out->clear();
    return 0;
}
inline ssize_t get_entry_forwarder(qstring* out, uval_t /*ord*/) {
    if (out) out->clear();
    return 0;
}
inline bool add_entry(uval_t /*ord*/, ea_t /*ea*/, const char* /*name*/ = nullptr, bool /*makecode*/ = false) { return false; }
