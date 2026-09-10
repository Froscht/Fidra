#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <cstddef>

// get_entry_qty / get_entry_ordinal / get_entry / get_entry_name — see ida_shim.h.

inline ssize_t get_entry_forwarder(qstring* out, uval_t /*ord*/) {
    if (out) out->clear();
    return 0;
}
inline bool add_entry(uval_t /*ord*/, ea_t /*ea*/, const char* /*name*/ = nullptr, bool /*makecode*/ = false) { return false; }
