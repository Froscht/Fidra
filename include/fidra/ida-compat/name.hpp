#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <string>

// get_ea_name flags
constexpr int GN_VISIBLE   = 0x01;
constexpr int GN_DEMANGLED = 0x02;
constexpr int GN_SHORT     = 0x04;
constexpr int GN_STRICT    = 0x08;
constexpr int GN_NOT_DUMMY = 0x10;
constexpr int GN_COLORED   = 0x20;
constexpr int GN_LONG      = 0x40;

inline ssize_t get_ea_name(qstring* out, ea_t ea, int /*flags*/ = 0) {
    if (!out) return 0;
    std::string n = get_name(ea);
    *out = qstring(n);
    return static_cast<ssize_t>(n.size());
}

inline ssize_t get_ea_name(char* buf, size_t bufsize, ea_t ea, int /*flags*/ = 0) {
    if (!buf || bufsize == 0) return 0;
    std::string n = get_name(ea);
    size_t len = n.size() < bufsize - 1 ? n.size() : bufsize - 1;
    for (size_t i = 0; i < len; ++i) buf[i] = n[i];
    buf[len] = 0;
    return static_cast<ssize_t>(len);
}

inline bool is_uname(const char* /*name*/) { return true; }
inline bool is_valid_typename(const char* /*name*/) { return true; }

// IDA has a qstring* overload of get_name/get_func_name distinct from Fidra's.
inline ssize_t get_name(qstring* out, ea_t ea, int /*flags*/ = 0) {
    if (!out) return 0;
    *out = qstring(get_name(ea));
    return static_cast<ssize_t>(out->length());
}

inline ssize_t get_func_name(qstring* out, ea_t ea) {
    if (!out) return 0;
    *out = qstring(get_func_name(ea));
    return static_cast<ssize_t>(out->length());
}

// Name list — nlist API is empty (no persistent name list in shim).
inline size_t get_nlist_size() { return 0; }
inline const char* get_nlist_name(size_t /*n*/) { return ""; }
inline ea_t get_nlist_ea(size_t /*n*/) { return BADADDR; }
inline ea_t get_name_ea(ea_t /*from*/, const char* name) {
    // Fallback: iterate names. Not implemented in shim.
    (void)name;
    return BADADDR;
}
inline bool is_loaded(ea_t /*ea*/) { return true; }
inline bool has_name(flags_t flags) { return (flags & 0x00100000) != 0; }
inline bool has_dummy_name(flags_t /*flags*/) { return false; }
inline bool has_user_name(flags_t /*flags*/) { return false; }
inline bool has_auto_name(flags_t /*flags*/) { return false; }
