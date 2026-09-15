#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <cstddef>
#include <string>

// PATH_TYPE_*, QMAXPATH, retrieve_input_file_*, get_import_module_*,
// enum_import_names, import_enum_cb_t — see ida_shim.h.

// Extra helpers not in ida_shim.h
inline ssize_t get_path(char* buf, size_t bufsize, int /*type*/) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
inline const char* get_path(int /*type*/) { return ""; }
inline ssize_t get_input_file_path(char* buf, size_t bufsize) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
inline uint64_t retrieve_input_file_size() { return 0; }
inline ssize_t retrieve_input_file_crc32(uint32_t* /*crc*/) { return 0; }
inline ssize_t get_user_idadir(char* buf, size_t bufsize) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
