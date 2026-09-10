#pragma once
#include <fidra/ida_shim.h>
#include <fidra/ida-compat/kernwin.hpp>
#include <cstddef>
#include <string>

// IDA path type
enum {
    PATH_TYPE_CMD  = 0,
    PATH_TYPE_IDB  = 1,
    PATH_TYPE_ID0  = 2
};

constexpr size_t QMAXPATH = 4096;

inline ssize_t get_path(qstring* out, int /*type*/) {
    if (out) out->clear();
    return 0;
}
inline ssize_t get_path(char* buf, size_t bufsize, int /*type*/) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
inline const char* get_path(int /*type*/) { return ""; }
inline ssize_t get_input_file_path(char* buf, size_t bufsize) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
inline ssize_t get_input_file_path(qstring* out) {
    if (out) out->clear();
    return 0;
}
inline ssize_t retrieve_input_file_md5(uint8_t* /*hash*/) { return 0; }
inline ssize_t retrieve_input_file_sha256(uint8_t* /*hash*/) { return 0; }
inline ssize_t retrieve_input_file_crc32(uint32_t* /*crc*/) { return 0; }
inline uint64_t retrieve_input_file_size() { return 0; }
ea_t get_imagebase();
inline ssize_t get_user_idadir(char* buf, size_t bufsize) {
    if (buf && bufsize > 0) buf[0] = 0;
    return 0;
}
inline const char* get_user_idadir() { return ".idapro"; }

// Import iterators. Iteration is empty in shim.
int get_import_module_qty();
inline ssize_t get_import_module_name(qstring* out, int /*idx*/) {
    if (out) out->clear();
    return 0;
}

typedef int (*import_enum_cb_t)(ea_t ea, const char* name, uval_t ord, void* param);

inline int enum_import_names(int /*module_idx*/, import_enum_cb_t /*cb*/, void* /*param*/ = nullptr) {
    return 0;
}
