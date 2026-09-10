#pragma once
#include <fidra/ida_shim.h>
#include <string>
#include <cstddef>

// IDA qstring is a mutable string with QStringList-like helpers.
class qstring : public std::string {
public:
    qstring() = default;
    qstring(const char* s) : std::string(s ? s : "") {}
    qstring(const std::string& s) : std::string(s) {}
    qstring(std::string&& s) : std::string(std::move(s)) {}

    const char* c_str() const { return std::string::c_str(); }
    size_t length() const { return std::string::length(); }
    bool empty() const { return std::string::empty(); }
    void clear() { std::string::clear(); }
    qstring& append(const char* s) { std::string::append(s ? s : ""); return *this; }
    qstring& append(const std::string& s) { std::string::append(s); return *this; }
};

// generate_disasm_line flags
constexpr int GENDSM_FORCE_CODE  = 0x00000001;
constexpr int GENDSM_REMOVE_TAGS = 0x00000002;
constexpr int GENDSM_MULTI_LINE  = 0x00000004;

// tag_remove — strips IDA color tags. No-op for shim.
inline ssize_t tag_remove(qstring* out, const qstring& in) {
    if (out) *out = in;
    return in.length();
}
inline ssize_t tag_remove(qstring* inout) {
    return inout ? static_cast<ssize_t>(inout->length()) : 0;
}
inline ssize_t tag_remove(char* out, size_t bufsz, const char* in) {
    if (!in || !out || bufsz == 0) return 0;
    size_t n = 0;
    while (in[n] && n + 1 < bufsz) { out[n] = in[n]; ++n; }
    out[n] = 0;
    return n;
}

inline ssize_t generate_disasm_line(qstring* out, ea_t /*ea*/, int /*flags*/ = 0) {
    if (out) out->clear();
    return 0;
}

// Warning / msg / info — logging stubs.
inline int msg(const char* /*format*/, ...) { return 0; }
inline void warning(const char* /*format*/, ...) {}
inline void info(const char* /*format*/, ...) {}

// UI notification stubs — enum + register/unregister
enum ui_notification_t { ui_ready_to_run, ui_last };
inline bool register_action(const void* /*action_desc*/) { return false; }
inline bool unregister_action(const char* /*action_name*/) { return false; }
inline bool attach_action_to_menu(const char* /*menupath*/, const char* /*action_name*/, int /*flags*/ = 0) { return false; }

// hook_to_notification_point stubs
using hook_cb_t = int(void* user, int notification_code, va_list va);
enum hook_type_t { HT_UI, HT_IDP, HT_IDB, HT_LAST };
inline bool hook_to_notification_point(hook_type_t, hook_cb_t*, void* /*ud*/ = nullptr) { return false; }
inline bool unhook_from_notification_point(hook_type_t, hook_cb_t*, void* /*ud*/ = nullptr) { return false; }

// Chooser stubs
struct chooser_base_t {};

// execute_sync — thread-marshal onto UI thread. In shim: execute inline.
constexpr int MFF_FAST     = 0x0000;
constexpr int MFF_READ     = 0x0001;
constexpr int MFF_WRITE    = 0x0002;
constexpr int MFF_NOWAIT   = 0x0004;

struct exec_request_t {
    int code = 0;
    virtual ~exec_request_t() = default;
    virtual ssize_t idaapi execute() { return 0; }
};

inline int execute_sync(exec_request_t& req, int /*flags*/ = MFF_FAST) {
    return static_cast<int>(req.execute());
}
inline int execute_sync(exec_request_t* req, int /*flags*/ = MFF_FAST) {
    return req ? static_cast<int>(req->execute()) : 0;
}

// auto analysis wait — in shim analysis is already done.
inline bool auto_is_ok() { return true; }
inline void auto_wait() {}

// get_user_idadir (qstring overload)
inline ssize_t get_user_idadir(qstring* out) {
    if (out) *out = qstring(".idapro");
    return out ? out->length() : 0;
}
using get_user_idadir_fn_char = ssize_t(*)(char*, size_t);
