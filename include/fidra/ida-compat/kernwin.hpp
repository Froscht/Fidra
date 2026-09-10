#pragma once
#include <fidra/ida_shim.h>
#include <string>
#include <cstddef>
#include <cstdarg>

// qstring, tag_remove, generate_disasm_line, GENDSM_* — see fidra/ida_shim.h

// Warning / msg / info — logging stubs
inline int msg(const char* /*format*/, ...) { return 0; }
inline void warning(const char* /*format*/, ...) {}
inline void info(const char* /*format*/, ...) {}

// UI notification stubs
enum ui_notification_t { ui_ready_to_run, ui_last };
inline bool register_action(const void* /*action_desc*/) { return false; }
inline bool unregister_action(const char* /*action_name*/) { return false; }
inline bool attach_action_to_menu(const char* /*menupath*/, const char* /*action_name*/, int /*flags*/ = 0) { return false; }

// hook notifications
using hook_cb_t = int(void* user, int notification_code, va_list va);
enum hook_type_t { HT_UI, HT_IDP, HT_IDB, HT_LAST };
inline bool hook_to_notification_point(hook_type_t, hook_cb_t*, void* /*ud*/ = nullptr) { return false; }
inline bool unhook_from_notification_point(hook_type_t, hook_cb_t*, void* /*ud*/ = nullptr) { return false; }

// Chooser
struct chooser_base_t {};

// execute_sync thread-marshal — inline execution in shim
constexpr int MFF_FAST   = 0x0000;
constexpr int MFF_READ   = 0x0001;
constexpr int MFF_WRITE  = 0x0002;
constexpr int MFF_NOWAIT = 0x0004;

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

// get_user_idadir qstring overload — ida_shim.h has char* overload
inline ssize_t get_user_idadir_qs(qstring* out) {
    if (out) *out = qstring(".idapro");
    return out ? static_cast<ssize_t>(out->size()) : 0;
}
