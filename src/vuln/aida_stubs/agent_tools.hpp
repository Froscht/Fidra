#pragma once

#include <string>
#include <vector>
#include <fidra/ida_shim.h>

namespace agent_tools {

using tool_result_t = ::tool_result_t;

struct tool_call_t {
    std::string name;
    std::string args_json;
    std::string result_json;
};

inline std::vector<std::string> list_tools() { return {}; }
inline std::string invoke(const std::string& /*name*/, const std::string& /*args_json*/) { return {}; }

namespace helpers {
    inline tool_result_t success(const std::string& msg = {}) { tool_result_t r; r.ok = true; r.message = msg; return r; }
    inline tool_result_t failure(const std::string& msg) { tool_result_t r; r.ok = false; r.error = msg; r.is_error = true; return r; }
    inline std::string format_address(ea_t ea) {
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ea); return buf;
    }
    inline std::string format_ea(ea_t ea) { return format_address(ea); }
    inline ea_t parse_address(const std::string& s) {
        try { return static_cast<ea_t>(std::stoull(s, nullptr, 0)); } catch(...) { return BADADDR; }
    }
    inline std::string extract_string_arg(const std::string& s) { return s; }
}

}
