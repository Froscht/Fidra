#pragma once
// AiDA ida_utils namespace — thin stubs.

#include <fidra/ida_shim.h>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <functional>

class settings_t;

namespace ida_utils {

using get_code_callback_t = std::function<void(const std::pair<std::string, std::string>&)>;

inline std::string markup_text_with_addresses(const std::string& text) { return text; }

inline std::pair<std::string, std::string> get_function_code(ea_t /*ea*/, size_t /*max_len*/ = 0, bool /*force_assembly*/ = false) {
    return {std::string{}, std::string{}};
}
inline void get_function_code(ea_t ea, get_code_callback_t cb, size_t max_len = 0, bool force_assembly = false) {
    if (cb) cb(get_function_code(ea, max_len, force_assembly));
}

inline std::string get_code_xrefs_to(ea_t /*ea*/, const settings_t& /*s*/) { return {}; }
inline std::string get_code_xrefs_from(ea_t /*ea*/, const settings_t& /*s*/) { return {}; }
inline std::string get_struct_usage_context(ea_t /*ea*/) { return {}; }
inline std::string get_data_xrefs_for_struct(const tinfo_t& /*t*/, const settings_t& /*s*/) { return {}; }
inline nlohmann::json get_context_for_prompt(ea_t /*ea*/, bool /*include_struct*/ = false, size_t /*max_len*/ = 0) { return nlohmann::json::object(); }
inline std::string format_context_for_clipboard(const nlohmann::json& /*ctx*/) { return {}; }
inline bool set_clipboard_text(const qstring& /*text*/) { return false; }
inline void apply_struct_from_cpp(const std::string& /*cpp*/, ea_t /*ea*/) {}
inline std::string format_prompt(const char* prompt_template, const nlohmann::json& /*ctx*/) {
    return prompt_template ? std::string(prompt_template) : std::string{};
}
inline bool is_word_char(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'; }
inline func_t* get_function_for_item(ea_t ea) { return get_func(ea); }
inline qstring qstring_tolower(const qstring& s) {
    qstring out = s;
    for (auto& c : out.buf) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return out;
}
inline bool get_address_from_line_pos(ea_t* /*out_ea*/, const char* /*line*/, int /*x*/) { return false; }
inline qstring apply_renames_from_ai(ea_t /*func_ea*/, const std::string& /*cpp_code*/) { return {}; }
inline std::string get_binary_metadata() { return {}; }
inline std::string get_imports_for_function(ea_t /*ea*/) { return {}; }
inline std::string get_type_context_for_function(ea_t /*ea*/) { return {}; }
inline nlohmann::json get_rag_context(ea_t /*ea*/, const settings_t& /*s*/, const nlohmann::json* /*cached*/ = nullptr) { return nlohmann::json::object(); }
inline nlohmann::json get_full_cached_context(ea_t /*ea*/, const settings_t& /*s*/, bool /*inc*/ = true, size_t /*max*/ = 0) { return nlohmann::json::object(); }
inline void invalidate_rag_cache() {}
inline void invalidate_rag_cache_for(ea_t /*ea*/) {}
inline void apply_struct_from_cpp_ex(const std::string& /*cpp*/, ea_t /*ea*/, const std::string& /*target*/ = "") {}
inline bool update_existing_struct(const std::string& /*name*/, const std::string& /*def*/) { return false; }
inline bool is_safely_decompilable(func_t* /*pfn*/) { return false; }

}
