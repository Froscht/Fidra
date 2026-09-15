#pragma once

#include <string>
#include <fidra/ida_shim.h>
#include <fidra/hexrays_shim.h>

namespace ida_utils {

inline bool is_safely_decompilable(func_t* /*pfn*/) { return false; }
inline bool is_safely_decompilable(ea_t /*ea*/) { return false; }
inline bool set_clipboard_text(const std::string& /*text*/) { return false; }
inline std::string get_input_file_path() { return {}; }
inline std::string get_module_name() { return {}; }

}
