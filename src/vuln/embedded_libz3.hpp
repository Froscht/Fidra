#pragma once

// Fidra stub replacing AiDA's embedded_libz3.hpp Windows DLL loader.
// Z3 is not embedded in Fidra. All entry points return failure.

#include <string>
#include <atomic>

namespace aida { namespace vuln { namespace embedded_libz3 {

inline std::atomic<bool> g_z3_attempted{false};

inline bool ensure_loaded() { return false; }
inline bool is_loaded() { return false; }
inline void unload() {}
inline std::string last_error() { return "z3 not available (Fidra stub)"; }
inline std::string module_path() { return {}; }

}}}
