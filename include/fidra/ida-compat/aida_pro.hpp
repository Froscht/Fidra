#pragma once
// AiDA umbrella header stub — pulls in all IDA-compat shims for ported code.

#include <fidra/ida_shim.h>
#include <fidra/hexrays_shim.h>
#include <fidra/ida-compat/settings.hpp>
#include <fidra/ida-compat/analysis_db.hpp>
#include <fidra/ida-compat/ida_utils.hpp>

#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <sstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <fstream>
#include <mutex>
#include <algorithm>
#include <thread>

// mkdir / stat (POSIX)
#include <sys/stat.h>
#include <sys/types.h>

// mark_builtin_widgets — no-op in Fidra
using builtin_widgets_mask_t = uint32_t;
inline void aida_request_refresh(builtin_widgets_mask_t /*mask*/, bool /*dirty*/ = true) {}

// mstr helper (IDA-ism)
inline void aida_msg(const char* /*fmt*/, ...) {}
// msg(...) provided by kernwin.hpp — leave alone here to avoid macro clash.
