#pragma once

// Minimal replacement for AiDA's aida_pro.hpp umbrella header.
// Provides the IDA SDK + json + std headers that ported chain code expects
// via a single include, routed through the Fidra shim.

#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <chrono>
#include <regex>
#include <future>
#include <sstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <optional>

#include <nlohmann/json.hpp>

#include <fidra/ida_shim.h>
#include <fidra/hexrays_shim.h>

class aida_plugin_t;
