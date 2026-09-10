#pragma once

#include <string>
#include <functional>

namespace aida_ipc {

inline bool send(const std::string& /*channel*/, const std::string& /*payload*/) { return false; }
inline bool subscribe(const std::string& /*channel*/, std::function<void(const std::string&)> /*cb*/) { return false; }

}
