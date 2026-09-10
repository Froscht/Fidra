#pragma once
#include <fidra/ida_shim.h>
#include <string>
#include <filesystem>

// IDA POSIX-style filesystem helpers.
inline bool qisdir(const char* path) {
    if (!path) return false;
    std::error_code Ec;
    return std::filesystem::is_directory(path, Ec);
}
inline bool qfileexist(const char* path) {
    if (!path) return false;
    std::error_code Ec;
    return std::filesystem::exists(path, Ec);
}
inline int qmkdir(const char* path, int /*mode*/ = 0755) {
    if (!path) return -1;
    std::error_code Ec;
    return std::filesystem::create_directories(path, Ec) ? 0 : -1;
}
inline int qunlink(const char* path) {
    if (!path) return -1;
    std::error_code Ec;
    return std::filesystem::remove(path, Ec) ? 0 : -1;
}
