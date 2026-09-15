#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

#include <fidra/ida_shim.h>

namespace aida_db {

struct analysis_entry_t {
    std::string id;
    ea_t address = 0;
    std::string name;
    std::string comment;
    std::string type_hint;
    std::string decompilation;
    std::string prompt;
    std::string response;
    uint64_t    timestamp_ms = 0;
    int         confidence = 0;
    nlohmann::json metadata;
};

class AnalysisDB {
public:
    static AnalysisDB& instance() {
        static AnalysisDB S;
        return S;
    }

    std::string get_binary_hash() const { return {}; }

    std::vector<analysis_entry_t> get_analysis(const std::string& /*hash*/, ea_t /*ea*/) const {
        return {};
    }

    bool store_analysis(const std::string& /*hash*/, ea_t /*ea*/, const analysis_entry_t& /*entry*/) {
        return false;
    }

    bool remove_analysis(const std::string& /*hash*/, ea_t /*ea*/) {
        return false;
    }

    std::vector<analysis_entry_t> list_all(const std::string& /*hash*/) const {
        return {};
    }
};

}
