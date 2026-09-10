#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace aida { namespace multibinary {

struct project_io_result_t {
    bool ok = false;
    std::string project_id;
    std::string error;
    nlohmann::json payload;
};

inline std::string default_project_id_for_current_idb() { return {}; }

inline nlohmann::json current_idb_inventory(bool /*include_segments*/ = true,
                                            bool /*include_functions*/ = true) {
    return nlohmann::json::object();
}

inline nlohmann::json merge_inventory_documents(const nlohmann::json& /*a*/,
                                                const nlohmann::json& /*b*/) {
    return nlohmann::json::object();
}

inline project_io_result_t list_projects() { return {}; }
inline project_io_result_t load_project_modules(const std::string& /*id*/) { return {}; }
inline project_io_result_t delete_project(const std::string& /*id*/) { return {}; }
inline project_io_result_t index_status(const std::string& /*id*/) { return {}; }
inline project_io_result_t load_project_manifest(const std::string& /*id*/) { return {}; }
inline project_io_result_t save_project_manifest(const std::string& /*id*/, const nlohmann::json& /*doc*/) { return {}; }
inline project_io_result_t bind_corpus(const std::string& /*project_id*/,
                                       const std::string& /*corpus_id*/,
                                       const nlohmann::json& /*bind_spec*/) { return {}; }
inline project_io_result_t rebuild_index(const std::string& /*project_id*/) { return {}; }

}} // namespace aida::multibinary

// Legacy alias used by some vuln code
namespace multibinary { using aida::multibinary::project_io_result_t; }
