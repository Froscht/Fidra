#pragma once

// Minimal stub for vuln::chain API surface referenced by multibinary port.
// Real chain analysis lives in AiDA — Fidra ships this as compile-only shim so
// multibinary builds. Runtime paths that call snapshot_current_idb_corpus() get
// an empty corpus and gracefully produce empty JSON.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <fidra/ida_shim.h>

namespace vuln {
namespace chain {

enum class corpus_availability_t {
    loaded,
    peer_loaded,
    missing,
    partial,
    recorded_only
};

enum class corpus_trust_t {
    ida_extracted,
    recorded_dynamic,
    user_declared,
    imported_contract
};

enum class location_confidence_t {
    exact,
    symbolic_exact,
    weak_name,
    ambiguous,
    unresolved
};

enum class address_kind_t {
    image_rva,
    segment_offset,
    import_slot,
    export_forwarder,
    synthetic,
    unknown
};

struct hash_identity_t {
    std::string md5;
    std::string sha256;
    std::string crc32;
    std::uint64_t input_size = 0;
};

struct corpus_identity_t {
    std::string corpus_id;
    hash_identity_t hashes;
    std::string canonical_path;
    std::string canonical_name;
    std::string input_path;
    std::string display_name;
    std::string architecture;
    int bitness = 64;
    std::uint64_t image_base = 0;
    std::string file_type;
    std::string binary_kind;
    std::string version_string;
};

struct segment_record_t {
    std::string name;
    std::string segment_class;
    std::uint64_t start_ea = 0;
    std::uint64_t end_ea = 0;
    std::uint32_t permissions = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    bool executable = false;
    bool writable = false;
    bool readable = true;
};

struct canonical_address_t {
    std::string corpus_id;
    location_confidence_t confidence = location_confidence_t::unresolved;
    address_kind_t kind = address_kind_t::unknown;
    std::uint64_t offset = 0;
    std::uint64_t address = 0;      // alias, some code reads .address
    std::uint64_t rva = 0;
    std::uint64_t ea = 0;
    std::uint64_t segment_start_rva = 0;
    std::uint64_t segment_offset = 0;
    bool ok = false;
    std::string symbol_name;
    std::string segment_name;
    std::string segment;
};

struct corpus_record_t {
    corpus_identity_t identity;
    corpus_availability_t availability = corpus_availability_t::missing;
    corpus_trust_t trust = corpus_trust_t::user_declared;
    std::vector<segment_record_t> segments;
    std::string loader_model;
    nlohmann::json metadata = nlohmann::json::object();
};

inline const char* to_string(corpus_availability_t) { return "unknown"; }
inline const char* to_string(corpus_trust_t) { return "unknown"; }
inline const char* to_string(location_confidence_t) { return "unresolved"; }
inline const char* to_string(address_kind_t) { return "unknown"; }

inline std::optional<corpus_availability_t> corpus_availability_from_string(const std::string&) { return std::nullopt; }
inline std::optional<corpus_trust_t> corpus_trust_from_string(const std::string&) { return std::nullopt; }
inline std::optional<location_confidence_t> location_confidence_from_string(const std::string&) { return std::nullopt; }

inline nlohmann::json to_json(const corpus_identity_t&) { return nlohmann::json::object(); }
inline nlohmann::json to_json(const corpus_record_t&) { return nlohmann::json::object(); }
inline nlohmann::json to_json(const segment_record_t&) { return nlohmann::json::object(); }
inline nlohmann::json to_json(const canonical_address_t&) { return nlohmann::json::object(); }

inline corpus_record_t snapshot_current_idb_corpus(const std::string& /*corpus_id_override*/ = {}) {
    return corpus_record_t{};
}

inline canonical_address_t normalize_ea(const corpus_record_t&, std::uint64_t ea) {
    canonical_address_t out;
    out.offset = ea;
    return out;
}

inline corpus_record_t make_missing_corpus(const std::string& corpus_id) {
    corpus_record_t out;
    out.identity.corpus_id = corpus_id;
    out.availability = corpus_availability_t::missing;
    return out;
}

inline std::string derive_module_id(const corpus_identity_t& id) {
    return id.corpus_id;
}

inline std::optional<const corpus_record_t*> find_corpus(const std::vector<corpus_record_t>& corpus, const std::string& corpus_id) {
    for (const auto& c : corpus) if (c.identity.corpus_id == corpus_id) return &c;
    return std::nullopt;
}

inline std::optional<corpus_record_t*> find_corpus(std::vector<corpus_record_t>& corpus, const std::string& corpus_id) {
    for (auto& c : corpus) if (c.identity.corpus_id == corpus_id) return &c;
    return std::nullopt;
}

// Placeholder — real engines live elsewhere. Multibinary only forward-references
// these; instantiate as no-op if constructed.
class microcode_engine_t {
public:
    microcode_engine_t() = default;
    void analyze(func_t*) {}
};

class verification_engine_t {
public:
    verification_engine_t() = default;
    bool verify_target(ea_t) { return false; }
};

}
}
