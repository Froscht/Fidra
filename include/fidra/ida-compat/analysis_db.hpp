#pragma once
// AiDA aida_db::AnalysisDB stub — in-memory only, matches interface footprint.

#include <fidra/ida_shim.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace aida_db {

struct rlhf_entry_t {
    std::string id;
    std::string model_name;
    std::string prompt;
    std::string system_prompt;
    std::string response;
    int         feedback = 0;
    uint64_t    timestamp_ms = 0;
    nlohmann::json metadata;
};

struct chat_entry_t {
    std::string role;
    std::string content;
    uint64_t    timestamp_ms = 0;
    nlohmann::json metadata;
};

struct analysis_entry_t {
    ea_t        address = BADADDR;
    std::string function_name;
    std::string analysis_type;
    std::string result;
    std::string model_name;
    uint64_t    timestamp_ms = 0;
};

class AnalysisDB {
public:
    static AnalysisDB& instance() { static AnalysisDB s; return s; }

    struct binary_registry_entry_t {
        std::string    hash;
        uint64_t       first_seen_ms = 0;
        uint64_t       last_seen_ms  = 0;
        bool           has_graph     = false;
        bool           has_vectors   = false;
        nlohmann::json fingerprint_summary;
    };

    struct rlhf_stats_t {
        int total = 0;
        int upvotes = 0;
        int downvotes = 0;
        std::unordered_map<std::string, int> by_model;
    };

    std::string get_binary_hash() const {
        uchar md5[16];
        if (!retrieve_input_file_md5(md5)) return {};
        char buf[33]{};
        for (int i = 0; i < 16; ++i) qsnprintf(buf + i * 2, 3, "%02x", md5[i]);
        return std::string(buf, 32);
    }

    void add_rlhf(const rlhf_entry_t& e) { std::lock_guard<std::mutex> lk(m_mtx); m_rlhf.push_back(e); }
    std::vector<rlhf_entry_t> get_rlhf_entries() const { std::lock_guard<std::mutex> lk(m_mtx); return m_rlhf; }
    rlhf_stats_t get_rlhf_stats() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        rlhf_stats_t s;
        s.total = static_cast<int>(m_rlhf.size());
        for (auto& e : m_rlhf) {
            if (e.feedback > 0) ++s.upvotes;
            else if (e.feedback < 0) ++s.downvotes;
            ++s.by_model[e.model_name];
        }
        return s;
    }

    void add_chat(const std::string& binary_hash, const chat_entry_t& e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_chat[binary_hash].push_back(e);
    }
    std::vector<chat_entry_t> get_chat_history(const std::string& bh) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_chat.find(bh);
        return it != m_chat.end() ? it->second : std::vector<chat_entry_t>{};
    }
    void clear_chat_history(const std::string& bh) { std::lock_guard<std::mutex> lk(m_mtx); m_chat.erase(bh); }

    void add_analysis(const std::string& bh, const analysis_entry_t& e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto& v = m_analysis[bh];
        for (auto& x : v) if (x.address == e.address && x.analysis_type == e.analysis_type) { x = e; return; }
        v.push_back(e);
    }
    std::vector<analysis_entry_t> get_analysis(const std::string& bh, ea_t addr = BADADDR) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_analysis.find(bh);
        if (it == m_analysis.end()) return {};
        if (addr == BADADDR) return it->second;
        std::vector<analysis_entry_t> out;
        for (auto& e : it->second) if (e.address == addr) out.push_back(e);
        return out;
    }

    void register_binary(const std::string& hash, const nlohmann::json& fingerprint) {
        if (hash.empty()) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        auto& e = m_bin[hash];
        uint64_t ts = now_ms();
        if (e.hash.empty()) { e.hash = hash; e.first_seen_ms = ts; }
        e.last_seen_ms = ts;
        if (!fingerprint.is_null() && !fingerprint.empty()) e.fingerprint_summary = fingerprint;
    }
    std::vector<binary_registry_entry_t> list_registered_binaries() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<binary_registry_entry_t> out;
        out.reserve(m_bin.size());
        for (auto& [k, v] : m_bin) out.push_back(v);
        return out;
    }
    void mark_binary_capabilities(const std::string& hash, bool has_graph, bool has_vectors) {
        if (hash.empty()) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        auto& e = m_bin[hash];
        if (e.hash.empty()) { e.hash = hash; e.first_seen_ms = now_ms(); }
        e.last_seen_ms = now_ms();
        e.has_graph = has_graph;
        e.has_vectors = has_vectors;
    }

    bool save() { return true; }
    bool load() { return false; }
    bool is_dirty() const { return false; }

private:
    AnalysisDB() = default;
    mutable std::mutex m_mtx;
    std::vector<rlhf_entry_t> m_rlhf;
    std::unordered_map<std::string, std::vector<chat_entry_t>> m_chat;
    std::unordered_map<std::string, std::vector<analysis_entry_t>> m_analysis;
    std::unordered_map<std::string, binary_registry_entry_t> m_bin;

    static uint64_t now_ms() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
};

}
