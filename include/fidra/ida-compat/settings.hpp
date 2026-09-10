#pragma once
// AiDA settings_t stub — minimal fields the ported code touches.
#include <string>
#include <vector>
#include <map>

class aida_plugin_t;

class settings_t {
public:
    std::string api_provider;
    std::string gemini_api_key;
    std::string gemini_model_name;
    std::string gemini_base_url;
    std::string openai_api_key;
    std::string openai_model_name;
    std::string openai_base_url;
    std::string openrouter_api_key;
    std::string openrouter_model_name;
    std::string anthropic_api_key;
    std::string anthropic_model_name;
    std::string anthropic_base_url;
    std::string copilot_proxy_address;
    std::string copilot_model_name;
    std::string local_llm_base_url;
    std::string local_llm_model_name;
    std::string local_llm_api_key;
    int         local_llm_context_window = 128000;

    int    xref_context_count      = 10;
    int    xref_analysis_depth     = 2;
    int    xref_code_snippet_lines = 8;
    double bulk_processing_delay   = 0.0;
    int    max_root_func_scan_count = 512;
    int    max_root_func_candidates = 64;
    double temperature             = 0.2;
    bool   check_for_updates       = false;

    bool mcp_enabled = false;
    int  mcp_port    = 0;

    bool        embedding_enabled     = false;
    std::string embedding_api_url;
    std::string embedding_api_key;
    std::string embedding_model_name;
    int         embedding_dimensions  = 1536;
    int         embedding_batch_size  = 32;

    std::map<std::string, std::string> custom_prompts;
    std::string active_prompt_name;

    static inline const std::vector<std::string> gemini_models{};
    static inline const std::vector<std::string> openai_models{};
    static inline const std::vector<std::string> openrouter_models{};
    static inline const std::vector<std::string> anthropic_models{};
    static inline const std::vector<std::string> copilot_models{};
    static inline const std::vector<std::string> local_llm_models{};

    settings_t() = default;
    void save() {}
    void load(aida_plugin_t* /*plugin*/) {}
    bool load_from_file() { return false; }
    std::string get_active_api_key() const { return {}; }
    bool has_custom_base_url() const { return false; }
    int  get_active_context_window() const { return local_llm_context_window; }
    static int get_model_context_window(const std::string& /*model_name*/) { return 128000; }
};

inline settings_t g_settings;
