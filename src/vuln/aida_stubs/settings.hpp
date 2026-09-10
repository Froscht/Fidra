#pragma once

// Minimal stub for AiDA's settings.hpp. vuln references only a few fields;
// keep the class shape but leave every method as no-op.

#include <string>
#include <map>

class aida_plugin_t;

class settings_t {
public:
    std::string api_provider;
    std::string gemini_api_key, gemini_model_name, gemini_base_url;
    std::string openai_api_key, openai_model_name, openai_base_url;
    std::string openrouter_api_key, openrouter_model_name;
    std::string anthropic_api_key, anthropic_model_name, anthropic_base_url;
    std::string local_llm_base_url, local_llm_model_name, local_llm_api_key;
    int         local_llm_context_window = 8192;
    int         xref_context_count = 8;
    int         xref_analysis_depth = 2;
    int         xref_code_snippet_lines = 200;
    int         max_root_func_scan_count = 256;
    int         max_root_func_candidates = 16;
    bool        check_for_updates = false;
    bool        mcp_enabled = false;
    int         mcp_port = 0;
    bool        embedding_enabled = false;
    std::string embedding_api_url, embedding_api_key, embedding_model_name;
    int         embedding_dimensions = 0;
    int         embedding_batch_size = 0;
    std::map<std::string, std::string> custom_prompts;
    std::string active_prompt_name;

    void save() {}
    void load(aida_plugin_t* /*plugin_instance*/) {}
    bool load_from_file() { return false; }
};

inline settings_t g_settings;
