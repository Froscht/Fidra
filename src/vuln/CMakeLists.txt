set(VULN_SOURCES
    # cfg_engine.cpp — blocked: 127 errors, tinfo_t/udt/hexrays microcode heavy
    chain_alias.cpp
    chain_binary_corpus.cpp
    chain_boundary.cpp
    chain_budget.cpp
    chain_cross_domain.cpp
    # chain_extraction.cpp — blocked: 236 errors, deep hexrays traversal
    chain_lifetime.cpp
    chain_model.cpp
    chain_path_trace.cpp
    chain_protocol.cpp
    chain_regression_specs.cpp
    chain_report.cpp
    # chain_report_view.cpp — blocked: IDA UI-specific (simpleline_place_t, custom_viewer, WOPN_*)
    chain_schema.cpp
    chain_side_effects.cpp
    chain_solver.cpp
    chain_state_contracts.cpp
    chain_state.cpp
    # chain_store.cpp — blocked: execute_sync/MFF_READ IDA thread marshal
    chain_transfer.cpp
    chain_trigger_trace.cpp
    # chain_verification_engine.cpp — blocked: hexrays microcode traversal
    # chain_verifier.cpp — blocked: multibinary+hexrays deep integration
    # chain_verify_service.cpp — blocked: IDA thread marshal + UI dispatch
    # ida_gateway.cpp — blocked: IDA thread marshal deep integration
    # kernel_engine.cpp — blocked: IDA kernel-mode analysis primitives
    # microcode_engine.cpp — blocked: hexrays microcode API (mba_ranges, mba flow, gen_microcode)
    # surface_engine.cpp — blocked: heavy hexrays cfunc_t traversal
    # taint_engine.cpp — blocked: 189 errors, needs mop_t/minsn_t taint tracking
    # verification_engine.cpp — blocked: microcode-level verification
    # verification_tools.cpp — blocked: 72 errors from verification pipeline
    # vuln_callsites.cpp — blocked: 198 errors, hexrays vd_failure_t + decompile_cache_t
    # vuln_strings.cpp — blocked: string literal type traversal + hexrays visit_expr
    vuln_tools.cpp
    VulnModule.h
    VulnModule.cpp
)

# Blocked without Z3 - excluded until libz3 wired in.
# smt_solver.cpp — depends on z3++ API
# Blocked without Triton - guarded via FIDRA_ENABLE_TRITON.
# symbolic_engine.cpp — see conditional block below

add_library(fidra_vuln STATIC ${VULN_SOURCES})

target_include_directories(fidra_vuln PUBLIC
    ${FIDRA_INCLUDE_DIR}
    ${FIDRA_INCLUDE_DIR}/fidra/ida-compat
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(fidra_vuln PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_vuln PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    fidra_analysis
    nlohmann_json::nlohmann_json
    capstone
)

set_target_properties(fidra_vuln PROPERTIES AUTOMOC ON)

target_compile_definitions(fidra_vuln PRIVATE
    FIDRA_VULN=1
)

if(FIDRA_ENABLE_TRITON AND TARGET triton)
    target_sources(fidra_vuln PRIVATE symbolic_engine.cpp)
    target_link_libraries(fidra_vuln PUBLIC triton)
    target_compile_definitions(fidra_vuln PRIVATE FIDRA_HAS_TRITON=1)
endif()

if(NOT MSVC)
    target_compile_options(fidra_vuln PRIVATE
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-unused-function
        -Wno-unused-value
        -Wno-sign-compare
        -Wno-parentheses
        -Wno-missing-field-initializers
        -Wno-reorder
        -Wno-deprecated-declarations
        -Wno-pedantic
    )
endif()
