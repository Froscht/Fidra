# MultibinaryIndex.cpp is 2740 LOC of deep hexrays/kernwin integration
# (ctree_visitor_t traversal, decompile_func, execute_sync, vd_failure_t
# exceptions, cinsn_t::cswitch, netnode blob storage). It is NOT compiled
# yet — the shims required to make it build are the equivalent of a real
# hexrays reimplementation. Keep .h + .cpp on disk as staging reference,
# see PORT_NOTES.md.
set(MULTIBINARY_SOURCES
    VulnStub.h
    MultibinaryIndex.h
    MultibinaryProject.h
    MultibinaryProject.cpp
)

add_library(fidra_multibinary STATIC ${MULTIBINARY_SOURCES})

target_include_directories(fidra_multibinary PUBLIC
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(fidra_multibinary PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_multibinary PUBLIC
    Qt6::Core
    fidra_analysis
    nlohmann_json::nlohmann_json
)

target_link_libraries(fidra_multibinary PRIVATE
    Qt6::Gui
    Qt6::Widgets
    capstone
)

target_compile_options(fidra_multibinary PRIVATE
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-unused-but-set-variable
    -Wno-unused-function
    -Wno-sign-compare
)
