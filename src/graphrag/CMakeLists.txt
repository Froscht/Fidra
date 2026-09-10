set(GRAPHRAG_SOURCES
    GraphRag.h
    GraphRag.cpp
    GraphRagModule.h
)

add_library(fidra_graphrag STATIC ${GRAPHRAG_SOURCES})

target_include_directories(fidra_graphrag PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_graphrag PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    fidra_analysis
    capstone
    nlohmann_json::nlohmann_json
)

# The ported code triggers many "unused parameter / set-but-unused" warnings
# because most IDA API stubs return dummy values. Suppress until real port.
if(NOT MSVC)
    target_compile_options(fidra_graphrag PRIVATE
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-unused-function
        -Wno-sign-compare
        -Wno-deprecated-declarations
    )
endif()

set_target_properties(fidra_graphrag PROPERTIES AUTOMOC ON)
