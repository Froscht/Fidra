set(CALLGRAPH_SOURCES
    CallGraphWidget.cpp
    CallGraphWidget.h
    CallGraphModule.cpp
    CallGraphModule.h
)

add_library(fidra_callgraph STATIC ${CALLGRAPH_SOURCES})

target_include_directories(fidra_callgraph PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_callgraph PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)
