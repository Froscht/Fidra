set(CORE_SOURCES
    main.cpp
    Application.cpp
    Application.h
    AnalysisProgressWidget.cpp
    AnalysisProgressWidget.h
    UndoManager.cpp
    UndoManager.h
    LogWidget.cpp
    LogWidget.h
    Theme.cpp
    Theme.h
)

add_executable(Fidra ${CORE_SOURCES})

target_include_directories(Fidra PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(Fidra PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    fidra_disasm
    fidra_debugger
    fidra_scanner
    fidra_unpacker
    fidra_network
    fidra_websec
    fidra_mcp
    fidra_dumper
    fidra_structeditor
    fidra_diff
    fidra_decompiler
    fidra_plugins
    fidra_project
    fidra_symbols
    fidra_analysis
    fidra_scripting
    fidra_callgraph
    fidra_bindiff
)

if(Qt6WebEngineWidgets_FOUND)
    target_link_libraries(Fidra PRIVATE Qt6::WebEngineWidgets fidra_browser)
    target_compile_definitions(Fidra PRIVATE FIDRA_HAS_WEBENGINE)
endif()

if(WIN32)
    target_link_libraries(Fidra PRIVATE psapi)
    set_target_properties(Fidra PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
