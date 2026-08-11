set(MCP_SOURCES
    McpModule.cpp
    McpModule.h
    McpWidget.cpp
    McpWidget.h
    McpServer.cpp
    McpServer.h
    McpToolRegistry.cpp
    McpToolRegistry.h
    McpSchemaBuilder.h
    McpProtocol.cpp
    McpProtocol.h
    McpToolsAnalysis.cpp
    McpToolsMemory.cpp
    McpToolsNetwork.cpp
    McpToolsCodegen.cpp
    McpToolsScripting.cpp
    McpToolsAi.cpp
    McpToolsFile.cpp
    McpToolsEncoding.cpp
    McpToolsDebugger.cpp
    McpToolsUtility.cpp
)

add_library(fidra_mcp STATIC ${MCP_SOURCES})

target_include_directories(fidra_mcp PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_mcp PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    nlohmann_json::nlohmann_json
    capstone
)
