set(DEBUGGER_SOURCES
    DebuggerModule.cpp
    DebuggerModule.h
    DebuggerWidget.cpp
    DebuggerWidget.h
    DebugEngine.cpp
    DebugEngine.h
    RegisterWidget.cpp
    RegisterWidget.h
    StackWidget.cpp
    StackWidget.h
    BreakpointWidget.cpp
    BreakpointWidget.h
    TraceEngine.cpp
    TraceEngine.h
    TraceWidget.cpp
    TraceWidget.h
    CoverageWidget.cpp
    CoverageWidget.h
)

add_library(fidra_debugger STATIC ${DEBUGGER_SOURCES})

target_include_directories(fidra_debugger PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_debugger PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    capstone
)
