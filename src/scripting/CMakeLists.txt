set(SCRIPTING_SOURCES
    ScriptEngine.cpp
    ScriptEngine.h
    ScriptWidget.cpp
    ScriptWidget.h
    ScriptModule.cpp
    ScriptModule.h
)

add_library(fidra_scripting STATIC ${SCRIPTING_SOURCES})

target_include_directories(fidra_scripting PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_scripting PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)
