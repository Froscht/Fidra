set(PLUGINS_SOURCES
    PluginLoader.h
    PluginLoader.cpp
    PluginModule.h
    PluginModule.cpp
    PluginWidget.h
    PluginWidget.cpp
)

add_library(fidra_plugins STATIC ${PLUGINS_SOURCES})

target_include_directories(fidra_plugins PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_plugins PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

set_target_properties(fidra_plugins PROPERTIES AUTOMOC ON)
