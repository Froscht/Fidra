set(PLUGIN_SOURCES
    PluginManager.h
    PluginManager.cpp
    PluginLoader.h
    PluginLoader.cpp
    PluginModule.h
    PluginModule.cpp
    PluginWidget.h
    PluginWidget.cpp
)

add_library(fidra_plugin STATIC ${PLUGIN_SOURCES})

target_include_directories(fidra_plugin PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_plugin PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    dl
)

set_target_properties(fidra_plugin PROPERTIES AUTOMOC ON)
