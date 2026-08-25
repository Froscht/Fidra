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
)

# libdl only exists on Unix; on Windows dynamic loading is in the base API.
if(NOT WIN32)
    target_link_libraries(fidra_plugin PRIVATE ${CMAKE_DL_LIBS})
endif()

set_target_properties(fidra_plugin PROPERTIES AUTOMOC ON)
