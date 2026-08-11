set(STRUCTEDITOR_SOURCES
    StructTypes.cpp
    StructTypes.h
    StructEditorWidget.cpp
    StructEditorWidget.h
    StructEditorModule.cpp
    StructEditorModule.h
)

add_library(fidra_structeditor STATIC ${STRUCTEDITOR_SOURCES})

target_include_directories(fidra_structeditor PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_structeditor PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

set_target_properties(fidra_structeditor PROPERTIES AUTOMOC ON)
