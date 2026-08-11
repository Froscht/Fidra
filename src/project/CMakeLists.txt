set(PROJECT_SOURCES
    ProjectManager.h
    ProjectManager.cpp
    ProjectWidget.h
    ProjectWidget.cpp
    ProjectModule.h
    ProjectModule.cpp
)

add_library(fidra_project STATIC ${PROJECT_SOURCES})

target_include_directories(fidra_project PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_project PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    fidra_analysis
)
