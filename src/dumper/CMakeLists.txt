set(DUMPER_SOURCES
    DumperModule.cpp
    DumperModule.h
    DumperWidget.cpp
    DumperWidget.h
    ProcessDumper.cpp
    ProcessDumper.h
    HeatmapWidget.cpp
    HeatmapWidget.h
)

add_library(fidra_dumper STATIC ${DUMPER_SOURCES})

target_include_directories(fidra_dumper PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_dumper PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
)
