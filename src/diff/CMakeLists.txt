set(DIFF_SOURCES
    DiffEngine.cpp
    DiffEngine.h
    DiffWidget.cpp
    DiffWidget.h
    DiffModule.cpp
    DiffModule.h
)

add_library(fidra_diff STATIC ${DIFF_SOURCES})

target_include_directories(fidra_diff PRIVATE
    ${FIDRA_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(fidra_diff PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
    fidra_analysis
)

set_target_properties(fidra_diff PROPERTIES AUTOMOC ON)
